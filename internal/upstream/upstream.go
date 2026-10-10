// Package upstream forwards DNS queries to DoH upstreams with hedging.
//
// 契约: .trellis/spec/arch/upstream.md. 顺序启动加对冲: 对冲间隔内无结果即
// 启动下一个上游, 首个合法应答胜出, 中止其余在飞请求; 应答校验链不可削弱;
// 同键并发未命中查询合并为一次外发 (singleflight).
package upstream

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/wire"

	"golang.org/x/sync/singleflight"
)

// Result is a validated upstream response and its winning upstream.
type Result struct {
	Packet   []byte
	Upstream string
}

// httpClient never follows redirects; upstream redirect responses surface as
// non-2xx failures. The custom transport keeps a real connection pool per
// upstream host: the default transport's MaxIdleConnsPerHost of 2 forces a
// fresh TLS handshake on nearly every concurrent exchange against the same
// upstream, and that handshake cost lands directly on the query tail
// (ForceAttemptHTTP2 is required for h2 negotiation on an explicit
// Transport).
var httpClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	},
}

var flights singleflight.Group

// Query forwards query to the upstream list selected by withECS (ECS queries
// route to EcsUpstreams). Concurrent identical queries are merged into one
// outbound exchange keyed on the ID-normalized query bytes and list choice.
func Query(ctx context.Context, query []byte, cfg *config.Config, withECS bool) (*Result, error) {
	upstreams := cfg.Upstreams
	if withECS {
		upstreams = cfg.EcsUpstreams
	}
	if len(upstreams) == 0 {
		return nil, errors.New("no upstreams configured")
	}
	key := flightKey(query, withECS)
	v, err, _ := flights.Do(key, func() (any, error) {
		// Detach from the triggering request: a shared exchange must survive
		// one caller walking away while others still wait.
		return hedge(context.WithoutCancel(ctx), query, cfg, upstreams)
	})
	if err != nil {
		return nil, err
	}
	return v.(*Result), nil
}

func flightKey(query []byte, withECS bool) string {
	sum := sha256.Sum256(wire.PatchID(query, 0))
	return fmt.Sprintf("ecs=%t/%x", withECS, sum)
}

// hedge runs the hedged race. The next upstream starts when the previous one
// fails or after the hedge interval without an answer, whichever comes first;
// hedgeMs == 0 degrades to sequential fallback. The first response passing
// the validation chain wins and cancels every other in-flight attempt.
func hedge(ctx context.Context, query []byte, cfg *config.Config, upstreams []string) (*Result, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu      sync.Mutex
		next    int
		pending int
		errs    []string
		settled atomic.Bool
		done    = make(chan *Result, 1)
		failure = make(chan error, 1)
	)

	var launch func()
	launch = func() {
		mu.Lock()
		if settled.Load() || next >= len(upstreams) {
			mu.Unlock()
			return
		}
		upstream := upstreams[next]
		next++
		pending++
		more := next < len(upstreams)
		mu.Unlock()

		if cfg.UpstreamHedgeMs > 0 && more {
			time.AfterFunc(time.Duration(cfg.UpstreamHedgeMs)*time.Millisecond, launch)
		}
		go func() {
			packet, err := attempt(ctx, upstream, query, cfg)
			mu.Lock()
			pending--
			if err == nil {
				mu.Unlock()
				if settled.CompareAndSwap(false, true) {
					done <- &Result{Packet: packet, Upstream: upstream}
				}
				return
			}
			errs = append(errs, fmt.Sprintf("%s: %v", hostOf(upstream), err))
			if settled.Load() {
				mu.Unlock()
				return
			}
			if next < len(upstreams) {
				mu.Unlock()
				launch()
				return
			}
			if pending == 0 {
				detail := fmt.Errorf("all upstreams failed (%s)", strings.Join(errs, "; "))
				mu.Unlock()
				failure <- detail
				return
			}
			mu.Unlock()
		}()
	}

	go launch()
	select {
	case result := <-done:
		return result, nil
	case err := <-failure:
		slog.Warn("event", "event", "upstream_failure", "detail", err.Error())
		return nil, err
	}
}

// attempt performs one upstream POST and runs the response validation chain:
// HTTP 2xx, Content-Type, size limit, QR bit, transaction ID.
func attempt(ctx context.Context, upstream string, query []byte, cfg *config.Config) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.UpstreamTimeoutMs)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, upstream, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	contentType := resp.Header.Get("Content-Type")
	if i := strings.IndexByte(contentType, ';'); i >= 0 {
		contentType = contentType[:i]
	}
	if strings.ToLower(strings.TrimSpace(contentType)) != "application/dns-message" {
		return nil, fmt.Errorf("invalid Content-Type %q", contentType)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(cfg.MaxDNSPacketSize)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > cfg.MaxDNSPacketSize {
		return nil, errors.New("response too large")
	}
	parsed, err := wire.ParseRelaxed(body)
	if err != nil {
		return nil, err
	}
	if !parsed.Header.QR() {
		return nil, errors.New("not a DNS response")
	}
	if parsed.Header.ID != idOf(query) {
		return nil, errors.New("transaction ID mismatch")
	}
	return body, nil
}

// ResolveAddresses resolves the A and AAAA addresses of name with a hedged
// query each, bypassing the response cache. One family failing hard still
// yields the other; only a double failure is an error.
func ResolveAddresses(ctx context.Context, name string, cfg *config.Config) (v4, v6 []string, err error) {
	var (
		wg         sync.WaitGroup
		err4, err6 error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		v4, err4 = resolveFamily(ctx, name, wire.TypeA, cfg)
	}()
	go func() {
		defer wg.Done()
		v6, err6 = resolveFamily(ctx, name, wire.TypeAAAA, cfg)
	}()
	wg.Wait()
	if err4 != nil && err6 != nil {
		return nil, nil, fmt.Errorf("resolve %s failed: v4: %v; v6: %v", name, err4, err6)
	}
	return v4, v6, nil
}

func resolveFamily(ctx context.Context, name string, qtype uint16, cfg *config.Config) ([]string, error) {
	query := &wire.Packet{
		Header:    wire.Header{ID: randomID(), Flags: 0x0100},
		Questions: []wire.Question{{Name: name, Type: qtype, Class: wire.ClassIN}},
	}
	encoded, err := query.Encode()
	if err != nil {
		return nil, err
	}
	result, err := Query(ctx, encoded, cfg, false)
	if err != nil {
		return nil, err
	}
	parsed, err := wire.ParseRelaxed(result.Packet)
	if err != nil {
		return nil, err
	}
	var out []string
	seen := make(map[string]bool)
	for _, record := range parsed.Answers {
		switch rd := record.RData.(type) {
		case wire.A:
			if qtype != wire.TypeA {
				continue
			}
			if s := wire.IPv4String(rd.IP); !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		case wire.AAAA:
			if qtype != wire.TypeAAAA {
				continue
			}
			if s := wire.IPv6String(rd.IP); !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out, nil
}

func randomID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint16(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint16(b[:])
}

func idOf(query []byte) uint16 {
	if len(query) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(query[:2])
}

func hostOf(upstream string) string {
	if u, err := url.Parse(upstream); err == nil && u.Host != "" {
		return u.Host
	}
	return upstream
}
