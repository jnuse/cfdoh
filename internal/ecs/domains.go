// Dynamic ECS domain table: an operator-pointed URL (ECS_DOMAINS_URL)
// supplies a community-maintained domestic-domain list (dnsmasq-china-list
// shape); rules-mode ECS decisions consult it next to the static
// ECS_DOMAINS list. Matching is ancestor-suffix over a hash set, so a list
// of ~80k entries costs a few map lookups per query instead of a linear
// scan. Loads are atomic swaps; a failed or empty refresh keeps the old
// table.
package ecs

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jnuse/cfdoh/internal/config"
	"github.com/jnuse/cfdoh/internal/wire"
)

// domainsMaxBytes caps the downloaded list (the reference list is ~1.5MB;
// 8MB leaves room for growth without a new config knob).
const domainsMaxBytes = 8 << 20

// domains holds the loaded table; nil means "no dynamic table configured".
var domains atomic.Pointer[domainSet]

// domainSet matches a name when the name itself or any ancestor equals a
// listed domain (dnsmasq-china-list semantics: a listed domain covers
// itself and all subdomains).
type domainSet struct {
	names map[string]struct{}
}

func (s *domainSet) match(name string) bool {
	if s == nil || len(s.names) == 0 {
		return false
	}
	// Walk the ancestor chain: a.b.c.com -> a.b.c.com, b.c.com, c.com, com.
	// Each hop is one map lookup; a hit means some listed domain is the
	// name itself or one of its parents — exactly dot-boundary suffix
	// matching, with no wildcard string scans.
	cname := wire.CanonicalName(name)
	for {
		if _, ok := s.names[cname]; ok {
			return true
		}
		dot := strings.IndexByte(cname, '.')
		if dot < 0 || dot == len(cname)-1 {
			return false
		}
		cname = cname[dot+1:]
	}
}

// SetDomainList installs a table parsed from body and returns its entry
// count. An empty result keeps the current table (a blank download must
// not clear live routing).
func SetDomainList(body []byte) int {
	set := parseDomainList(body)
	if set == nil {
		return 0
	}
	domains.Store(set)
	return len(set.names)
}

// MatchDynamic reports whether name falls inside the loaded dynamic table.
func MatchDynamic(name string) bool {
	return domains.Load().match(name)
}

// DomainCount reports the loaded entry count (0 when none).
func DomainCount() int {
	if s := domains.Load(); s != nil {
		return len(s.names)
	}
	return 0
}

// resetDomains drops the dynamic table (tests).
func resetDomains() {
	domains.Store(nil)
}

// parseDomainList accepts both plain-domain lines and dnsmasq server lines
// (server=/example.com/), skipping blanks, comments and non-domain tokens.
// It returns nil when nothing usable was found.
func parseDomainList(body []byte) *domainSet {
	set := &domainSet{names: make(map[string]struct{})}
	for _, line := range strings.Split(string(body), "\n") {
		candidate := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if candidate == "" || strings.HasPrefix(candidate, "#") {
			continue
		}
		if s, ok := strings.CutPrefix(candidate, "server=/"); ok {
			if end := strings.IndexByte(s, '/'); end >= 0 {
				s = s[:end]
			}
			candidate = s
		}
		if name := wire.CanonicalName(candidate); name != "" && validDomainToken(name) {
			set.names[name] = struct{}{}
		}
	}
	if len(set.names) == 0 {
		return nil
	}
	return set
}

// validDomainToken is a permissive token check: at least one dot-boundary
// label pair with plain bytes. List hygiene is the list maintainer's job;
// this only keeps garbage lines out of the hash set.
func validDomainToken(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	labels := 0
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
		labels++
	}
	return labels >= 2
}

// domainsClient never follows redirects; a list redirect is a failure.
var domainsClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// LoadDomains fetches the list from rawURL (https only) and swaps it in,
// returning the installed entry count. A failed fetch, non-2xx answer,
// oversized or empty body keeps the old table — a broken upstream must
// not clear live routing.
func LoadDomains(ctx context.Context, rawURL string, cfg *config.Config) (int, error) {
	if !strings.HasPrefix(rawURL, "https://") {
		return 0, fmt.Errorf("domain list URL must be https, got %q", rawURL)
	}
	timeout := 2 * cfg.UpstreamTimeoutMs
	if timeout > 5000 {
		timeout = 5000
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := domainsClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, domainsMaxBytes+1))
	if err != nil {
		return 0, err
	}
	if len(body) > domainsMaxBytes {
		return 0, fmt.Errorf("list exceeds %d bytes", domainsMaxBytes)
	}
	n := SetDomainList(body)
	if n == 0 {
		return 0, fmt.Errorf("list contained no usable domains")
	}
	return n, nil
}
