package cfhost

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	managedDNSAliEndpoint        = "https://dns.alidns.com/dns-query"
	managedDNSCloudflareEndpoint = "https://cloudflare-dns.com/dns-query"
)

type managedDNSQuestion struct {
	domain string
	qtype  dnsmessage.Type
}

// fetchManagedDomainCandidates queries each managed domain's A and AAAA
// records independently, with bounded concurrency and stable result order.
func fetchManagedDomainCandidates(ctx context.Context, domains []string, f *fetcher, concurrency int) []netip.Addr {
	if len(domains) == 0 {
		return nil
	}
	if concurrency < 1 {
		concurrency = 1
	}

	questions := make([]managedDNSQuestion, 0, len(domains)*2)
	for _, domain := range domains {
		questions = append(questions,
			managedDNSQuestion{domain: domain, qtype: dnsmessage.TypeA},
			managedDNSQuestion{domain: domain, qtype: dnsmessage.TypeAAAA},
		)
	}

	results := make([][]netip.Addr, len(questions))
	jobs := make(chan int)
	workerCount := min(concurrency, len(questions))
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for index := range jobs {
				if ctx.Err() != nil {
					return
				}
				question := questions[index]
				addrs, err := queryManagedDNSQuestion(ctx, f, question.domain, question.qtype)
				if err != nil {
					if ctx.Err() == nil {
						slogWarnManagedDNS(question.domain, question.qtype, err)
					}
					continue
				}
				results[index] = addrs
			}
		}()
	}

sendJobs:
	for index := range questions {
		if ctx.Err() != nil {
			break
		}
		select {
		case jobs <- index:
		case <-ctx.Done():
			break sendJobs
		}
	}
	close(jobs)
	workers.Wait()

	var addrs []netip.Addr
	for _, questionResults := range results {
		addrs = append(addrs, questionResults...)
	}
	return uniquePublicAddresses(addrs)
}

func slogWarnManagedDNS(domain string, qtype dnsmessage.Type, err error) {
	slog.Warn("cfhost: managed domain DoH lookup failed",
		"domain", domain, "type", qtype.String(), "error", err.Error())
}

// queryManagedDNSQuestion tries DNS1 first and retries the same question at
// DNS2 only when the first answer is unusable.
func queryManagedDNSQuestion(ctx context.Context, f *fetcher, domain string, qtype dnsmessage.Type) ([]netip.Addr, error) {
	packet, err := packManagedDNSQuestion(domain, qtype)
	if err != nil {
		return nil, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(packet)
	endpoints := managedDNSEndpoints(f)
	labels := [...]string{"DNS1", "DNS2"}
	attemptErrors := make([]error, 0, len(endpoints))

	for index, endpoint := range endpoints {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		addrs, err := queryManagedDNSEndpoint(ctx, f, endpoint, encoded, domain, qtype)
		if err == nil && len(addrs) > 0 {
			return addrs, nil
		}
		if err == nil {
			err = errors.New("no usable public unicast answer")
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		attemptErrors = append(attemptErrors, fmt.Errorf("%s: %w", labels[index], err))
	}
	return nil, errors.Join(attemptErrors...)
}

func managedDNSEndpoints(f *fetcher) [2]string {
	if f != nil && f.dohEndpoints[0] != "" && f.dohEndpoints[1] != "" {
		return f.dohEndpoints
	}
	return [2]string{managedDNSAliEndpoint, managedDNSCloudflareEndpoint}
}

func packManagedDNSQuestion(domain string, qtype dnsmessage.Type) ([]byte, error) {
	if qtype != dnsmessage.TypeA && qtype != dnsmessage.TypeAAAA {
		return nil, fmt.Errorf("unsupported managed-domain query type %s", qtype)
	}
	name, err := dnsmessage.NewName(strings.TrimSuffix(domain, ".") + ".")
	if err != nil {
		return nil, fmt.Errorf("invalid managed domain %q: %w", domain, err)
	}
	message := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 0, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  qtype,
			Class: dnsmessage.ClassINET,
		}},
	}
	packet, err := message.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack managed-domain DNS question: %w", err)
	}
	return packet, nil
}

func queryManagedDNSEndpoint(ctx context.Context, f *fetcher, endpoint, encoded, domain string, qtype dnsmessage.Type) ([]netip.Addr, error) {
	if f == nil || f.client == nil {
		return nil, errors.New("managed-domain DoH HTTP client is unavailable")
	}
	if err := requireHTTPS(endpoint); err != nil {
		return nil, fmt.Errorf("invalid DoH endpoint: %w", err)
	}
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse DoH endpoint: %w", err)
	}
	query := endpointURL.Query()
	query.Set("dns", encoded)
	endpointURL.RawQuery = query.Encode()

	attemptCtx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(attemptCtx, http.MethodGet, endpointURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build DoH request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-message")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("DoH HTTP status %d", resp.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/dns-message") {
		return nil, fmt.Errorf("unexpected DoH content type %q", resp.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, fetchLimitByte+1))
	if err != nil {
		return nil, fmt.Errorf("read DoH response: %w", err)
	}
	if len(body) > fetchLimitByte {
		return nil, fmt.Errorf("DoH response exceeds %d bytes", fetchLimitByte)
	}
	return parseManagedDNSResponse(body, domain, qtype)
}

func parseManagedDNSResponse(packet []byte, domain string, qtype dnsmessage.Type) ([]netip.Addr, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(packet)
	if err != nil {
		return nil, fmt.Errorf("parse DoH DNS header: %w", err)
	}
	if header.ID != 0 {
		return nil, fmt.Errorf("unexpected DNS response ID %d", header.ID)
	}
	if !header.Response {
		return nil, errors.New("DNS response QR bit is not set")
	}
	if header.OpCode != 0 {
		return nil, fmt.Errorf("unexpected DNS response opcode %d", header.OpCode)
	}
	if header.Truncated {
		return nil, errors.New("DNS response is truncated")
	}
	if header.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("DNS response code is %s", header.RCode)
	}
	questions, err := parser.AllQuestions()
	if err != nil {
		return nil, fmt.Errorf("parse DoH DNS question: %w", err)
	}
	if len(questions) != 1 {
		return nil, fmt.Errorf("DNS response has %d questions, want 1", len(questions))
	}
	wantName, err := dnsmessage.NewName(strings.TrimSuffix(domain, ".") + ".")
	if err != nil {
		return nil, fmt.Errorf("invalid managed domain %q: %w", domain, err)
	}
	question := questions[0]
	if !strings.EqualFold(question.Name.String(), wantName.String()) || question.Type != qtype || question.Class != dnsmessage.ClassINET {
		return nil, fmt.Errorf("DNS response question mismatch: got %s %s class %d", question.Name, question.Type, question.Class)
	}

	var addrs []netip.Addr
	for {
		resourceHeader, err := parser.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse DoH answer header: %w", err)
		}
		if resourceHeader.Class != dnsmessage.ClassINET || resourceHeader.Type != qtype {
			if err := parser.SkipAnswer(); err != nil {
				return nil, fmt.Errorf("skip unrelated DoH answer: %w", err)
			}
			continue
		}

		switch qtype {
		case dnsmessage.TypeA:
			if resourceHeader.Length != 4 {
				if err := parser.SkipAnswer(); err != nil {
					return nil, fmt.Errorf("skip malformed A answer: %w", err)
				}
				continue
			}
			resource, err := parser.AResource()
			if err != nil {
				if skipErr := parser.SkipAnswer(); skipErr != nil {
					return nil, fmt.Errorf("skip malformed A answer: %w", skipErr)
				}
				continue
			}
			addrs = append(addrs, netip.AddrFrom4(resource.A))
		case dnsmessage.TypeAAAA:
			if resourceHeader.Length != 16 {
				if err := parser.SkipAnswer(); err != nil {
					return nil, fmt.Errorf("skip malformed AAAA answer: %w", err)
				}
				continue
			}
			resource, err := parser.AAAAResource()
			if err != nil {
				if skipErr := parser.SkipAnswer(); skipErr != nil {
					return nil, fmt.Errorf("skip malformed AAAA answer: %w", skipErr)
				}
				continue
			}
			addrs = append(addrs, netip.AddrFrom16(resource.AAAA))
		}
	}
	if err := parser.SkipAllAuthorities(); err != nil {
		return nil, fmt.Errorf("skip DoH authority section: %w", err)
	}
	if err := parser.SkipAllAdditionals(); err != nil {
		return nil, fmt.Errorf("skip DoH additional section: %w", err)
	}
	return uniquePublicAddresses(addrs), nil
}
