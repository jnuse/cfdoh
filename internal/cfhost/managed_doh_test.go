package cfhost

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func testDNSName(name string) (dnsmessage.Name, error) {
	return dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
}

func decodeDoHRequest(r *http.Request) (dnsmessage.Message, error) {
	var query dnsmessage.Message
	if r.Method != http.MethodGet {
		return query, fmt.Errorf("method %q", r.Method)
	}
	encoded := r.URL.Query().Get("dns")
	if encoded == "" || strings.Contains(encoded, "=") {
		return query, fmt.Errorf("invalid dns query parameter %q", encoded)
	}
	packet, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return query, err
	}
	if err := query.Unpack(packet); err != nil {
		return query, err
	}
	return query, nil
}

func packTestDNSResponse(query dnsmessage.Message, rcode dnsmessage.RCode, answers ...dnsmessage.Resource) ([]byte, error) {
	response := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: query.ID, Response: true, RCode: rcode},
		Questions: query.Questions,
		Answers:   answers,
	}
	return response.Pack()
}

func cloneDNSMessage(message dnsmessage.Message) dnsmessage.Message {
	message.Questions = append([]dnsmessage.Question(nil), message.Questions...)
	message.Answers = append([]dnsmessage.Resource(nil), message.Answers...)
	message.Authorities = append([]dnsmessage.Resource(nil), message.Authorities...)
	message.Additionals = append([]dnsmessage.Resource(nil), message.Additionals...)
	return message
}

func testDNSAddressAnswer(name string, addr netip.Addr) (dnsmessage.Resource, error) {
	owner, err := testDNSName(name)
	if err != nil {
		return dnsmessage.Resource{}, err
	}
	header := dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, TTL: 60}
	if addr.Is4() {
		header.Type = dnsmessage.TypeA
		return dnsmessage.Resource{Header: header, Body: &dnsmessage.AResource{A: addr.As4()}}, nil
	}
	if addr.Is6() {
		header.Type = dnsmessage.TypeAAAA
		return dnsmessage.Resource{Header: header, Body: &dnsmessage.AAAAResource{AAAA: addr.As16()}}, nil
	}
	return dnsmessage.Resource{}, fmt.Errorf("invalid test address %v", addr)
}

func testDoHFetcher(primary, backup string) *fetcher {
	f := insecureFetcher()
	f.dohEndpoints = [2]string{primary, backup}
	return f
}

type managedDNSRoundTripper func(*http.Request) (*http.Response, error)

func (rt managedDNSRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt(req)
}

func TestManagedDNSDoHRequestAndFamilyExtraction(t *testing.T) {
	var requestCount atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		if got := r.Header.Get("Accept"); got != "application/dns-message" {
			t.Errorf("Accept = %q, want application/dns-message", got)
		}
		query, err := decodeDoHRequest(r)
		if err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		if query.ID != 0 || len(query.Questions) != 1 || query.Questions[0].Class != dnsmessage.ClassINET {
			t.Errorf("unexpected DNS question: %+v", query)
		}
		if got := query.Questions[0].Name.String(); got != "cdn.example.com." {
			t.Errorf("question name = %q", got)
		}

		var answers []dnsmessage.Resource
		var answerAddrs []string
		if query.Questions[0].Type == dnsmessage.TypeA {
			answerAddrs = []string{"8.8.8.8", "10.0.0.1", "2001:4860::1"}
		} else {
			answerAddrs = []string{"1.1.1.1", "2001:4860:4860::8888"}
		}
		for _, raw := range answerAddrs {
			addr := netip.MustParseAddr(raw)
			answer, err := testDNSAddressAnswer("cdn.example.com", addr)
			if err != nil {
				t.Errorf("build answer: %v", err)
				return
			}
			answers = append(answers, answer)
		}
		body, err := packTestDNSResponse(query, dnsmessage.RCodeSuccess, answers...)
		if err != nil {
			t.Errorf("pack response: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(body)
	}))
	defer server.Close()

	f := testDoHFetcher(server.URL, server.URL)
	for _, test := range []struct {
		qtype dnsmessage.Type
		want  []string
	}{
		{dnsmessage.TypeA, []string{"8.8.8.8"}},
		{dnsmessage.TypeAAAA, []string{"2001:4860:4860::8888"}},
	} {
		got, err := queryManagedDNSQuestion(context.Background(), f, "cdn.example.com", test.qtype)
		if err != nil {
			t.Fatalf("query %s: %v", test.qtype, err)
		}
		if gotStrings := addrStrings(got); !reflect.DeepEqual(gotStrings, test.want) {
			t.Fatalf("%s answers = %v, want %v", test.qtype, gotStrings, test.want)
		}
	}
	if got := requestCount.Load(); got != 2 {
		t.Fatalf("provider requests = %d, want 2 (no backup after usable primary answers)", got)
	}
}

func TestManagedDNSFallsBackForUnusableOrFailedPrimary(t *testing.T) {
	for _, mode := range []string{"no usable address", "HTTP failure", "media type failure"} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.Mutex
			var paths []string
			var questions []string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				query, err := decodeDoHRequest(r)
				if err != nil {
					t.Errorf("decode request: %v", err)
					http.Error(w, "bad query", http.StatusBadRequest)
					return
				}
				mu.Lock()
				paths = append(paths, r.URL.Path)
				questions = append(questions, fmt.Sprintf("%s/%s", query.Questions[0].Name, query.Questions[0].Type))
				mu.Unlock()
				if r.URL.Path == "/ali" {
					if mode == "HTTP failure" {
						http.Error(w, "upstream failure", http.StatusBadGateway)
						return
					}
					primaryAddr := "10.0.0.1"
					mediaType := "application/dns-message"
					if mode == "media type failure" {
						primaryAddr = "8.8.8.8"
						mediaType = "text/plain"
					}
					answer, _ := testDNSAddressAnswer("cdn.example.com", netip.MustParseAddr(primaryAddr))
					body, _ := packTestDNSResponse(query, dnsmessage.RCodeSuccess, answer)
					w.Header().Set("Content-Type", mediaType)
					_, _ = w.Write(body)
					return
				}
				answer, _ := testDNSAddressAnswer("cdn.example.com", netip.MustParseAddr("8.8.4.4"))
				body, _ := packTestDNSResponse(query, dnsmessage.RCodeSuccess, answer)
				w.Header().Set("Content-Type", "application/dns-message")
				_, _ = w.Write(body)
			}))
			defer server.Close()

			f := testDoHFetcher(server.URL+"/ali", server.URL+"/cf")
			got, err := queryManagedDNSQuestion(context.Background(), f, "cdn.example.com", dnsmessage.TypeA)
			if err != nil {
				t.Fatalf("query should succeed through backup: %v", err)
			}
			if gotStrings := addrStrings(got); !reflect.DeepEqual(gotStrings, []string{"8.8.4.4"}) {
				t.Fatalf("backup answers = %v", gotStrings)
			}
			mu.Lock()
			defer mu.Unlock()
			if !reflect.DeepEqual(paths, []string{"/ali", "/cf"}) {
				t.Fatalf("provider order = %v", paths)
			}
			if len(questions) != 2 || questions[0] != questions[1] {
				t.Fatalf("fallback did not repeat same question: %v", questions)
			}
		})
	}
}

func TestManagedDNSCancellationDoesNotStartBackup(t *testing.T) {
	started := make(chan struct{})
	var requests atomic.Int32
	f := &fetcher{
		client: &http.Client{Transport: managedDNSRoundTripper(func(req *http.Request) (*http.Response, error) {
			requests.Add(1)
			if req.URL.Path != "/ali" {
				t.Errorf("unexpected backup request to %s", req.URL.Path)
				return nil, fmt.Errorf("unexpected backup request")
			}
			close(started)
			<-req.Context().Done()
			return nil, req.Context().Err()
		})},
		dohEndpoints: [2]string{"https://doh.example/ali", "https://doh.example/cf"},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := queryManagedDNSQuestion(ctx, f, "cdn.example.com", dnsmessage.TypeA)
		done <- err
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("primary request did not start")
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("query error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("query did not stop after cancellation")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("provider requests after cancellation = %d, want only the primary", got)
	}
}

func TestManagedDNSResponseValidation(t *testing.T) {
	queryPacket, err := packManagedDNSQuestion("cdn.example.com", dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	var query dnsmessage.Message
	if err := query.Unpack(queryPacket); err != nil {
		t.Fatal(err)
	}
	answer, err := testDNSAddressAnswer("cdn.example.com", netip.MustParseAddr("8.8.8.8"))
	if err != nil {
		t.Fatal(err)
	}
	owner, err := testDNSName("cdn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	malformedAnswer := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, TTL: 60},
		Body:   &dnsmessage.UnknownResource{Type: dnsmessage.TypeA, Data: []byte{8, 8, 8}},
	}
	validPacket, err := packTestDNSResponse(query, dnsmessage.RCodeSuccess, answer)
	if err != nil {
		t.Fatal(err)
	}
	if addrs, err := parseManagedDNSResponse(validPacket, "cdn.example.com", dnsmessage.TypeA); err != nil || len(addrs) != 1 {
		t.Fatalf("valid response rejected: addrs=%v err=%v", addrs, err)
	}
	malformedPacket, err := packTestDNSResponse(query, dnsmessage.RCodeSuccess, malformedAnswer, answer)
	if err != nil {
		t.Fatal(err)
	}
	if addrs, err := parseManagedDNSResponse(malformedPacket, "cdn.example.com", dnsmessage.TypeA); err != nil || len(addrs) != 1 || addrs[0].String() != "8.8.8.8" {
		t.Fatalf("malformed answer should be ignored: addrs=%v err=%v", addrs, err)
	}

	var valid dnsmessage.Message
	if err := valid.Unpack(validPacket); err != nil {
		t.Fatal(err)
	}
	otherName, _ := testDNSName("other.example.com")
	secondQuestion := dnsmessage.Question{Name: otherName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	cases := []struct {
		name   string
		packet []byte
	}{
		{name: "malformed wire", packet: []byte{0, 1, 2}},
		{name: "wrong ID", packet: func() []byte { m := cloneDNSMessage(valid); m.ID = 7; b, _ := m.Pack(); return b }()},
		{name: "QR clear", packet: func() []byte { m := cloneDNSMessage(valid); m.Response = false; b, _ := m.Pack(); return b }()},
		{name: "nonzero opcode", packet: func() []byte {
			m := cloneDNSMessage(valid)
			m.OpCode = dnsmessage.OpCode(1)
			b, _ := m.Pack()
			return b
		}()},
		{name: "truncated", packet: func() []byte { m := cloneDNSMessage(valid); m.Truncated = true; b, _ := m.Pack(); return b }()},
		{name: "negative response", packet: func() []byte {
			m := cloneDNSMessage(valid)
			m.RCode = dnsmessage.RCodeNameError
			b, _ := m.Pack()
			return b
		}()},
		{name: "question mismatch", packet: func() []byte {
			m := cloneDNSMessage(valid)
			m.Questions[0].Name = otherName
			b, _ := m.Pack()
			return b
		}()},
		{name: "multiple questions", packet: func() []byte {
			m := cloneDNSMessage(valid)
			m.Questions = append(m.Questions, secondQuestion)
			b, _ := m.Pack()
			return b
		}()},
		{name: "wrong type", packet: func() []byte {
			m := cloneDNSMessage(valid)
			m.Questions[0].Type = dnsmessage.TypeAAAA
			b, _ := m.Pack()
			return b
		}()},
		{name: "wrong class", packet: func() []byte {
			m := cloneDNSMessage(valid)
			m.Questions[0].Class = dnsmessage.ClassCHAOS
			b, _ := m.Pack()
			return b
		}()},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseManagedDNSResponse(test.packet, "cdn.example.com", dnsmessage.TypeA); err == nil {
				t.Fatal("invalid DNS response was accepted")
			}
		})
	}
}

func TestManagedDomainQueriesAreBoundedAndOrdered(t *testing.T) {
	var active atomic.Int32
	var maxActive atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			previous := maxActive.Load()
			if current <= previous || maxActive.CompareAndSwap(previous, current) {
				break
			}
		}
		query, err := decodeDoHRequest(r)
		if err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		name := strings.TrimSuffix(query.Questions[0].Name.String(), ".")
		time.Sleep(time.Duration(len(name)%4+1) * 5 * time.Millisecond)
		if name == "b.example.com" && query.Questions[0].Type == dnsmessage.TypeAAAA {
			body, _ := packTestDNSResponse(query, dnsmessage.RCodeServerFailure)
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(body)
			return
		}
		var raw string
		switch name {
		case "b.example.com":
			raw = "8.8.8.1"
		case "a.example.com":
			if query.Questions[0].Type == dnsmessage.TypeA {
				raw = "8.8.8.2"
			} else {
				raw = "2001:4860::2"
			}
		case "c.example.com":
			if query.Questions[0].Type == dnsmessage.TypeA {
				raw = "8.8.8.3"
			} else {
				raw = "2001:4860::3"
			}
		}
		answer, err := testDNSAddressAnswer(name, netip.MustParseAddr(raw))
		if err != nil {
			t.Errorf("build answer: %v", err)
			return
		}
		body, err := packTestDNSResponse(query, dnsmessage.RCodeSuccess, answer)
		if err != nil {
			t.Errorf("pack response: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(body)
	}))
	defer server.Close()

	got := fetchManagedDomainCandidates(context.Background(),
		[]string{"b.example.com", "a.example.com", "c.example.com"},
		testDoHFetcher(server.URL+"/ali", server.URL+"/cf"), 2)
	want := []string{"8.8.8.1", "8.8.8.2", "2001:4860::2", "8.8.8.3", "2001:4860::3"}
	if gotStrings := addrStrings(got); !reflect.DeepEqual(gotStrings, want) {
		t.Fatalf("ordered partial results = %v, want %v", gotStrings, want)
	}
	if got := maxActive.Load(); got > 2 || got < 2 {
		t.Fatalf("maximum concurrent queries = %d, want exactly 2 and never above the limit", got)
	}
}

func TestMergeCandidateSetsReservesManagedAnswers(t *testing.T) {
	cases := []struct {
		name       string
		configured []string
		managed    []string
		limit      int
		want       []string
	}{
		{
			name:       "retained duplicate stays in source position",
			configured: []string{"8.8.8.1", "8.8.8.2", "8.8.8.3"},
			managed:    []string{"8.8.8.2", "1.1.1.1"},
			limit:      3,
			want:       []string{"8.8.8.1", "8.8.8.2", "1.1.1.1"},
		},
		{
			name:       "duplicate in truncated tail does not consume two slots",
			configured: []string{"8.8.8.1", "8.8.8.2", "1.1.1.1"},
			managed:    []string{"1.1.1.1", "9.9.9.9"},
			limit:      2,
			want:       []string{"1.1.1.1", "9.9.9.9"},
		},
		{
			name:       "DNS-only overflow truncates in stable order",
			configured: []string{"8.8.8.1"},
			managed:    []string{"1.1.1.1", "9.9.9.9", "8.8.4.4"},
			limit:      2,
			want:       []string{"1.1.1.1", "9.9.9.9"},
		},
		{
			name:       "source order and managed append order",
			configured: []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"},
			managed:    []string{"1.1.1.1", "4.4.4.4"},
			limit:      3,
			want:       []string{"8.8.8.8", "1.1.1.1", "4.4.4.4"},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := mergeCandidateSets(parseIPList(strings.Join(test.configured, ",")),
				parseIPList(strings.Join(test.managed, ",")), test.limit)
			if gotStrings := addrStrings(got); !reflect.DeepEqual(gotStrings, test.want) {
				t.Fatalf("merged candidates = %v, want %v", gotStrings, test.want)
			}
		})
	}
}

func TestRunOnceProbesManagedDomainCandidates(t *testing.T) {
	domain := "cdn.example.com"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, err := decodeDoHRequest(r)
		if err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		var raw string
		if query.Questions[0].Type == dnsmessage.TypeA {
			raw = "8.8.8.8"
		} else {
			raw = "2001:4860::8888"
		}
		answer, err := testDNSAddressAnswer(domain, netip.MustParseAddr(raw))
		if err != nil {
			t.Errorf("build answer: %v", err)
			return
		}
		body, err := packTestDNSResponse(query, dnsmessage.RCodeSuccess, answer)
		if err != nil {
			t.Errorf("pack response: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(body)
	}))
	defer server.Close()

	dir := t.TempDir()
	cfg := testConfig(t, dir+"/hosts", dir+"/state.json", "list:1.1.1.1")
	cfg.ManagedDomains = []string{domain}
	f := testDoHFetcher(server.URL, server.URL)
	withPassCandidateFetcher(t, func(ctx context.Context, cfg *Config) ([]netip.Addr, bool) {
		return fetchCandidatesWithManagedDomains(ctx, cfg.Sources, cfg.ManagedDomains, f,
			cfg.CandidateLimit, cfg.Concurrency)
	})

	var probed []netip.Addr
	oldProbes := runProbes
	runProbes = func(_ context.Context, candidates []netip.Addr, _ probeOptions) []probeOutcome {
		probed = append([]netip.Addr(nil), candidates...)
		return []probeOutcome{
			{addr: netip.MustParseAddr("1.1.1.1"), median: 30 * time.Millisecond, ok: true},
			{addr: netip.MustParseAddr("8.8.8.8"), median: 10 * time.Millisecond, ok: true},
			{addr: netip.MustParseAddr("2001:4860::8888"), median: 20 * time.Millisecond, ok: true},
		}
	}
	t.Cleanup(func() { runProbes = oldProbes })

	if err := RunOnce(context.Background(), cfg); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	want := []string{"1.1.1.1", "8.8.8.8", "2001:4860::8888"}
	if got := addrStrings(probed); !reflect.DeepEqual(got, want) {
		t.Fatalf("probed candidates = %v, want %v", got, want)
	}
	st, found := loadState(cfg.StatePath)
	if !found || !reflect.DeepEqual(st.Candidates, want) {
		t.Fatalf("state candidates = %v, found=%v, want %v", st.Candidates, found, want)
	}
	if st.CurrentV4 != "8.8.8.8" || st.CurrentV6 != "2001:4860::8888" {
		t.Fatalf("managed answers did not use existing family selection: v4=%q v6=%q", st.CurrentV4, st.CurrentV6)
	}
}

func TestRunOnceFallsBackToPreviousCandidatesWhenCurrentSourcesAreEmpty(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(t, dir+"/hosts", dir+"/state.json", "list:")
	if err := saveState(cfg.StatePath, clientState{Candidates: []string{"8.8.4.4"}}); err != nil {
		t.Fatal(err)
	}
	withPassCandidateFetcher(t, func(context.Context, *Config) ([]netip.Addr, bool) {
		return nil, true
	})

	var probed []netip.Addr
	oldProbes := runProbes
	runProbes = func(_ context.Context, candidates []netip.Addr, _ probeOptions) []probeOutcome {
		probed = append([]netip.Addr(nil), candidates...)
		return []probeOutcome{{addr: netip.MustParseAddr("8.8.4.4"), median: 10 * time.Millisecond, ok: true}}
	}
	t.Cleanup(func() { runProbes = oldProbes })
	if err := RunOnce(context.Background(), cfg); err != nil {
		t.Fatalf("RunOnce should use saved candidates: %v", err)
	}
	if got := addrStrings(probed); !reflect.DeepEqual(got, []string{"8.8.4.4"}) {
		t.Fatalf("fallback probe candidates = %v", got)
	}
}

func TestConfiguredDoHEndpointsUsedByPass(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, err := decodeDoHRequest(r)
		if err != nil {
			t.Errorf("decode: %v", err)
			return
		}
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/first" {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		addr := netip.MustParseAddr("8.8.4.4")
		if query.Questions[0].Type == dnsmessage.TypeAAAA {
			addr = netip.MustParseAddr("2001:4860:4860::8888")
		}
		answer, _ := testDNSAddressAnswer("probe.example.com", addr)
		body, _ := packTestDNSResponse(query, dnsmessage.RCodeSuccess, answer)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(body)
	}))
	defer server.Close()
	previous := defaultFetcher
	defaultFetcher = insecureFetcher()
	defer func() { defaultFetcher = previous }()
	cfg := &Config{Sources: []string{"list:1.1.1.1"}, ManagedDomains: []string{"probe.example.com"}, DNS1: server.URL + "/first", DNS2: server.URL + "/second", CandidateLimit: 10, Concurrency: 1}
	got, allFailed := fetchCandidatesForPass(context.Background(), cfg)
	if allFailed || !reflect.DeepEqual(addrStrings(got), []string{"1.1.1.1", "8.8.4.4", "2001:4860:4860::8888"}) {
		t.Fatalf("candidates = %v, allFailed=%v", got, allFailed)
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(paths, []string{"/first", "/second", "/first", "/second"}) {
		t.Fatalf("requests = %v", paths)
	}
}
