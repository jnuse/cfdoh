// Command fake-upstream is a minimal DoH upstream for the end-to-end self
// test: it answers A with a Cloudflare-range IPv4, AAAA with a
// Cloudflare-range IPv6, and HTTPS with a target "." record carrying an ech
// parameter. Everything else gets an empty NOERROR answer.
//
// Latency shaping for load tests: -delay 120 -jitter 80 sleeps 120ms ±80ms
// per query before answering, approximating a real upstream's tail.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/jnuse/cfdoh/internal/wire"
)

var echConfigList = []byte{0x00, 0x08, 0xfe, 0x0d, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44}

func answer(q *wire.Packet) (*wire.Packet, error) {
	if len(q.Questions) != 1 {
		return nil, fmt.Errorf("want exactly one question, got %d", len(q.Questions))
	}
	question := q.Questions[0]
	resp := &wire.Packet{
		Header:    wire.Header{ID: q.Header.ID, Flags: 0x8180},
		Questions: q.Questions,
	}
	switch question.Type {
	case wire.TypeA:
		ip, err := wire.ParseIPv4("104.16.132.229")
		if err != nil {
			return nil, err
		}
		resp.Answers = []wire.Record{{Name: question.Name, Type: wire.TypeA, Class: wire.ClassIN, TTL: 60, RData: wire.A{IP: ip}}}
	case wire.TypeAAAA:
		ip, err := wire.ParseIPv6("2606:4700:4700:1111:1111:2222:3333:4444")
		if err != nil {
			return nil, err
		}
		resp.Answers = []wire.Record{{Name: question.Name, Type: wire.TypeAAAA, Class: wire.ClassIN, TTL: 60, RData: wire.AAAA{IP: ip}}}
	case wire.TypeHTTPS:
		// Mirrors a real Cloudflare HTTPS answer: target "." with ech, plus
		// address hints inside the published ranges so the resolver's
		// answer-local Cloudflare classification can settle without a
		// follow-up A/AAAA resolve.
		v4, err4 := wire.ParseIPv4("104.16.132.229")
		v6, err6 := wire.ParseIPv6("2606:4700:4700:1111:1111:2222:3333:4444")
		if err4 != nil {
			return nil, err4
		}
		if err6 != nil {
			return nil, err6
		}
		resp.Answers = []wire.Record{{
			Name: question.Name, Type: wire.TypeHTTPS, Class: wire.ClassIN, TTL: 60,
			RData: wire.SVCB{Priority: 1, Target: ".",
				Params: []wire.SvcParam{
					{Key: wire.ParamECH, Value: echConfigList},
					{Key: wire.ParamIPv4Hint, Value: v4[:]},
					{Key: wire.ParamIPv6Hint, Value: v6[:]},
			}},
		}}
	}
	return resp, nil
}

func main() {
	delayMs := flag.Int("delay", 0, "per-query base delay in milliseconds")
	jitterMs := flag.Int("jitter", 0, "plus/minus jitter in milliseconds around the delay")
	flag.Parse()
	rest := flag.Args()
	addr := "127.0.0.1:8053"
	if len(rest) > 0 {
		addr = rest[0]
	}
	certFile, keyFile := "", ""
	if len(rest) > 2 {
		certFile, keyFile = rest[1], rest[2]
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
		if err != nil {
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}
		q, err := wire.Parse(body)
		if err != nil {
			http.Error(w, "malformed query", http.StatusBadRequest)
			return
		}
		if *delayMs > 0 {
			d := time.Duration(*delayMs) * time.Millisecond
			if *jitterMs > 0 {
				d += time.Duration(rand.Intn(2*(*jitterMs)+1)-*jitterMs) * time.Millisecond
			}
			time.Sleep(d)
		}
		resp, err := answer(q)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		encoded, err := resp.Encode()
		if err != nil {
			http.Error(w, "encode failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(encoded)
	})
	log.Printf("fake-upstream listening on %s (delay=%dms jitter=%dms)", addr, *delayMs, *jitterMs)
	if certFile != "" {
		log.Fatal(http.ListenAndServeTLS(addr, certFile, keyFile, nil))
	}
	log.Fatal(http.ListenAndServe(addr, nil))
}
