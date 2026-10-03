// Command fake-upstream is a minimal DoH upstream for the end-to-end self
// test: it answers A with a Cloudflare-range IPv4, AAAA with a
// Cloudflare-range IPv6, and HTTPS with a target "." record carrying an ech
// parameter. Everything else gets an empty NOERROR answer.
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

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
		resp.Answers = []wire.Record{{
			Name: question.Name, Type: wire.TypeHTTPS, Class: wire.ClassIN, TTL: 60,
			RData: wire.SVCB{Priority: 1, Target: ".",
				Params: []wire.SvcParam{{Key: wire.ParamECH, Value: echConfigList}}},
		}}
	}
	return resp, nil
}

func main() {
	addr := "127.0.0.1:8053"
	if len(os.Args) > 1 {
		addr = os.Args[1]
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
	log.Printf("fake-upstream listening on %s", addr)
	if len(os.Args) > 3 {
		log.Fatal(http.ListenAndServeTLS(addr, os.Args[2], os.Args[3], nil))
	}
	log.Fatal(http.ListenAndServe(addr, nil))
}
