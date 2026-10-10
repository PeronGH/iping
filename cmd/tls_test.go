package cmd

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestVerifyCertRejectsUntrustedChain(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	target := netip.MustParseAddrPort(srv.Listener.Addr().String())

	p := prober{
		dial: func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
			dialer := tls.Dialer{Config: &tls.Config{ServerName: "example.com", InsecureSkipVerify: true}}
			return dialer.DialContext(ctx, "tcp", addr.String())
		},
		verify: func(conn net.Conn) error { return verifyCert(conn.(*tls.Conn), "example.com") },
	}
	opts := scanOptions{port: target.Port(), count: 2, timeout: 5 * time.Second}

	r := probeHost(t.Context(), target.Addr(), opts, p)
	if r.sent != 2 || r.received != 0 || r.certErrors != 2 {
		t.Fatalf("got sent=%d received=%d certErrors=%d, want 2/0/2", r.sent, r.received, r.certErrors)
	}

	p.verify = nil
	r = probeHost(t.Context(), target.Addr(), opts, p)
	if r.received != 2 || r.certErrors != 0 {
		t.Fatalf("without verify: got received=%d certErrors=%d, want 2/0", r.received, r.certErrors)
	}
}
