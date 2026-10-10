package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestVerifyCertRejectsUntrustedChain(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	target := netip.MustParseAddrPort(srv.Listener.Addr().String())

	clientConfig := &tls.Config{ServerName: "example.com", InsecureSkipVerify: true}
	tcpDial := func(ctx context.Context, addr netip.AddrPort) (session, error) {
		dialer := tls.Dialer{Config: clientConfig}
		conn, err := dialer.DialContext(ctx, "tcp", addr.String())
		if err != nil {
			return session{}, err
		}
		return session{close: conn.Close, peerCerts: conn.(*tls.Conn).ConnectionState().PeerCertificates}, nil
	}

	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: srv.TLS.Certificates, NextProtos: []string{"h3"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			if _, err := ln.Accept(context.Background()); err != nil {
				return
			}
		}
	}()
	quicTarget := netip.MustParseAddrPort(ln.Addr().String())
	quicDial := func(ctx context.Context, addr netip.AddrPort) (session, error) {
		config := clientConfig.Clone()
		config.NextProtos = []string{"h3"}
		conn, err := quic.DialAddr(ctx, addr.String(), config, nil)
		if err != nil {
			return session{}, err
		}
		return session{close: func() error { return conn.CloseWithError(0, "") }, peerCerts: conn.ConnectionState().TLS.PeerCertificates}, nil
	}

	verify := func(peerCerts []*x509.Certificate) error { return verifyCert(peerCerts, "example.com") }
	for _, tc := range []struct {
		name   string
		target netip.AddrPort
		dial   func(context.Context, netip.AddrPort) (session, error)
	}{
		{"tcp", target, tcpDial},
		{"quic", quicTarget, quicDial},
	} {
		opts := scanOptions{port: tc.target.Port(), count: 2, timeout: 5 * time.Second}

		r := probeHost(t.Context(), tc.target.Addr(), opts, prober{dial: tc.dial, verify: verify})
		if r.sent != 2 || r.received != 0 || r.certErrors != 2 {
			t.Fatalf("%s: got sent=%d received=%d certErrors=%d, want 2/0/2", tc.name, r.sent, r.received, r.certErrors)
		}

		r = probeHost(t.Context(), tc.target.Addr(), opts, prober{dial: tc.dial})
		if r.received != 2 || r.certErrors != 0 {
			t.Fatalf("%s without verify: got received=%d certErrors=%d, want 2/0", tc.name, r.received, r.certErrors)
		}
	}
}
