package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/quic-go/quic-go"
	"github.com/spf13/cobra"
)

func newTLSCmd() *cobra.Command {
	var opts scanOptions
	var sni string
	var insecure, useQUIC bool
	var alpn []string

	cmd := &cobra.Command{
		Use:   "tls <cidr|file>",
		Short: "Measure TLS handshake time to every IP in a CIDR range or a file of ranges",
		Long: `Measure TLS handshake time to every IP in a CIDR range or a file of ranges
(one CIDR or IP per line). By default this is TCP connect plus TLS handshake;
with --quic it is a QUIC handshake over UDP instead, which takes one round trip
fewer, so its times are not comparable to TCP+TLS.

Without --sni, the target IP is used as the server name, so no SNI is sent
(IP literals are not allowed in SNI) and the certificate is not verified.
With --sni, the certificate must be valid for that name unless --insecure is set.
Verification runs after the handshake and is not included in the RTT.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targets, err := loadTargets(args[0])
			if err != nil {
				return err
			}

			proto := "tls"
			if useQUIC {
				proto = "quic"
				if len(alpn) == 0 {
					alpn = []string{"h3"}
				}
				// Handshakes don't need large UDP buffers; the warning would break the progress bar.
				os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
			}

			tlsConfig := func(addr netip.AddrPort) *tls.Config {
				serverName := sni
				if serverName == "" {
					serverName = addr.Addr().String()
				}
				return &tls.Config{
					ServerName: serverName,
					NextProtos: alpn,
					// The chain is checked by verify, outside the timed handshake.
					InsecureSkipVerify: true,
				}
			}

			p := prober{proto: proto, dial: func(ctx context.Context, addr netip.AddrPort) (session, error) {
				dialer := tls.Dialer{Config: tlsConfig(addr)}
				conn, err := dialer.DialContext(ctx, "tcp", addr.String())
				if err != nil {
					return session{}, err
				}
				return session{close: conn.Close, peerCerts: conn.(*tls.Conn).ConnectionState().PeerCertificates}, nil
			}}
			if useQUIC {
				p.dial = func(ctx context.Context, addr netip.AddrPort) (session, error) {
					conn, err := quic.DialAddr(ctx, addr.String(), tlsConfig(addr), nil)
					if err != nil {
						return session{}, err
					}
					return session{
						close:     func() error { return conn.CloseWithError(0, "") },
						peerCerts: conn.ConnectionState().TLS.PeerCertificates,
					}, nil
				}
			}

			details := []string{fmt.Sprintf("%s %s port %d", proto, targets.name, opts.port)}
			if len(alpn) > 0 {
				details = append(details, "ALPN "+strings.Join(alpn, ","))
			}
			switch {
			case sni == "":
				details = append(details, "no SNI", "unverified")
			case insecure:
				details = append(details, "SNI "+sni, "unverified")
			default:
				details = append(details, "SNI "+sni, "verified")
				p.verify = func(peerCerts []*x509.Certificate) error { return verifyCert(peerCerts, sni) }
			}

			return runScan(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), strings.Join(details, ", "), targets, opts, p)
		},
	}
	addScanFlags(cmd, &opts, 443)
	f := cmd.Flags()
	f.StringVar(&sni, "sni", "", "server name for the TLS handshake (default: the target IP, sent as no SNI)")
	f.BoolVarP(&insecure, "insecure", "k", false, "skip certificate verification when --sni is set")
	f.BoolVar(&useQUIC, "quic", false, "perform a QUIC handshake over UDP instead of TCP+TLS")
	f.StringSliceVar(&alpn, "alpn", nil, "ALPN protocols to offer (default none, or h3 with --quic)")

	return cmd
}

// verifyCert checks the peer chain against the system roots, as crypto/tls
// would during the handshake.
func verifyCert(peerCerts []*x509.Certificate, serverName string) error {
	opts := x509.VerifyOptions{DNSName: serverName, Intermediates: x509.NewCertPool()}
	for _, cert := range peerCerts[1:] {
		opts.Intermediates.AddCert(cert)
	}
	_, err := peerCerts[0].Verify(opts)
	return err
}
