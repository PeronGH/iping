package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"

	"github.com/spf13/cobra"
)

func newTLSCmd() *cobra.Command {
	var opts scanOptions
	var sni string
	var insecure bool

	cmd := &cobra.Command{
		Use:   "tls <cidr>",
		Short: "Measure TCP connect plus TLS handshake time to every IP in a CIDR range",
		Long: `Measure TCP connect plus TLS handshake time to every IP in a CIDR range.

Without --sni, the target IP is used as the server name, so no SNI is sent
(IP literals are not allowed in SNI) and the certificate is not verified.
With --sni, the certificate must be valid for that name unless --insecure is set.
Verification runs after the handshake and is not included in the RTT.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			prefix, err := parseTarget(args[0])
			if err != nil {
				return err
			}

			p := prober{dial: func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
				serverName := sni
				if serverName == "" {
					serverName = addr.Addr().String()
				}
				dialer := tls.Dialer{Config: &tls.Config{
					ServerName: serverName,
					// The chain is checked by verify, outside the timed handshake.
					InsecureSkipVerify: true,
				}}
				return dialer.DialContext(ctx, "tcp", addr.String())
			}}

			label := fmt.Sprintf("tls %s port %d, no SNI, unverified", prefix, opts.port)
			if sni != "" {
				status := "verified"
				if insecure {
					status = "unverified"
				} else {
					p.verify = func(conn net.Conn) error { return verifyCert(conn.(*tls.Conn), sni) }
				}
				label = fmt.Sprintf("tls %s port %d, SNI %s, %s", prefix, opts.port, sni, status)
			}

			return runScan(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), label, prefix, opts, p)
		},
	}
	addScanFlags(cmd.Flags(), &opts, 443)
	cmd.Flags().StringVar(&sni, "sni", "", "server name for the TLS handshake (default: the target IP, sent as no SNI)")
	cmd.Flags().BoolVarP(&insecure, "insecure", "k", false, "skip certificate verification when --sni is set")

	return cmd
}

// verifyCert checks the peer chain against the system roots, as crypto/tls
// would during the handshake.
func verifyCert(conn *tls.Conn, serverName string) error {
	certs := conn.ConnectionState().PeerCertificates
	opts := x509.VerifyOptions{DNSName: serverName, Intermediates: x509.NewCertPool()}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	_, err := certs[0].Verify(opts)
	return err
}
