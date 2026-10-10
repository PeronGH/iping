package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"

	"github.com/spf13/cobra"
)

func newTLSCmd() *cobra.Command {
	var opts scanOptions
	var sni string

	cmd := &cobra.Command{
		Use:   "tls <cidr>",
		Short: "Measure TCP connect plus TLS handshake time to every IP in a CIDR range",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			prefix, err := parseTarget(args[0])
			if err != nil {
				return err
			}
			dial := func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
				serverName := sni
				if serverName == "" {
					serverName = addr.Addr().String()
				}
				dialer := tls.Dialer{Config: &tls.Config{
					ServerName: serverName,
					// Only handshake latency is measured; the certificate is not trusted for anything.
					InsecureSkipVerify: true,
				}}
				return dialer.DialContext(ctx, "tcp", addr.String())
			}
			serverName := sni
			if serverName == "" {
				serverName = "<target IP>"
			}
			label := fmt.Sprintf("tls %s port %d, SNI %s", prefix, opts.port, serverName)
			return runScan(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), label, prefix, opts, dial)
		},
	}
	addScanFlags(cmd.Flags(), &opts, 443)
	cmd.Flags().StringVar(&sni, "sni", "", "server name for the TLS handshake (default: the target IP)")

	return cmd
}
