package cmd

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/spf13/cobra"
)

func newTCPCmd() *cobra.Command {
	var opts scanOptions

	cmd := &cobra.Command{
		Use:   "tcp <cidr>",
		Short: "Measure TCP connect time to every IP in a CIDR range",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			prefix, err := parseTarget(args[0])
			if err != nil {
				return err
			}
			var dialer net.Dialer
			dial := func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
				return dialer.DialContext(ctx, "tcp", addr.String())
			}
			label := fmt.Sprintf("tcp %s port %d", prefix, opts.port)
			return runScan(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), label, prefix, opts, dial)
		},
	}
	addScanFlags(cmd.Flags(), &opts, 80)

	return cmd
}
