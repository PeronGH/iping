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
		Use:   "tcp <cidr|file>",
		Short: "Measure TCP connect time to every IP in a CIDR range or a file of ranges",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targets, err := loadTargets(args[0])
			if err != nil {
				return err
			}
			var dialer net.Dialer
			p := prober{dial: func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
				return dialer.DialContext(ctx, "tcp", addr.String())
			}}
			label := fmt.Sprintf("tcp %s port %d", targets.name, opts.port)
			return runScan(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), label, targets, opts, p)
		},
	}
	addScanFlags(cmd.Flags(), &opts, 80)

	return cmd
}
