package cmd

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/spf13/cobra"
)

type tcpOptions struct {
	port     uint16
	count    int
	interval time.Duration
	timeout  time.Duration
}

func newTCPCmd() *cobra.Command {
	var opts tcpOptions

	cmd := &cobra.Command{
		Use:   "tcp <host>",
		Short: "Measure TCP connect time to a host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTCP(cmd.Context(), args[0], opts)
		},
	}

	f := cmd.Flags()
	f.Uint16VarP(&opts.port, "port", "p", 80, "TCP port to connect to")
	f.IntVarP(&opts.count, "count", "c", 0, "stop after this many attempts (0 = until interrupted)")
	f.DurationVarP(&opts.interval, "interval", "i", time.Second, "wait between attempts")
	f.DurationVarP(&opts.timeout, "timeout", "W", 2*time.Second, "connect timeout per attempt")

	return cmd
}

func runTCP(ctx context.Context, host string, opts tcpOptions) error {
	addr := net.JoinHostPort(host, strconv.Itoa(int(opts.port)))
	dialer := net.Dialer{Timeout: opts.timeout}

	fmt.Printf("TCP PING %s\n", addr)

	var sent, received int
	var minRTT, maxRTT, totalRTT time.Duration

	for seq := 0; opts.count == 0 || seq < opts.count; seq++ {
		if seq > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(opts.interval):
			}
		}
		if ctx.Err() != nil {
			break
		}

		sent++
		start := time.Now()
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		rtt := time.Since(start)
		if err != nil {
			if ctx.Err() != nil {
				sent--
				break
			}
			fmt.Printf("seq=%d error: %v\n", seq, err)
			continue
		}
		remote := conn.RemoteAddr().String()
		conn.Close()

		received++
		totalRTT += rtt
		if received == 1 || rtt < minRTT {
			minRTT = rtt
		}
		maxRTT = max(maxRTT, rtt)
		fmt.Printf("connected to %s: seq=%d time=%s\n", remote, seq, formatRTT(rtt))
	}

	fmt.Printf("\n--- %s tcp ping statistics ---\n", addr)
	loss := 0.0
	if sent > 0 {
		loss = float64(sent-received) / float64(sent) * 100
	}
	fmt.Printf("%d attempts, %d successful, %.1f%% failed\n", sent, received, loss)
	if received > 0 {
		avg := totalRTT / time.Duration(received)
		fmt.Printf("rtt min/avg/max = %s/%s/%s\n", formatRTT(minRTT), formatRTT(avg), formatRTT(maxRTT))
	}

	if received == 0 {
		return fmt.Errorf("no successful connections to %s", addr)
	}
	return nil
}

func formatRTT(d time.Duration) string {
	return fmt.Sprintf("%.3fms", float64(d.Microseconds())/1000)
}
