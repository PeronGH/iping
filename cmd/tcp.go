package cmd

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

type tcpOptions struct {
	port    uint16
	count   int
	timeout time.Duration
	workers int
}

type hostResult struct {
	addr                  netip.Addr
	sent, received        int
	minRTT, maxRTT, total time.Duration
}

func (r hostResult) avg() time.Duration {
	return r.total / time.Duration(r.received)
}

func newTCPCmd() *cobra.Command {
	var opts tcpOptions

	cmd := &cobra.Command{
		Use:   "tcp <cidr>",
		Short: "Measure TCP connect time to every IP in a CIDR range",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			prefix, err := parseTarget(args[0])
			if err != nil {
				return err
			}
			return runTCP(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], prefix, opts)
		},
	}

	f := cmd.Flags()
	f.Uint16VarP(&opts.port, "port", "p", 80, "TCP port to connect to")
	f.IntVarP(&opts.count, "count", "c", 4, "connection attempts per IP")
	f.DurationVarP(&opts.timeout, "timeout", "W", 2*time.Second, "connect timeout per attempt")
	f.IntVarP(&opts.workers, "workers", "w", 1024, "number of concurrent workers")

	return cmd
}

// parseTarget accepts a CIDR or a single IP, treated as a full-length prefix.
func parseTarget(s string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		addr, addrErr := netip.ParseAddr(s)
		if addrErr != nil {
			return netip.Prefix{}, fmt.Errorf("invalid target %q: expected CIDR or IP", s)
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	if prefix.Addr().BitLen()-prefix.Bits() > 64 {
		return netip.Prefix{}, fmt.Errorf("target %s is too large: at most 64 host bits are supported", s)
	}
	return prefix.Masked(), nil
}

func runTCP(ctx context.Context, out, errOut io.Writer, target string, prefix netip.Prefix, opts tcpOptions) error {
	start := time.Now()
	bar := newProgressBar(errOut, prefix)

	addrs := make(chan netip.Addr)
	go func() {
		defer close(addrs)
		for addr := range shuffledAddrs(prefix) {
			select {
			case addrs <- addr:
			case <-ctx.Done():
				return
			}
		}
	}()

	results := make(chan hostResult)
	var wg sync.WaitGroup
	for range opts.workers {
		wg.Go(func() {
			for addr := range addrs {
				results <- probeTCP(ctx, addr, opts)
			}
		})
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var stats scanStats
	for r := range results {
		if r.sent == 0 {
			continue
		}
		stats.add(r)
		bar.Add(1)
	}
	if !bar.IsFinished() {
		bar.Exit()
	}

	if err := stats.write(out, target, opts.port, time.Since(start), ctx.Err() != nil); err != nil {
		return err
	}
	if stats.responded == 0 {
		return fmt.Errorf("no hosts responded in %s", prefix)
	}
	return nil
}

func newProgressBar(w io.Writer, prefix netip.Prefix) *progressbar.ProgressBar {
	total := int64(-1)
	if hostBits := prefix.Addr().BitLen() - prefix.Bits(); hostBits < 63 {
		total = 1 << hostBits
	}
	return progressbar.NewOptions64(total,
		progressbar.OptionSetWriter(w),
		progressbar.OptionSetDescription("scanning"),
		progressbar.OptionSetItsString("hosts"),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionFullWidth(),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionOnCompletion(func() { fmt.Fprintln(w) }),
	)
}

func probeTCP(ctx context.Context, addr netip.Addr, opts tcpOptions) hostResult {
	r := hostResult{addr: addr}
	target := net.JoinHostPort(addr.String(), strconv.Itoa(int(opts.port)))
	dialer := net.Dialer{Timeout: opts.timeout}

	for range opts.count {
		start := time.Now()
		conn, err := dialer.DialContext(ctx, "tcp", target)
		rtt := time.Since(start)
		if err == nil {
			conn.Close()
		}
		if ctx.Err() != nil {
			break
		}
		r.sent++
		if err != nil {
			continue
		}

		r.received++
		r.total += rtt
		if r.received == 1 || rtt < r.minRTT {
			r.minRTT = rtt
		}
		r.maxRTT = max(r.maxRTT, rtt)
	}
	return r
}
