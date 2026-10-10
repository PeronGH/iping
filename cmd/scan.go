package cmd

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

type scanOptions struct {
	port    uint16
	count   int
	timeout time.Duration
	workers int
	output  string
}

func addScanFlags(cmd *cobra.Command, opts *scanOptions, defaultPort uint16) {
	f := cmd.Flags()
	f.Uint16VarP(&opts.port, "port", "p", defaultPort, "port to connect to")
	f.IntVarP(&opts.count, "count", "c", 4, "attempts per IP")
	f.DurationVarP(&opts.timeout, "timeout", "W", 2*time.Second, "timeout per attempt")
	f.IntVarP(&opts.workers, "workers", "w", 1024, "number of concurrent workers")
	f.StringVarP(&opts.output, "output", "o", "", "CSV file for responsive hosts (default <target>-<protocol>.csv, use /dev/null to disable)")
}

// outputPath defaults to a name derived from the target. The protocol suffix
// keeps a target file like ips.csv from being overwritten by its own results.
func (o scanOptions) outputPath(targets *targetSet, proto string) string {
	if o.output != "" {
		return o.output
	}
	return targets.slug + "-" + proto + ".csv"
}

// prober performs one attempt: dial is timed, verify (optional) runs on the
// connection afterwards so its cost doesn't skew the RTT.
type prober struct {
	proto  string
	dial   func(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
	verify func(conn net.Conn) error
}

type hostResult struct {
	addr                  netip.Addr
	sent, received        int
	certErrors            int
	minRTT, maxRTT, total time.Duration
}

func (r hostResult) avg() time.Duration {
	return r.total / time.Duration(r.received)
}

func runScan(ctx context.Context, out, errOut io.Writer, label string, targets *targetSet, opts scanOptions, p prober) error {
	sink, err := createCSV(opts.outputPath(targets, p.proto))
	if err != nil {
		return err
	}

	start := time.Now()
	bar := newProgressBar(errOut, targets.size)

	addrs := make(chan netip.Addr)
	go func() {
		defer close(addrs)
		for addr := range shuffledAddrs(targets) {
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
				results <- probeHost(ctx, addr, opts, p)
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
		bar.add(r.received > 0)
		if r.received > 0 {
			sink.write(r)
		}
	}
	bar.finish()

	if err := sink.close(); err != nil {
		return fmt.Errorf("save %s: %w", sink.path, err)
	}
	saved := fmt.Sprintf("%s (%d hosts)", sink.path, sink.rows)

	if err := stats.write(out, label, time.Since(start), ctx.Err() != nil, saved); err != nil {
		return err
	}
	if stats.responded == 0 {
		return fmt.Errorf("no hosts responded in %s", targets.name)
	}
	return nil
}

func probeHost(ctx context.Context, addr netip.Addr, opts scanOptions, p prober) hostResult {
	r := hostResult{addr: addr}
	target := netip.AddrPortFrom(addr, opts.port)

	for range opts.count {
		attemptCtx, cancel := context.WithTimeout(ctx, opts.timeout)
		start := time.Now()
		conn, err := p.dial(attemptCtx, target)
		rtt := time.Since(start)
		cancel()
		var verifyErr error
		if err == nil {
			if p.verify != nil {
				verifyErr = p.verify(conn)
			}
			conn.Close()
		}
		if ctx.Err() != nil {
			break
		}
		r.sent++
		if err != nil {
			continue
		}
		if verifyErr != nil {
			r.certErrors++
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
