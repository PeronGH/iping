package cmd

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

type scanOptions struct {
	port       uint16
	count      int
	timeout    time.Duration
	workers    int
	output     string
	autoOutput bool
}

func addScanFlags(cmd *cobra.Command, opts *scanOptions, defaultPort uint16) {
	f := cmd.Flags()
	f.Uint16VarP(&opts.port, "port", "p", defaultPort, "port to connect to")
	f.IntVarP(&opts.count, "count", "c", 4, "attempts per IP")
	f.DurationVarP(&opts.timeout, "timeout", "W", 2*time.Second, "timeout per attempt")
	f.IntVarP(&opts.workers, "workers", "w", 1024, "number of concurrent workers")
	f.StringVarP(&opts.output, "output", "o", "", "save responsive hosts as CSV to this file")
	f.BoolVarP(&opts.autoOutput, "auto-output", "O", false, "save responsive hosts as CSV to a file named after the target")
	cmd.MarkFlagsMutuallyExclusive("output", "auto-output")
}

// outputPath returns where to save the CSV, or "" for no file. Auto names get
// a protocol suffix so a target file like ips.csv is never overwritten.
func (o scanOptions) outputPath(targets *targetSet, proto string) string {
	if o.autoOutput {
		return targets.slug + "-" + proto + ".csv"
	}
	return o.output
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
	var sink *csvSink
	if path := opts.outputPath(targets, p.proto); path != "" {
		var err error
		if sink, err = createCSV(path); err != nil {
			return err
		}
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
		bar.Add(1)
		if r.received > 0 {
			bar.Describe(barDescription(stats.responded))
			if sink != nil {
				sink.write(r)
			}
		}
	}
	if !bar.IsFinished() {
		bar.Exit()
	}

	saved := ""
	if sink != nil {
		if err := sink.close(); err != nil {
			return fmt.Errorf("save %s: %w", sink.path, err)
		}
		saved = fmt.Sprintf("%s (%d hosts)", sink.path, sink.rows)
	}

	if err := stats.write(out, label, time.Since(start), ctx.Err() != nil, saved); err != nil {
		return err
	}
	if stats.responded == 0 {
		return fmt.Errorf("no hosts responded in %s", targets.name)
	}
	return nil
}

func barDescription(responsive int) string {
	return fmt.Sprintf("scanning, %d responsive", responsive)
}

func newProgressBar(w io.Writer, size uint64) *progressbar.ProgressBar {
	total := int64(-1)
	if size <= math.MaxInt64 {
		total = int64(size)
	}
	return progressbar.NewOptions64(total,
		progressbar.OptionSetWriter(w),
		progressbar.OptionSetDescription(barDescription(0)),
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
