package cmd

import (
	"fmt"
	"io"
	"math"
	"sync/atomic"
	"time"

	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

type progressBar struct {
	progress   *mpb.Progress
	bar        *mpb.Bar
	responsive atomic.Int64 // read by mpb's render goroutine
}

func newProgressBar(w io.Writer, size uint64) *progressBar {
	pb := &progressBar{
		progress: mpb.New(mpb.WithOutput(w), mpb.WithRefreshRate(100*time.Millisecond)),
	}
	pb.bar = pb.progress.AddBar(int64(min(size, math.MaxInt64)),
		mpb.PrependDecorators(
			decor.Name("scanning"),
			decor.Any(func(decor.Statistics) string {
				return fmt.Sprintf("%d responsive", pb.responsive.Load())
			}, decor.WCSyncSpace),
		),
		mpb.AppendDecorators(
			decor.CountersNoUnit("%d/%d", decor.WCSyncSpace),
			decor.Percentage(decor.WCSyncSpace),
			decor.AverageSpeed(nil, "%.0f hosts/s", decor.WCSyncSpace),
			decor.AverageETA(decor.ET_STYLE_GO, decor.WCSyncSpace),
		),
	)
	return pb
}

// add counts one probed host. The bar is incremented first so the responsive
// count shown never exceeds the probed count.
func (pb *progressBar) add(responsive bool) {
	pb.bar.Increment()
	if responsive {
		pb.responsive.Add(1)
	}
}

// finish stops the bar, aborting it if the scan ended early, and waits until
// the final frame is rendered.
func (pb *progressBar) finish() {
	pb.bar.Abort(false)
	pb.progress.Wait()
}
