package cmd

import (
	"encoding/csv"
	"errors"
	"os"
	"strconv"
	"time"
)

type csvSink struct {
	path string
	rows int
	f    *os.File
	w    *csv.Writer
}

func createCSV(path string) (*csvSink, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	s := &csvSink{path: path, f: f, w: csv.NewWriter(f)}
	s.w.Write([]string{"ip", "sent", "received", "loss_pct", "min_ms", "avg_ms", "max_ms"})
	return s, nil
}

func (s *csvSink) write(r hostResult) {
	s.rows++
	loss := float64(r.sent-r.received) / float64(r.sent) * 100
	s.w.Write([]string{
		r.addr.String(),
		strconv.Itoa(r.sent),
		strconv.Itoa(r.received),
		strconv.FormatFloat(loss, 'f', 1, 64),
		formatMillis(r.minRTT),
		formatMillis(r.avg()),
		formatMillis(r.maxRTT),
	})
}

func (s *csvSink) close() error {
	s.w.Flush()
	return errors.Join(s.w.Error(), s.f.Close())
}

func formatMillis(d time.Duration) string {
	return strconv.FormatFloat(float64(d.Microseconds())/1000, 'f', 3, 64)
}
