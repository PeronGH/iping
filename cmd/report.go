package cmd

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strconv"
	"time"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
)

const fastestCount = 10

type scanStats struct {
	probed, responded        int
	sent, received           int
	minRTT, maxRTT, totalRTT time.Duration
	fastest                  []hostResult // sorted by average RTT, at most fastestCount
}

func (s *scanStats) add(r hostResult) {
	s.probed++
	s.sent += r.sent
	s.received += r.received
	if r.received == 0 {
		return
	}

	if s.responded == 0 || r.minRTT < s.minRTT {
		s.minRTT = r.minRTT
	}
	s.responded++
	s.maxRTT = max(s.maxRTT, r.maxRTT)
	s.totalRTT += r.total

	i, _ := slices.BinarySearchFunc(s.fastest, r.avg(), func(h hostResult, avg time.Duration) int {
		return cmp.Compare(h.avg(), avg)
	})
	if i < fastestCount {
		s.fastest = slices.Insert(s.fastest, i, r)[:min(len(s.fastest)+1, fastestCount)]
	}
}

var (
	cellStyle   = lipgloss.NewStyle().Padding(0, 1)
	headerStyle = cellStyle.Bold(true)
	borderStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
)

func newTable() *table.Table {
	return table.New().Border(lipgloss.RoundedBorder()).BorderStyle(borderStyle)
}

func (s *scanStats) write(w io.Writer, target string, port uint16, elapsed time.Duration, interrupted bool) error {
	if len(s.fastest) > 0 {
		fastest := newTable().
			Headers("#", "IP", "RECV", "LOSS", "MIN", "AVG", "MAX").
			StyleFunc(func(row, col int) lipgloss.Style {
				style := cellStyle
				if row == table.HeaderRow {
					style = headerStyle
				}
				if col != 1 {
					style = style.Align(lipgloss.Right)
				}
				return style
			})
		for i, r := range s.fastest {
			fastest.Row(
				strconv.Itoa(i+1), r.addr.String(), fmt.Sprintf("%d/%d", r.received, r.sent),
				percent(r.sent-r.received, r.sent),
				formatRTT(r.minRTT), formatRTT(r.avg()), formatRTT(r.maxRTT),
			)
		}
		if _, err := lipgloss.Fprintf(w, "Fastest %d of %d responding hosts\n%s\n", len(s.fastest), s.responded, fastest); err != nil {
			return err
		}
	}

	summary := newTable().
		StyleFunc(func(_, col int) lipgloss.Style {
			if col == 0 {
				return headerStyle
			}
			return cellStyle
		}).
		Row("Target", fmt.Sprintf("%s port %d", target, port)).
		Row("Hosts", fmt.Sprintf("%d probed, %d responded (%s)", s.probed, s.responded, percent(s.responded, s.probed))).
		Row("Attempts", fmt.Sprintf("%d sent, %d succeeded (%s loss)", s.sent, s.received, percent(s.sent-s.received, s.sent)))
	if s.received > 0 {
		avg := s.totalRTT / time.Duration(s.received)
		summary.Row("RTT", fmt.Sprintf("min/avg/max = %s/%s/%s", formatRTT(s.minRTT), formatRTT(avg), formatRTT(s.maxRTT)))
	}
	status := ""
	if interrupted {
		status = " (interrupted)"
	}
	summary.Row("Elapsed", elapsed.Round(time.Millisecond).String()+status)

	_, err := lipgloss.Fprintln(w, summary)
	return err
}

func percent(n, total int) string {
	if total == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f%%", float64(n)/float64(total)*100)
}

func formatRTT(d time.Duration) string {
	return fmt.Sprintf("%.3fms", float64(d.Microseconds())/1000)
}
