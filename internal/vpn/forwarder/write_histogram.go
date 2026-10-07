package forwarder

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// Fixed buckets in seconds resolve 100us writes and cover slow/stalled writes.
// There are no identity or outcome labels; errors are observations too.
var writeDurationBounds = [...]float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type writeDurationHistogram struct {
	buckets    [len(writeDurationBounds)]uint64 // disjoint bins, accumulated on export
	count      uint64
	sumSeconds float64
}

func (h *writeDurationHistogram) observe(d time.Duration) {
	seconds := d.Seconds()
	h.count++
	h.sumSeconds += seconds
	for i, bound := range writeDurationBounds {
		if seconds <= bound {
			h.buckets[i]++
			break
		}
	}
}

// WriteDurationMetrics exports a coherent lifetime histogram snapshot. Its
// memory and response size are constant, independent of routes and backends.
func (f *Forwarder) WriteDurationMetrics(w io.Writer) error {
	var h writeDurationHistogram
	if f != nil {
		f.writeMetricsMu.Lock()
		h = f.writeHistogram
		f.writeMetricsMu.Unlock()
	}
	var out strings.Builder
	out.WriteString("# HELP nexus_forwarder_write_duration_seconds Completed client-device writes, including errors.\n# TYPE nexus_forwarder_write_duration_seconds histogram\n")
	var cumulative uint64
	for i, bound := range writeDurationBounds {
		cumulative += h.buckets[i]
		fmt.Fprintf(&out, "nexus_forwarder_write_duration_seconds_bucket{le=\"%g\"} %d\n", bound, cumulative)
	}
	fmt.Fprintf(&out, "nexus_forwarder_write_duration_seconds_bucket{le=\"+Inf\"} %d\nnexus_forwarder_write_duration_seconds_sum %g\nnexus_forwarder_write_duration_seconds_count %d\n", h.count, h.sumSeconds, h.count)
	_, err := io.WriteString(w, out.String())
	return err
}
