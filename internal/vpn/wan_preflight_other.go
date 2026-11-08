//go:build !linux

package vpn

import (
	"errors"
	"fmt"
	"io"
	"text/tabwriter"
)

// StandaloneResult describes the outcome of one production-path capability probe.
type StandaloneResult struct {
	Name    string
	Err     error
	Skipped bool
}

// OK reports whether the probe completed without error.
func (r StandaloneResult) OK() bool { return r.Err == nil }

// Label renders the probe status for operator output.
func (r StandaloneResult) Label() string {
	switch {
	case r.Skipped:
		return "SKIP"
	case r.Err != nil:
		return "FAIL"
	default:
		return "OK"
	}
}

// RunStandaloneWANChecks reports that direct WAN egress capability checks only apply
// to Linux, matching NewProductionWANDevice's platform support.
func RunStandaloneWANChecks(w io.Writer) []StandaloneResult {
	results := []StandaloneResult{{
		Name: "direct WAN egress capability checks (Linux only)",
		Err:  errors.New("vpn: direct WAN egress is only supported on Linux"),
	}}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, r := range results {
		fmt.Fprintf(tw, "%s	%s\n", r.Label(), r.Name)
	}
	_ = tw.Flush()
	return results
}

// EffectiveCapabilityNames is unavailable off Linux.
func EffectiveCapabilityNames() []string { return nil }
