//go:build linux

package vpn

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestClassifyPrerequisiteOutcome pins every environment the capture probe can run
// in, including the read-only-/proc/sys container that broke current-SHA CI
// (run 42137087122). These cases are the executable form of that failure: the
// container path must PASS on a sysctl-caused prerequisite failure, must still
// FAIL when the capture capability is the missing piece, and the writable path
// keeps the strict original contract.
func TestClassifyPrerequisiteOutcome(t *testing.T) {
	sysctlErr := fmt.Errorf("%w: read-only file system", ErrStrictRPFilter)

	tests := []struct {
		name           string
		sysctlWritable bool
		prereqErr      error
		wantPass       bool
		wantMessage    string
	}{
		{
			name:           "writable proc, all prerequisites satisfied",
			sysctlWritable: true,
			prereqErr:      nil,
			wantPass:       true,
			wantMessage:    "sysctl writable=true",
		},
		{
			name:           "writable proc, prerequisite failed is a real failure",
			sysctlWritable: true,
			prereqErr:      ErrStrictRPFilter,
			wantPass:       false,
			wantMessage:    "RESULT: FAIL",
		},
		{
			name:           "read-only proc, sysctl prerequisite failed still proves capture",
			sysctlWritable: false,
			prereqErr:      sysctlErr,
			wantPass:       true,
			wantMessage:    "not a capture-capability failure",
		},
		{
			name:           "read-only proc, prerequisites already satisfied",
			sysctlWritable: false,
			prereqErr:      nil,
			wantPass:       true,
			wantMessage:    "prerequisites already satisfied",
		},
		{
			name:           "read-only proc, capture capability reported missing is a failure",
			sysctlWritable: false,
			prereqErr:      ErrWANCaptureDenied,
			wantPass:       false,
			wantMessage:    "RESULT: FAIL",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyPrerequisiteOutcome(tc.sysctlWritable, tc.prereqErr)
			if got.pass != tc.wantPass {
				t.Fatalf("pass = %v, want %v (message: %s)", got.pass, tc.wantPass, got.message)
			}
			if !strings.Contains(got.message, tc.wantMessage) {
				t.Fatalf("message %q does not contain %q", got.message, tc.wantMessage)
			}
			// The CI harness greps for a leading RESULT: token; every branch must
			// emit exactly one so a run can never be ambiguous.
			if !strings.HasPrefix(got.message, "RESULT: ") {
				t.Fatalf("message must start with RESULT: , got %q", got.message)
			}
			if tc.wantPass != strings.HasPrefix(got.message, "RESULT: PASS") {
				t.Fatalf("PASS/FAIL token disagrees with pass=%v: %q", got.pass, got.message)
			}
		})
	}
}

// TestClassifyPrerequisiteOutcome_ReadOnlyProcNeverMasksCaptureDenial is the
// regression guard for the CI defect: a read-only /proc/sys must not turn a
// genuine missing-CAP_NET_RAW into a pass, and must not turn a sysctl-only
// failure into a hard failure.
func TestClassifyPrerequisiteOutcome_ReadOnlyProcNeverMasksCaptureDenial(t *testing.T) {
	readOnlyFailures := []error{
		fmt.Errorf("%w: read-only file system", ErrStrictRPFilter),
		fmt.Errorf("%w: read-only file system", ErrIPForwardingDisabled),
		ErrNoDefaultWANRoute,
		errors.New("iptables not found: no such file"),
	}
	for _, err := range readOnlyFailures {
		got := classifyPrerequisiteOutcome(false, err)
		if !got.pass {
			t.Fatalf("read-only environment should still prove capture for %v, got failure: %s", err, got.message)
		}
		if errors.Is(err, ErrWANCaptureDenied) {
			t.Fatal("test table error: capture denial must not be in the tolerated set")
		}
	}

	wrapped := fmt.Errorf("wan prerequisites: %w", ErrWANCaptureDenied)
	if got := classifyPrerequisiteOutcome(false, wrapped); got.pass {
		t.Fatalf("wrapped ErrWANCaptureDenied must fail even with read-only proc: %s", got.message)
	}
}

// TestApplyProbeSysctls_ReportsEffectiveState proves the writability probe reports
// the actual post-write state rather than the mere absence of a write error, so a
// silently ignored write cannot be mistaken for a configured kernel.
func TestApplyProbeSysctls_ReportsEffectiveState(t *testing.T) {
	settings := []struct{ path, want string }{
		{"/proc/sys/net/ipv4/ip_forward", "1"},
		{"/proc/sys/net/ipv4/conf/all/rp_filter", "2"},
		{"/proc/sys/net/ipv4/conf/all/accept_local", "1"},
	}

	got := applyProbeSysctls()

	// Whatever it reported, the reported value must match what procfs actually
	// holds: a "writable" claim is only credible if every setting reads back.
	for _, setting := range settings {
		// #nosec G304 -- fixed procfs setting paths
		data, err := os.ReadFile(setting.path)
		if err != nil {
			t.Fatalf("read %s: %v", setting.path, err)
		}
		matches := strings.TrimSpace(string(data)) == setting.want
		if got && !matches {
			t.Fatalf("applyProbeSysctls reported writable but %s reads %q, want %q",
				setting.path, strings.TrimSpace(string(data)), setting.want)
		}
	}
	t.Logf("applyProbeSysctls reported writable=%v for this environment", got)
}
