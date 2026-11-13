package tunnel

import "testing"

// TestAttemptOutcome_CombinationTable pins the whole reduction table, so the
// headline outcome a surface shows cannot drift from the two recorded halves.
//
// The cases are exhaustive over the closed outcome vocabulary. The rule the table
// encodes is the one the issue requires: an attempt counts as successful only when
// its affirmative observation was actually taken and nothing contradicted it, and
// "not established" is never reported as either extreme.
func TestAttemptOutcome_CombinationTable(t *testing.T) {
	cases := []struct {
		outer, inner, want AttemptOutcome
	}{
		{OutcomeSuccess, OutcomeSuccess, OutcomeSuccess},
		{OutcomeSuccess, OutcomeNotRun, OutcomeSuccess},
		{OutcomeSuccess, OutcomeFailure, OutcomeFailure},
		{OutcomeSuccess, OutcomeUnknown, OutcomeUnknown},
		{OutcomeFailure, OutcomeSuccess, OutcomeFailure},
		{OutcomeFailure, OutcomeFailure, OutcomeFailure},
		{OutcomeFailure, OutcomeNotRun, OutcomeFailure},
		{OutcomeFailure, OutcomeUnknown, OutcomeFailure},
		{OutcomeNotRun, OutcomeSuccess, OutcomeNotRun},
		{OutcomeNotRun, OutcomeFailure, OutcomeFailure},
		{OutcomeNotRun, OutcomeNotRun, OutcomeNotRun},
		{OutcomeNotRun, OutcomeUnknown, OutcomeNotRun},
		{OutcomeUnknown, OutcomeSuccess, OutcomeUnknown},
		{OutcomeUnknown, OutcomeFailure, OutcomeFailure},
		{OutcomeUnknown, OutcomeNotRun, OutcomeUnknown},
		{OutcomeUnknown, OutcomeUnknown, OutcomeUnknown},
	}
	for _, c := range cases {
		if got := attemptOutcome(c.outer, c.inner); got != c.want {
			t.Errorf("attemptOutcome(%q, %q) = %q, want %q", c.outer, c.inner, got, c.want)
		}
	}
}
