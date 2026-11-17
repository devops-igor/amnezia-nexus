package awg

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Controls for the release-interval oracle.
//
// The oracle previously observed a release with a single record appended after the whole
// release command. A successor that acquired between the real removal and that record was
// therefore reported as an overlap even though the removal had already happened. These
// controls pin the corrected behaviour from three directions:
//
//   - the classifier is exercised on synthetic journals, so the three acceptance classes
//     and the rejection of malformed data are decided deterministically, not by timing;
//   - a real two-participant protocol is run with the release-complete record deliberately
//     delayed, which reproduces the exact artifact that produced the false positive and
//     must still pass, while the superseded rule is shown to flag the same journal;
//   - a broken acquisition must still fail, and a cancelled oracle must join its parked
//     participant and prove that exact subprocess exited.

// issue872SyntheticEvents parses journal lines for the classifier controls.
func issue872SyntheticEvents(t *testing.T, lines ...string) []issue872JournalEvent {
	t.Helper()

	events, tail, err := issue872ParseJournal(strings.Join(lines, "\n") + "\n")
	if err != nil {
		t.Fatalf("synthetic journal did not parse: %v", err)
	}
	if tail != "" {
		t.Fatalf("synthetic journal left an unterminated fragment %q", tail)
	}
	return events
}

// TestIssue872ReleaseIntervalClassifier pins the acceptance classes and the rejection of
// journal data the verdict cannot rely on.
func TestIssue872ReleaseIntervalClassifier(t *testing.T) {
	t.Run("released predecessor is legal", func(t *testing.T) {
		events := issue872SyntheticEvents(t,
			"ACQ 1 holder-a owner=holder-a 1",
			"RELBEGIN 2 holder-a owner=holder-a 1",
			"RELDONE 3 holder-a owner=",
			"ACQ 4 holder-b owner=holder-b 4",
		)

		class, err := issue872ClassifyJournal(events)
		if err != nil {
			t.Fatalf("classification rejected a valid journal: %v", err)
		}
		if class.inFlight != 0 {
			t.Errorf("expected no in-flight acquisitions, got %d", class.inFlight)
		}
		if class.outstanding != "holder-b" {
			t.Errorf("expected holder-b to be the outstanding holder, got %q", class.outstanding)
		}
		if len(class.acquisitions) != 2 {
			t.Fatalf("expected 2 classified acquisitions, got %d", len(class.acquisitions))
		}
		if got := class.acquisitions[1].class; got != issue872AcqReleased {
			t.Errorf("successor class = %q, want %q", got, issue872AcqReleased)
		}
		if successor, predecessor, flagged := issue872LegacyOverlapRule(events); flagged {
			t.Errorf("superseded rule should not flag a released predecessor, got %q after %q", successor, predecessor)
		}
	})

	t.Run("successor inside the release interval is unresolved, not overlap", func(t *testing.T) {
		events := issue872SyntheticEvents(t,
			"ACQ 1 holder-a owner=holder-a 1",
			"RELBEGIN 2 holder-a owner=holder-a 1",
			"ACQ 3 holder-b owner=holder-b 3",
			"RELDONE 4 holder-a owner=",
		)

		class, err := issue872ClassifyJournal(events)
		if err != nil {
			t.Fatalf("classification rejected an interpretable journal: %v", err)
		}
		if class.inFlight != 1 {
			t.Errorf("expected 1 in-flight acquisition, got %d", class.inFlight)
		}
		if got := class.acquisitions[1].class; got != issue872AcqInFlight {
			t.Errorf("successor class = %q, want %q", got, issue872AcqInFlight)
		}
		for _, acq := range class.acquisitions {
			if acq.class == issue872AcqOverlap {
				t.Fatalf("an acquisition inside the release interval must not be classified as overlap")
			}
		}
		// The superseded rule reported exactly this shape as an overlap. That is the
		// false positive this correction removes, reproduced here deterministically.
		if successor, predecessor, flagged := issue872LegacyOverlapRule(events); !flagged {
			t.Errorf("superseded rule should have flagged this journal as overlap, got none")
		} else if successor != "holder-b" || predecessor != "holder-a" {
			t.Errorf("superseded rule flagged %q after %q, want holder-b after holder-a", successor, predecessor)
		}
	})

	t.Run("successor before the release begins is an overlap", func(t *testing.T) {
		events := issue872SyntheticEvents(t,
			"ACQ 1 holder-a owner=holder-a 1",
			"ACQ 2 holder-b owner=holder-b 2",
			"RELBEGIN 3 holder-a owner=holder-a 1",
			"RELDONE 4 holder-a owner=",
		)

		class, err := issue872ClassifyJournal(events)
		if err != nil {
			t.Fatalf("classification rejected an interpretable journal: %v", err)
		}
		if got := class.acquisitions[1].class; got != issue872AcqOverlap {
			t.Fatalf("successor class = %q, want %q", got, issue872AcqOverlap)
		}
		if class.acquisitions[1].previous != "holder-a" {
			t.Fatalf("overlap predecessor = %q, want holder-a", class.acquisitions[1].previous)
		}
	})

	t.Run("unusable journal data is rejected", func(t *testing.T) {
		cases := map[string]string{
			"missing owner observation":       "ACQ 1 holder-a",
			"unknown event kind":              "FROBNICATE 1 holder-a owner=holder-a",
			"empty token":                     "ACQ 1  owner=holder-a",
			"acquired without owning record":  "ACQ 1 holder-a owner=holder-b",
			"release without acquisition":     "RELBEGIN 1 holder-a owner=holder-a",
			"release-complete without begin":  "ACQ 1 holder-a owner=holder-a\nRELDONE 2 holder-a owner=",
			"double acquisition by one token": "ACQ 1 holder-a owner=holder-a\nACQ 2 holder-a owner=holder-a",
		}
		for name, line := range cases {
			t.Run(name, func(t *testing.T) {
				events, _, err := issue872ParseJournal(line + "\n")
				if err != nil {
					return // rejected at parse time, which is also a rejection
				}
				if _, classErr := issue872ClassifyJournal(events); classErr == nil {
					t.Fatalf("classifier accepted unusable journal %q", line)
				}
			})
		}

		t.Run("truncated tail is reported", func(t *testing.T) {
			_, tail, err := issue872ParseJournal("ACQ 1 holder-a owner=holder-a\nACQ 2 holder")
			if err != nil {
				t.Fatalf("a trailing fragment should be separable from parsed lines: %v", err)
			}
			if tail != "ACQ 2 holder" {
				t.Fatalf("tail = %q, want the unterminated fragment", tail)
			}
		})

		t.Run("empty interior line is rejected", func(t *testing.T) {
			if _, _, err := issue872ParseJournal("ACQ 1 holder-a owner=holder-a\n\nACQ 2 holder-b owner=holder-b\n"); err == nil {
				t.Fatal("parser accepted an empty interior journal line")
			}
		})
	})
}

// TestIssue872PostReleaseLagIsNotOverlap runs the real protocol with the release-complete
// record deliberately delayed past the real removal. A successor then acquires inside the
// gap. The corrected oracle must accept that journal, the artifact must be shown to have
// actually occurred, and the superseded single-marker rule must be shown to misreport it.
func TestIssue872PostReleaseLagIsNotOverlap(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	resName := fmt.Sprintf("release_lag_%d", time.Now().UnixNano())
	o := newIssue872Oracle(t, resName)
	o.releaseDoneDelay = 250 * time.Millisecond

	const holderToken = "lag-holder"
	const successorToken = "lag-successor"
	o.addParticipant(t, holderToken, false)
	o.addParticipant(t, successorToken, false)
	o.finalize(t)

	// The holder is started alone, so it is the first acquirer by construction.
	o.start(t, 0)
	o.awaitHolderParked(0)
	assertLockOwnerEquals(t, o.lockPath, holderToken, "lag control initial holder")

	// The successor joins and is proven to be retrying against the held lock.
	o.start(t, 1)
	o.await("the successor to retry against the held lock", func() bool {
		o.assertNoConcurrentAcquisition(0, holderToken)
		return o.countByKind(issue872EventLockTry)[successorToken] >= issue872RequiredAttempts
	})

	// Release with the forced logging lag. The real removal happens immediately; only its
	// completion record is delayed. This is the same handshake the oracle's rounds use.
	o.releaseHolder(0)

	// The successor acquires during the lag.
	o.awaitHolderParked(1)
	assertLockOwnerEquals(t, o.lockPath, successorToken, "successor acquired after the real removal")
	o.releaseHolder(1)

	// The corrected oracle accepts the journal.
	o.assertReleaseOrdering(t)
	o.assertEventTotals(t, 2)
	o.assertNoParticipantError()

	events := o.events()
	beginIdx, doneIdx, acqIdx := -1, -1, -1
	for i, ev := range events {
		switch {
		case ev.kind == issue872EventReleaseBegin && ev.token == holderToken:
			beginIdx = i
		case ev.kind == issue872EventReleaseDone && ev.token == holderToken:
			doneIdx = i
		case ev.kind == issue872EventAcquire && ev.token == successorToken:
			acqIdx = i
		}
	}
	if beginIdx < 0 || doneIdx < 0 || acqIdx < 0 {
		t.Fatalf("expected release-begin, release-complete and successor acquisition in the journal\n%s", o.diagnostics())
	}
	if !(beginIdx < acqIdx && acqIdx < doneIdx) {
		t.Fatalf("the forced lag did not place the successor acquisition inside the release interval (begin=%d acq=%d done=%d)\n%s",
			beginIdx, acqIdx, doneIdx, o.diagnostics())
	}

	successor, predecessor, flagged := issue872LegacyOverlapRule(events)
	if !flagged {
		t.Fatalf("the superseded single-marker rule did not reproduce the false positive for this journal\n%s", o.diagnostics())
	}
	t.Logf("forced post-release lag: the superseded rule reported overlap %q after %q for the same journal that the interval rule classifies as release-in-flight/legal; the real removal had already happened", successor, predecessor)

	if _, err := os.Stat(o.lockPath); !os.IsNotExist(err) {
		t.Fatalf("lock directory still exists after the last release: %v", err)
	}
}

// TestIssue872CancellationJoinsParkedParticipant proves the failure path: a participant
// parked mid-protocol by its own shell is reached by cancellation, its goroutine joins,
// and that exact subprocess is shown to be gone by identity rather than assumed to exit
// eventually on its own.
func TestIssue872CancellationJoinsParkedParticipant(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	resName := fmt.Sprintf("cancel_join_%d", time.Now().UnixNano())
	o := newIssue872Oracle(t, resName)

	const holderToken = "cancel-holder"
	o.addParticipant(t, holderToken, false)
	o.finalize(t)

	o.start(t, 0)
	o.awaitHolderParked(0)

	// The participant is parked by its own acquire shell and still owns the lock, which is
	// the worst state to abandon.
	if _, err := os.Stat(o.participants[0].parkPath); err != nil {
		t.Fatalf("participant was not parked when cancellation started: %v", err)
	}
	assertLockOwnerEquals(t, o.lockPath, holderToken, "parked participant holding the lock at cancellation")
	pid := o.pids[0].Load()
	if pid <= 0 {
		t.Fatalf("participant subprocess id was not recorded")
	}

	if err := o.joinParticipants(); err != nil {
		t.Fatalf("join after cancellation failed: %v", err)
	}
	if live := o.live.Load(); live != 0 {
		t.Fatalf("%d participant goroutine(s) still registered after join", live)
	}
	if err := o.assertNoLeftoverProcesses(); err != nil {
		t.Fatalf("subprocess identity check failed after join: %v", err)
	}
	if _, err := os.Stat("/proc"); err == nil {
		if _, statErr := os.Stat(fmt.Sprintf("/proc/%d", pid)); statErr == nil {
			t.Fatalf("parked participant subprocess %d still exists after join", pid)
		}
	}

	t.Logf("cancelled while %q was parked holding the lock: its goroutine joined and subprocess %d is gone", holderToken, pid)
}
