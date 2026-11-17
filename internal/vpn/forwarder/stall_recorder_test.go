package forwarder

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// phaseRecorder records enqueue, start and completion instants for a bounded window of
// events, addressed by ABSOLUTE sequence number (issue #861).
//
// The first version of this recorder was an array indexed by a ring slot, and it silently
// lost phase information once more events had been recorded than the window held: an event
// whose start had certainly happened reported "not_reached" because its slot had been
// reused. Identity is the thing being reported, so it is tracked by sequence number and the
// phases are resolved against absolute counts rather than against a reused slot.
//
// Bounded: the window holds at most `window` events; older events are dropped, but the
// aggregate counts keep telling the reader how far each phase got.
type phaseRecorder struct {
	mu     sync.Mutex
	window int
	events []phaseEvent
	// Absolute counts: how many events have reached each phase. Because one pump enqueues,
	// starts and completes in order, event seq s has started iff s < started, and completed
	// iff s < written.
	enqueued int
	started  int
	written  int
}

type phaseEvent struct {
	seq      int
	enqueued time.Time
	started  time.Time
	written  time.Time
}

func newPhaseRecorder(window int) *phaseRecorder {
	if window <= 0 {
		window = 64
	}
	return &phaseRecorder{window: window, events: make([]phaseEvent, 0, window)}
}

// Enqueue records one enqueue and returns its absolute sequence number.
func (r *phaseRecorder) Enqueue(at time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	seq := r.enqueued
	r.enqueued++
	r.events = append(r.events, phaseEvent{seq: seq, enqueued: at})
	if len(r.events) > r.window {
		// Drop only the oldest, so the retained window is always the most recent history.
		r.events = r.events[len(r.events)-r.window:]
	}
	return seq
}

// Started records that the next event in start order entered the write phase, and reports
// the sequence number it was attributed to.
func (r *phaseRecorder) Started(at time.Time) (int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started >= r.enqueued {
		return 0, false
	}
	seq := r.started
	r.started++
	if i := r.indexLocked(seq); i >= 0 {
		r.events[i].started = at
	}
	return seq, true
}

// Written records that the next event in completion order finished its write, and reports
// the sequence number it was attributed to.
func (r *phaseRecorder) Written(at time.Time) (int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.written >= r.enqueued {
		return 0, false
	}
	seq := r.written
	r.written++
	if i := r.indexLocked(seq); i >= 0 {
		r.events[i].written = at
	}
	return seq, true
}

// Counts reports the absolute phase counts.
func (r *phaseRecorder) Counts() (enqueued, started, written int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.enqueued, r.started, r.written
}

// indexLocked finds a retained event by absolute sequence, or -1 when it left the window.
func (r *phaseRecorder) indexLocked(seq int) int {
	if len(r.events) == 0 {
		return -1
	}
	first := r.events[0].seq
	if seq < first || seq >= first+len(r.events) {
		return -1
	}
	return seq - first
}

// Report renders the retained window plus the absolute counts. A phase is reported as
// "not_reached" only when the absolute counts prove it never happened; an event that left
// the window is reported as such rather than as a missing phase.
func (r *phaseRecorder) Report(stalledSeq int) string {
	r.mu.Lock()
	defer r.mu.Unlock()

	var b strings.Builder
	fmt.Fprintf(&b, "enqueued=%d started=%d written=%d window=", r.enqueued, r.started, r.written)
	if len(r.events) == 0 {
		b.WriteString("empty")
		return b.String()
	}
	fmt.Fprintf(&b, "%d..%d", r.events[0].seq, r.events[len(r.events)-1].seq)

	if i := r.indexLocked(stalledSeq); i >= 0 {
		fmt.Fprintf(&b, " stalled=%s", r.renderLocked(r.events[i], r.events[0].enqueued))
	} else if stalledSeq >= 0 {
		fmt.Fprintf(&b, " stalled=seq%d_outside_window", stalledSeq)
	}
	for _, ev := range r.events {
		fmt.Fprintf(&b, " | %s", r.renderLocked(ev, r.events[0].enqueued))
	}
	return b.String()
}

func (r *phaseRecorder) renderLocked(ev phaseEvent, origin time.Time) string {
	started := "not_reached"
	if ev.seq < r.started {
		// The start happened; it is only absent when the event predates the window, which
		// cannot be the case for a retained event.
		started = phaseGap(origin, ev.started)
	}
	written := "not_reached"
	if ev.seq < r.written {
		written = phaseGap(origin, ev.written)
	}
	return fmt.Sprintf("seq=%d enqueued=+%s started=%s written=%s",
		ev.seq, ev.enqueued.Sub(origin).Round(time.Microsecond), started, written)
}

// phaseGap renders a phase instant relative to the window origin.
func phaseGap(origin, at time.Time) string {
	if at.IsZero() {
		return "evicted"
	}
	return "+" + at.Sub(origin).Round(time.Microsecond).String()
}

// Tests for the recorder itself: identity and phase must survive more events than the window
// holds, and a delayed consumer must not be attributed to the wrong event.

func TestPhaseRecorderKeepsIdentityPastTheWindow(t *testing.T) {
	rec := newPhaseRecorder(64)
	origin := time.Unix(1_700_000_000, 0)

	const total = 160
	for i := range total {
		seq := rec.Enqueue(origin.Add(time.Duration(i) * time.Microsecond))
		if seq != i {
			t.Fatalf("enqueue %d got seq %d", i, seq)
		}
	}
	for i := range total {
		seq, ok := rec.Started(origin.Add(time.Duration(i) * time.Microsecond))
		if !ok || seq != i {
			t.Fatalf("start %d attributed to %d/%v", i, seq, ok)
		}
	}
	for i := range total {
		seq, ok := rec.Written(origin.Add(time.Duration(i) * time.Microsecond))
		if !ok || seq != i {
			t.Fatalf("write %d attributed to %d/%v", i, seq, ok)
		}
	}

	enqueued, started, written := rec.Counts()
	if enqueued != total || started != total || written != total {
		t.Fatalf("counts = %d/%d/%d, want %d each", enqueued, started, written, total)
	}

	report := rec.Report(total - 1)
	// The window holds the last 64 events, and every one of them has both phases.
	if !strings.Contains(report, "window=96..159") {
		t.Errorf("window = %s, want the most recent 96..159", report)
	}
	if strings.Contains(report, "not_reached") {
		t.Errorf("a completed event reported a missing phase: %s", report)
	}
	if strings.Contains(report, "seq159 started=evicted") {
		t.Errorf("a retained event's start was reported as evicted: %s", report)
	}
	// The stalled sequence is the last one, and it is rendered with its own phases.
	if !strings.Contains(report, "stalled=seq=159") {
		t.Errorf("stall attribution missing: %s", report)
	}
}

func TestPhaseRecorderReportsNeverReachedDistinctly(t *testing.T) {
	rec := newPhaseRecorder(8)
	origin := time.Unix(1_700_000_000, 0)
	for i := range 4 {
		rec.Enqueue(origin.Add(time.Duration(i) * time.Microsecond))
	}
	// Only two events ever start; none completes.
	for i := range 2 {
		if seq, ok := rec.Started(origin.Add(time.Duration(i) * time.Microsecond)); !ok || seq != i {
			t.Fatalf("start %d attributed to %d/%v", i, seq, ok)
		}
	}
	report := rec.Report(2)
	if !strings.Contains(report, "seq=0 enqueued=+0s started=+0s written=not_reached") {
		t.Errorf("event 0 phases wrong: %s", report)
	}
	if !strings.Contains(report, "seq=2 enqueued=+2µs started=not_reached") {
		t.Errorf("event 2 must report its start as never reached: %s", report)
	}
	if !strings.Contains(report, "stalled=seq=2") {
		t.Errorf("the stalled sequence is not named: %s", report)
	}
}

func TestPhaseRecorderSurvivesDelayedConsumption(t *testing.T) {
	rec := newPhaseRecorder(8)
	origin := time.Unix(1_700_000_000, 0)
	for i := range 20 {
		rec.Enqueue(origin.Add(time.Duration(i) * time.Microsecond))
	}
	// A delayed consumer: the first start arrives only after 20 events are enqueued, and the
	// completions trail the starts by a fixed lag.
	for i := range 5 {
		if seq, ok := rec.Started(origin.Add(time.Duration(20+i) * time.Microsecond)); !ok || seq != i {
			t.Fatalf("delayed start %d attributed to %d/%v", i, seq, ok)
		}
	}
	for i := range 2 {
		if seq, ok := rec.Written(origin.Add(time.Duration(40+i) * time.Microsecond)); !ok || seq != i {
			t.Fatalf("delayed write %d attributed to %d/%v", i, seq, ok)
		}
	}
	enqueued, started, written := rec.Counts()
	if enqueued != 20 || started != 5 || written != 2 {
		t.Fatalf("counts = %d/%d/%d, want 20/5/2", enqueued, started, written)
	}
	// The window holds 12..19: those events have neither phase, so the report must say
	// not_reached for them, and the counts must show the phases that were consumed late.
	report := rec.Report(12)
	if !strings.Contains(report, "window=12..19") {
		t.Errorf("window = %s, want 12..19", report)
	}
	if !strings.Contains(report, "stalled=seq=12") {
		t.Errorf("stall attribution lost under delayed consumption: %s", report)
	}
	if !strings.Contains(report, "enqueued=20 started=5 written=2") {
		t.Errorf("counts do not reflect delayed consumption: %s", report)
	}
}
