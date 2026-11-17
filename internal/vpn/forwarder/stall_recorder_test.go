package forwarder

import (
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// phaseRecorder records, per absolute sequence number, when an event was admitted and when
// the fixture device actually entered Write, received its permit and returned (issue #861).
//
// The device is the producer of the write phases and records them synchronously inside its
// Write call, before it sends any acknowledgement. Acknowledgements a test drains later are
// counted separately as observations and are never evidence that a phase happened: an
// observer that is slow to drain must not turn a completed write into one that never started.
//
// Identity: admissions are numbered in order, and the device takes the next number when it
// enters Write. That relies on the fixture's single serialized producer and on one pump
// draining one FIFO queue. The device carries the number it took through its permit and its
// completion, and the recorder refuses to attribute a phase to any other number.
//
// Bounds: a ring of `window` events, where a slot is used only for the seq it actually holds,
// plus the oldest unwritten event, kept if it leaves the ring while still pending so a stall
// report names it with its own instants. Nothing else grows.
type phaseRecorder struct {
	mu       sync.Mutex
	changed  chan struct{}
	ring     []phaseEvent
	head     phaseEvent
	headKept bool
	// producer is set once a device that records phases is attached. Without one, a zero
	// phase count is no evidence that the phase did not happen, and is reported as unknown.
	producer bool
	counts   phaseCounts
}

type phaseEvent struct {
	seq       int
	valid     bool
	enqueued  time.Time
	started   time.Time
	permitted time.Time
	written   time.Time
}

// phaseCounts are absolute: event seq s reached a producer phase iff s < that phase's count.
type phaseCounts struct {
	Enqueued        int
	Started         int
	Permitted       int
	Written         int
	ObservedStarted int
	ObservedWritten int
	// Unattributed counts producer phases that could not be tied to an admitted event in the
	// right order, for example a Write that began before any admission was recorded. They are
	// counted, never dropped silently and never credited to a neighbour.
	Unattributed int
}

func newPhaseRecorder(window int) *phaseRecorder {
	if window <= 0 {
		window = 64
	}
	return &phaseRecorder{changed: make(chan struct{}, 1), ring: make([]phaseEvent, window)}
}

// AttachProducer declares that a device records phases into this recorder.
func (r *phaseRecorder) AttachProducer() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.producer = true
}

// signalLocked wakes a waitFor; one pending wake-up is enough, so the send never blocks.
func (r *phaseRecorder) signalLocked() {
	select {
	case r.changed <- struct{}{}:
	default:
	}
}

// eventLocked returns the stored event for seq, or nil when it is no longer retained. A ring
// slot is used only when it holds exactly this seq: a reused slot belongs to another event.
func (r *phaseRecorder) eventLocked(seq int) *phaseEvent {
	if seq < 0 {
		return nil
	}
	if slot := &r.ring[seq%len(r.ring)]; slot.valid && slot.seq == seq {
		return slot
	}
	if r.headKept && r.head.seq == seq {
		return &r.head
	}
	return nil
}

// Enqueue records one admission and returns its absolute sequence number. The fixture calls
// it before handing the packet to the forwarder, so the device cannot start an event whose
// admission has not been recorded.
func (r *phaseRecorder) Enqueue(at time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	seq := r.counts.Enqueued
	slot := &r.ring[seq%len(r.ring)]
	if slot.valid && slot.seq == r.counts.Written {
		// The oldest unwritten event is leaving the ring: keep it, it is the one a stall
		// report must name.
		r.head, r.headKept = *slot, true
	}
	*slot = phaseEvent{seq: seq, valid: true, enqueued: at}
	r.counts.Enqueued++
	r.signalLocked()
	return seq
}

// Started is called by the device on entry to Write. It returns the seq the write belongs
// to, or -1 when no admitted event is waiting for it.
func (r *phaseRecorder) Started(at time.Time) int {
	if r == nil {
		return -1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	defer r.signalLocked()
	if r.counts.Started >= r.counts.Enqueued {
		r.counts.Unattributed++
		return -1
	}
	seq := r.counts.Started
	r.counts.Started++
	if ev := r.eventLocked(seq); ev != nil {
		ev.started = at
	}
	return seq
}

// Permitted is called by the device once its write for seq has been released.
func (r *phaseRecorder) Permitted(seq int, at time.Time) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	defer r.signalLocked()
	if seq != r.counts.Permitted || seq >= r.counts.Started {
		r.counts.Unattributed++
		return
	}
	r.counts.Permitted++
	if ev := r.eventLocked(seq); ev != nil {
		ev.permitted = at
	}
}

// Written is called by the device when its write for seq returns, before it acknowledges.
func (r *phaseRecorder) Written(seq int, at time.Time) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	defer r.signalLocked()
	if seq != r.counts.Written || seq >= r.counts.Permitted {
		r.counts.Unattributed++
		return
	}
	r.counts.Written++
	if ev := r.eventLocked(seq); ev != nil {
		ev.written = at
	}
	if r.headKept && r.head.seq == seq {
		r.headKept = false
	}
}

// ObserveStarted and ObserveWritten count acknowledgements a test drained. They are
// observations of the device, not evidence of its phases.
func (r *phaseRecorder) ObserveStarted() { r.observe(&r.counts.ObservedStarted) }
func (r *phaseRecorder) ObserveWritten() { r.observe(&r.counts.ObservedWritten) }

func (r *phaseRecorder) observe(counter *int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	*counter++
}

// Counts reports the absolute counts.
func (r *phaseRecorder) Counts() phaseCounts {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counts
}

// HeadOfLine is the oldest admitted event the device has not finished writing.
func (r *phaseRecorder) HeadOfLine() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counts.Written
}

// Event returns a copy of the retained event for seq.
func (r *phaseRecorder) Event(seq int) (phaseEvent, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ev := r.eventLocked(seq); ev != nil {
		return *ev, true
	}
	return phaseEvent{}, false
}

// waitFor blocks until done accepts the producer counts, bounded by the fixture's 3s wait.
func (r *phaseRecorder) waitFor(t *testing.T, what string, done func(phaseCounts) bool) {
	t.Helper()
	timeout := time.NewTimer(3 * time.Second)
	defer timeout.Stop()
	for !done(r.Counts()) {
		select {
		case <-r.changed:
		case <-timeout.C:
			t.Fatalf("device never reached %s (%s)", what, r.Report(r.HeadOfLine()))
		}
	}
}

// Report renders the counts, the stalled event and the retained window. A phase reads
// not_reached only when an attached producer's count shows it has not happened, unknown when
// no producer records phases, and reached_time_evicted when the count shows it happened but
// its instant is no longer retained.
func (r *phaseRecorder) Report(stalledSeq int) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.counts
	producer := "absent"
	if r.producer {
		producer = "attached"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "producer=%s enqueued=%d started=%d permitted=%d written=%d "+
		"observed_started=%d observed_written=%d unattributed=%d window=",
		producer, c.Enqueued, c.Started, c.Permitted, c.Written,
		c.ObservedStarted, c.ObservedWritten, c.Unattributed)
	if c.Enqueued == 0 {
		b.WriteString("empty")
		return b.String()
	}
	first := max(0, c.Enqueued-len(r.ring))
	fmt.Fprintf(&b, "%d..%d", first, c.Enqueued-1)
	origin := r.ring[first%len(r.ring)].enqueued
	if r.headKept {
		origin = r.head.enqueued
	}
	if stalledSeq >= 0 && stalledSeq < c.Enqueued {
		fmt.Fprintf(&b, " stalled=%s", r.renderLocked(stalledSeq, origin))
	}
	for seq := first; seq < c.Enqueued; seq++ {
		fmt.Fprintf(&b, " | %s", r.renderLocked(seq, origin))
	}
	return b.String()
}

func (r *phaseRecorder) renderLocked(seq int, origin time.Time) string {
	ev := r.eventLocked(seq)
	if ev == nil {
		ev = &phaseEvent{seq: seq}
	}
	enqueued := "reached_time_evicted"
	if !ev.enqueued.IsZero() {
		enqueued = phaseOffset(origin, ev.enqueued)
	}
	return fmt.Sprintf("seq=%d enqueued=%s started=%s permitted=%s written=%s", seq, enqueued,
		r.phaseLocked(seq, r.counts.Started, ev.started, origin),
		r.phaseLocked(seq, r.counts.Permitted, ev.permitted, origin),
		r.phaseLocked(seq, r.counts.Written, ev.written, origin))
}

func (r *phaseRecorder) phaseLocked(seq, count int, at, origin time.Time) string {
	switch {
	case !r.producer:
		return "unknown"
	case seq >= count:
		return "not_reached"
	case at.IsZero():
		return "reached_time_evicted"
	default:
		return phaseOffset(origin, at)
	}
}

// phaseOffset renders an instant relative to the oldest retained admission, which precedes
// every retained phase.
func phaseOffset(origin, at time.Time) string {
	return "+" + at.Sub(origin).Round(time.Microsecond).String()
}

// phaseSignal is the device's acknowledgement of a phase it has already recorded, carrying
// the instant it acted. Tests may wait on it; the recorder never learns a phase from it.
type phaseSignal struct {
	at time.Time
}

// pacedQueueDevice is a client device whose writes wait for a permit. It records each write
// phase into rec at the moment it happens, then acknowledges it on the buffered channels.
type pacedQueueDevice struct {
	permits chan struct{}
	started chan phaseSignal
	written chan phaseSignal
	// published wakes a wait that a buffered acknowledgement changed. It carries no phase:
	// a recorder count shows the producer's own record, not that the acknowledgement that
	// follows it has been sent.
	published chan struct{}
	rec       *phaseRecorder // nil: phases are acknowledged but not recorded
}

func newPacedQueueDevice(buffer int, rec *phaseRecorder) *pacedQueueDevice {
	rec.AttachProducer()
	return &pacedQueueDevice{
		permits:   make(chan struct{}, buffer),
		started:   make(chan phaseSignal, buffer),
		written:   make(chan phaseSignal, buffer),
		published: make(chan struct{}, 1),
		rec:       rec,
	}
}

func (d *pacedQueueDevice) Read([]byte) (int, error) { return 0, nil }
func (d *pacedQueueDevice) Close() error             { return nil }
func (d *pacedQueueDevice) Write(packet []byte) (int, error) {
	at := time.Now()
	seq := d.rec.Started(at)
	d.started <- phaseSignal{at: at}
	<-d.permits
	d.rec.Permitted(seq, time.Now())
	time.Sleep(100 * time.Microsecond)
	at = time.Now()
	d.rec.Written(seq, at)
	d.written <- phaseSignal{at: at}
	d.signalPublished()
	return len(packet), nil
}

// signalPublished wakes a wait for a buffered acknowledgement. One pending wake-up is enough,
// so the send never blocks and a test that is not waiting cannot stall the producer.
func (d *pacedQueueDevice) signalPublished() {
	select {
	case d.published <- struct{}{}:
	default:
	}
}

// waitAcknowledged blocks until the producer's own record shows n completed writes and the
// device has buffered the acknowledgement of each. Those are two publications, in this order:
// Written is complete under the recorder's mutex before the acknowledgement is sent, so a wait
// on the count alone can return while the acknowledgement is still unsent. Both facts share
// the fixture's existing 3s budget, so one deadline covers the whole wait and an
// acknowledgement that never arrives fails inside it rather than adding a second budget.
// Only channel lengths are read, so no acknowledgement is consumed before the assertions that
// count them, and none of them is evidence that a phase happened.
func (d *pacedQueueDevice) waitAcknowledged(t *testing.T, n int) {
	t.Helper()
	timeout := time.NewTimer(3 * time.Second)
	defer timeout.Stop()
	for {
		started, written := len(d.started), len(d.written)
		if d.rec.Counts().Written >= n && started >= n && written >= n {
			return
		}
		select {
		case <-d.rec.changed:
		case <-d.published:
		case <-timeout.C:
			t.Fatalf("device never published %d completed writes with their acknowledgements: "+
				"started=%d written=%d buffered (%s)",
				n, started, written, d.rec.Report(d.rec.HeadOfLine()))
		}
	}
}

// recorderFixture is the real forwarder path the recorder is used on: one route, one client
// pump, the paced device behind the route's return path.
type recorderFixture struct {
	t      *testing.T
	f      *Forwarder
	dev    *pacedQueueDevice
	rec    *phaseRecorder
	packet []byte
}

func newRecorderFixture(t *testing.T, capacity, window int) *recorderFixture {
	t.Helper()
	rec := newPhaseRecorder(window)
	dev := newPacedQueueDevice(capacity+1, rec)
	f := NewForwarder(nil, "10.100.0.0/16", capacity)
	path := NewReturnPath(func(_, _ string, p []byte) (int, error) { return dev.Write(p) })
	f.RegisterSessionWithReturnPath("session", "connection", "peer", "10.100.0.10", 1, path)
	f.StartPumps(t.Context())
	packet := returnPacket("10.100.0.10")
	packet = append(packet, make([]byte, 1420-len(packet))...)
	binary.BigEndian.PutUint16(packet[2:4], 1420)
	t.Cleanup(func() {
		// Release every held write and drain every acknowledgement, then join the pump.
		stop := make(chan struct{})
		drained := make(chan struct{})
		go func() {
			defer close(drained)
			for {
				select {
				case <-dev.started:
				case <-dev.written:
				case <-stop:
					return
				}
			}
		}()
		close(dev.permits)
		f.StopPumps()
		close(stop)
		<-drained
	})
	return &recorderFixture{t: t, f: f, dev: dev, rec: rec, packet: packet}
}

func (x *recorderFixture) enqueue(n int) {
	x.t.Helper()
	for range n {
		seq := x.rec.Enqueue(time.Now())
		if err := x.f.RouteBackendToClient(1, x.packet, "10.100.0.10"); err != nil {
			x.t.Fatalf("admission of seq %d refused: %v", seq, err)
		}
	}
}

func (x *recorderFixture) permit(n int) {
	for range n {
		x.dev.permits <- struct{}{}
	}
}

// observe is the delayed observer: it drains acknowledgements only after the producer has
// already recorded the phases they acknowledge.
func (x *recorderFixture) observe(starts, writes int) {
	for range starts {
		<-x.dev.started
		x.rec.ObserveStarted()
	}
	for range writes {
		<-x.dev.written
		x.rec.ObserveWritten()
	}
}

// Recorder tests on the real device and forwarder. No acknowledgement is drained before an
// assertion about a phase: the device's own record is the only source.

func TestPhaseRecorderDeviceWithoutRecorderReportsUnknown(t *testing.T) {
	rec := newPhaseRecorder(64)
	rec.Enqueue(time.Now())
	dev := &pacedQueueDevice{
		permits: make(chan struct{}, 1),
		started: make(chan phaseSignal, 1),
		written: make(chan phaseSignal, 1),
	}
	dev.permits <- struct{}{}
	if _, err := dev.Write([]byte("fixture")); err != nil {
		t.Fatal(err)
	}
	if len(dev.started) != 1 || len(dev.written) != 1 {
		t.Fatal("missing device acknowledgements")
	}
	report := rec.Report(0)
	if strings.Contains(report, "not_reached") || !strings.Contains(report, "producer=absent") ||
		!strings.Contains(report, "seq=0 enqueued=+0s started=unknown permitted=unknown written=unknown") {
		t.Fatalf("a recorder no device writes to must report unknown, not absence: %s", report)
	}
}

func TestPhaseRecorderActualDeviceCompletesBeforeObserver(t *testing.T) {
	x := newRecorderFixture(t, 32, 64)
	x.permit(1)
	x.enqueue(1)
	// The producer records the completed write and then acknowledges it. The assertion below
	// counts the acknowledgement, so the wait covers both publications: a completed record
	// alone does not mean the acknowledgement has been sent.
	x.dev.waitAcknowledged(t, 1)

	if len(x.dev.started) != 1 || len(x.dev.written) != 1 {
		t.Fatalf("acknowledgements: started=%d written=%d, want 1 buffered each",
			len(x.dev.started), len(x.dev.written))
	}
	report := x.rec.Report(0)
	for _, want := range []string{
		"producer=attached enqueued=1 started=1 permitted=1 written=1",
		"observed_started=0 observed_written=0 unattributed=0",
		"stalled=seq=0 enqueued=+0s started=+",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("report lacks %q before the observer drained: %s", want, report)
		}
	}
	if strings.Contains(report, "not_reached") || strings.Contains(report, "unknown") ||
		strings.Contains(report, "evicted") {
		t.Fatalf("completed write reported absent before acknowledgement: %s", report)
	}
	ev, ok := x.rec.Event(0)
	if !ok || ev.started.Before(ev.enqueued) || ev.permitted.Before(ev.started) ||
		ev.written.Before(ev.permitted) {
		t.Fatalf("phase instants out of order: %+v", ev)
	}
}

func TestPhaseRecorderActualFixtureKeepsIdentityAcrossWraps(t *testing.T) {
	const window, round, rounds = 64, 16, 15 // 240 events: more than three full windows
	x := newRecorderFixture(t, 32, window)
	for r := range rounds {
		x.enqueue(round)
		x.permit(round)
		total := round * (r + 1)
		x.rec.waitFor(t, fmt.Sprintf("%d writes", total), func(c phaseCounts) bool { return c.Written == total })
		if c := x.rec.Counts(); c.ObservedWritten != total-round || c.Started != total || c.Unattributed != 0 {
			t.Fatalf("round %d: the producer must lead the delayed observer: %+v", r, c)
		}
		x.observe(round, round)
	}

	// Zero completion after 240 writes: one more event is admitted and its write held.
	const stalled = round * rounds
	x.enqueue(1)
	x.rec.waitFor(t, "the held write's start", func(c phaseCounts) bool { return c.Started == stalled+1 })
	report := x.rec.Report(x.rec.HeadOfLine())
	for _, want := range []string{
		"enqueued=241 started=241 permitted=240 written=240 observed_started=240 observed_written=240 unattributed=0",
		"window=177..240 stalled=seq=240 enqueued=+",
		"permitted=not_reached written=not_reached | seq=177 ",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("stall report lacks %q: %s", want, report)
		}
	}
	if n := strings.Count(report, "not_reached"); n != 4 || strings.Contains(report, "evicted") {
		t.Fatalf("only seq 240's permit and completion may be missing (%d): %s", n, report)
	}
	if _, ok := x.rec.Event(stalled - window); ok {
		t.Fatalf("seq %d left the window but is still retained", stalled-window)
	}
	for seq := stalled - window + 1; seq < stalled; seq++ {
		ev, ok := x.rec.Event(seq)
		next, _ := x.rec.Event(seq + 1)
		if !ok || ev.seq != seq || ev.started.Before(ev.enqueued) || ev.permitted.Before(ev.started) ||
			ev.written.Before(ev.permitted) || next.started.Before(ev.written) {
			t.Fatalf("seq %d phases out of serialized order: %+v next=%+v", seq, ev, next)
		}
	}

	// Late completion of the held write.
	x.permit(1)
	x.rec.waitFor(t, "the held write's completion", func(c phaseCounts) bool { return c.Written == stalled+1 })
	if report := x.rec.Report(stalled); strings.Contains(report, "not_reached") {
		t.Fatalf("late completion not recorded: %s", report)
	}
}

func TestPhaseRecorderActualFixtureKeepsPendingHeadPastTheWindow(t *testing.T) {
	const capacity, window = 32, 16
	x := newRecorderFixture(t, capacity, window)
	x.enqueue(1)
	x.rec.waitFor(t, "the first write's start", func(c phaseCounts) bool { return c.Started == 1 })
	x.enqueue(capacity) // seqs 1..32 queue behind the held write and push seq 0 out of the ring

	report := x.rec.Report(x.rec.HeadOfLine())
	for _, want := range []string{
		"enqueued=33 started=1 permitted=0 written=0",
		"window=17..32 stalled=seq=0 enqueued=+0s started=+",
		"permitted=not_reached written=not_reached | seq=17 ",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("pending head report lacks %q: %s", want, report)
		}
	}
	if head, ok := x.rec.Event(0); !ok || head.seq != 0 || head.started.IsZero() {
		t.Fatalf("the evicted pending head lost its identity: %+v %v", head, ok)
	}

	x.permit(1)
	x.rec.waitFor(t, "the head's completion and the next start", func(c phaseCounts) bool {
		return c.Written == 1 && c.Started == 2
	})
	// Seq 0's permit and completion, and seq 1's start, belong to those events alone: the
	// slots they once used now hold seq 32 and seq 17.
	if ev, _ := x.rec.Event(32); !ev.started.IsZero() || !ev.permitted.IsZero() || !ev.written.IsZero() {
		t.Fatalf("seq 0's phases were written into seq 32's slot: %+v", ev)
	}
	if ev, _ := x.rec.Event(17); !ev.started.IsZero() {
		t.Fatalf("seq 1's start was written into seq 17's slot: %+v", ev)
	}
	report = x.rec.Report(x.rec.HeadOfLine())
	if !strings.Contains(report, "stalled=seq=1 enqueued=reached_time_evicted "+
		"started=reached_time_evicted permitted=not_reached written=not_reached") {
		t.Fatalf("an unretained head must be named with its counted phases: %s", report)
	}
}

func TestPhaseRecorderActualFixtureWriteBeforeAdmissionRecord(t *testing.T) {
	x := newRecorderFixture(t, 32, 16)
	// A packet handed to the forwarder without its admission recorded: the device's Write
	// must neither block on the recorder nor take a sequence number it has no claim to.
	if err := x.f.RouteBackendToClient(1, x.packet, "10.100.0.10"); err != nil {
		t.Fatal(err)
	}
	x.permit(1)
	x.rec.waitFor(t, "three unattributed phases", func(c phaseCounts) bool { return c.Unattributed == 3 })
	if c := x.rec.Counts(); c.Enqueued != 0 || c.Started != 0 || c.Permitted != 0 || c.Written != 0 {
		t.Fatalf("an unadmitted write was credited: %+v", c)
	}
	// The next recorded admission is still seq 0, and its write is attributed to it.
	x.permit(1)
	x.enqueue(1)
	x.rec.waitFor(t, "seq 0's completion", func(c phaseCounts) bool { return c.Written == 1 })
	if c := x.rec.Counts(); c.Enqueued != 1 || c.Started != 1 || c.Unattributed != 3 {
		t.Fatalf("attribution after an unadmitted write: %+v", c)
	}
}

// Hand-fed recorder tests: attribution rules the fixture device does not reach on purpose.

func TestPhaseRecorderCountsUnattributedPhases(t *testing.T) {
	rec := newPhaseRecorder(8)
	rec.AttachProducer()
	at := time.Unix(1_700_000_000, 0)
	if seq := rec.Started(at); seq != -1 {
		t.Fatalf("a write before any admission was attributed to seq %d", seq)
	}
	rec.Permitted(-1, at)
	rec.Written(-1, at)
	seq := rec.Enqueue(at)
	rec.Written(seq, at) // a completion with no start or permit for this seq
	if c := rec.Counts(); c.Unattributed != 4 || c.Started != 0 || c.Permitted != 0 || c.Written != 0 {
		t.Fatalf("unattributed phases must be counted, not credited: %+v", c)
	}
	if got := rec.Started(at); got != 0 {
		t.Fatalf("first admitted write attributed to %d", got)
	}
	rec.Permitted(0, at)
	rec.Written(0, at)
	if c := rec.Counts(); c.Started != 1 || c.Permitted != 1 || c.Written != 1 || c.Unattributed != 4 {
		t.Fatalf("counts after an ordinary write: %+v", c)
	}
}

func TestPhaseRecorderReportsNeverReachedOnlyWithProducer(t *testing.T) {
	rec := newPhaseRecorder(8)
	at := time.Unix(1_700_000_000, 0)
	for i := range 3 {
		rec.Enqueue(at.Add(time.Duration(i) * time.Microsecond))
	}
	if report := rec.Report(0); strings.Contains(report, "not_reached") {
		t.Fatalf("absence asserted without a producer: %s", report)
	}
	rec.AttachProducer()
	rec.Started(at.Add(5 * time.Microsecond))
	report := rec.Report(1)
	for _, want := range []string{
		"seq=0 enqueued=+0s started=+5µs permitted=not_reached written=not_reached",
		"stalled=seq=1 enqueued=+1µs started=not_reached",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("report lacks %q: %s", want, report)
		}
	}
}
