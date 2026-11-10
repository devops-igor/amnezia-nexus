package clientawg

import (
	"fmt"
	"regexp"
	"runtime"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// stackBufSize bounds the goroutine dump used to identify the event reader. It is a var
// only so one test can force saturation; no test here runs in parallel.
var stackBufSize = 1 << 20

// eventReaders counts goroutines blocked in the upstream TUN event reader of this
// engine, keyed by the receiver pointer the runtime prints. runtime.Stack fills the
// buffer EXACTLY when the output does not fit, so a full buffer means the dump is
// truncated: a reader past the cut is invisible, would count as zero and falsely certify
// shutdown. ok is false there.
func eventReaders(t *testing.T, dev *device.Device) (int, bool) {
	t.Helper()
	buf := make([]byte, stackBufSize)
	size := runtime.Stack(buf, true)
	if size >= len(buf) {
		return 0, false
	}
	re := regexp.MustCompile(`device\.\(\*Device\)\.RoutineTUNEventReader\(` + regexp.QuoteMeta(fmt.Sprintf("%p", dev)) + `\)`)
	return len(re.FindAll(buf[:size], -1)), true
}

// waitEventReaders polls until dev has exactly want event readers. The reader may not be
// scheduled yet, so "0 readers" right after construction proves nothing: the 1 -> 0
// transition is the evidence. A truncated dump is a hard failure — unknown is not zero.
func waitEventReaders(t *testing.T, dev *device.Device, want int, what string) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		n, ok := eventReaders(t, dev)
		if !ok {
			t.Fatalf("%s: dump exceeded %d bytes; reader count unknown, not certifying it", what, stackBufSize)
		}
		if n == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d event readers, want %d", what, n, want)
		}
	}
}

// TestDeviceShutdownTerminatesTUNEventReader pins issue #758 on real engines: the
// upstream event reader over the VirtualTUN event channel must exit after Close, across
// three repeated create/close cycles. SendEvent racing Close is covered in the
// virtualtun package; this test does not flood a real engine.
func TestDeviceShutdownTerminatesTUNEventReader(t *testing.T) {
	for i := 0; i < 3; i++ {
		d, err := NewDevice(testConfig())
		if err != nil {
			t.Fatalf("cycle %d: NewDevice: %v", i, err)
		}
		// Registered before any assertion can fail: a failed observation must not
		// strand a running engine.
		t.Cleanup(func() { _ = d.Close() })
		waitEventReaders(t, d.dev, 1, fmt.Sprintf("cycle %d while up", i))
		d.tun.SendEvent(tun.EventMTUUpdate) // live delivery, as production does
		if err := d.Close(); err != nil {
			t.Fatalf("cycle %d: Close: %v", i, err)
		}
		waitEventReaders(t, d.dev, 0, fmt.Sprintf("cycle %d after Close", i))
	}
}

// TestEventReaderObservationRefusesTruncatedDump pins the fail-closed rule: a saturated
// buffer hides every reader past the cut, so the observation must refuse rather than
// report the false zero that would certify a shutdown.
func TestEventReaderObservationRefusesTruncatedDump(t *testing.T) {
	d, err := NewDevice(testConfig())
	if err != nil {
		t.Fatalf("NewDevice: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if _, ok := eventReaders(t, d.dev); !ok {
		t.Fatalf("a %d-byte dump did not fit the process; raise stackBufSize", stackBufSize)
	}
	stackBufSize = 64 // deterministic saturation: one goroutine trace exceeds 64 bytes
	defer func() { stackBufSize = 1 << 20 }()
	if n, ok := eventReaders(t, d.dev); ok || n != 0 {
		t.Fatalf("truncated dump accepted: n=%d ok=%v, want the refusal", n, ok)
	}
}
