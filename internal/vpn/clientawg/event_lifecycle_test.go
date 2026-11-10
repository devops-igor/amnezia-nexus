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

// eventReaders counts goroutines blocked in the upstream TUN event reader of this
// engine, keyed by the receiver pointer the runtime prints. Total goroutine counts
// conflate unrelated workers; this counts the one routine whose exit we own.
func eventReaders(t *testing.T, dev *device.Device) int {
	t.Helper()
	re := regexp.MustCompile(`device\.\(\*Device\)\.RoutineTUNEventReader\(` + regexp.QuoteMeta(fmt.Sprintf("%p", dev)) + `\)`)
	buf := make([]byte, 1<<20)
	return len(re.FindAll(buf[:runtime.Stack(buf, true)], -1))
}

// waitEventReaders polls until dev has exactly want event readers. The reader
// starts inside device.NewDevice but may not be scheduled yet, so "0 readers" right
// after construction proves nothing: the transition to 1 and back to 0 is evidence.
func waitEventReaders(t *testing.T, dev *device.Device, want int, what string) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if n := eventReaders(t, dev); n == want {
			return
		} else if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			t.Fatalf("%s: %d event readers, want %d\n%s", what, n, want, buf[:runtime.Stack(buf, true)])
		}
	}
}

// TestDeviceShutdownTerminatesTUNEventReader pins issue #758 on real engines: the
// upstream event reader ranging over the VirtualTUN event channel must exit after
// Close, across repeated create/close cycles, including when Close races live
// event submissions. The send/close race itself is covered in the virtualtun
// package, which owns the channel.
func TestDeviceShutdownTerminatesTUNEventReader(t *testing.T) {
	for i := 0; i < 3; i++ {
		d, err := NewDevice(testConfig())
		if err != nil {
			t.Fatalf("cycle %d: NewDevice: %v", i, err)
		}
		waitEventReaders(t, d.dev, 1, fmt.Sprintf("cycle %d while up", i))
		d.tun.SendEvent(tun.EventMTUUpdate) // live delivery, as production does
		if err := d.Close(); err != nil {
			t.Fatalf("cycle %d: Close: %v", i, err)
		}
		// Bounded: a leaked reader from this cycle fails here, and a reader from
		// an earlier cycle would already have failed its own cycle.
		waitEventReaders(t, d.dev, 0, fmt.Sprintf("cycle %d after Close", i))
	}
}
