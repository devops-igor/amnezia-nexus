package forwarder

import (
	"net/netip"
	"testing"
	"time"
)

// Lifecycle controls for the test WAN devices (issue #861).
//
// A production TUN read blocks until the device is closed. The package's WAN device
// fixtures are held to the same contract here, because a fixture that returns
// (0, nil) at once makes readWANLoop spin for as long as its DirectEgressManager is
// alive, and those spinners starve the timer wake-ups that unrelated timing
// assertions depend on. The device read count is the evidence: a parked reader calls
// the device once, a spinning one calls it without bound.
//
// Manager ownership is the other half: a manager built with a WAN device starts a
// reader, so the fixture that builds it must retire it, including when the case ends
// early.

// requireParkedWANReader asserts the device's reader reached Read and stays there.
func requireParkedWANReader(t *testing.T, dev *mockPacketDev) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for dev.readCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the manager's reader never reached the WAN device")
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if got := dev.readCount(); got != 1 {
		t.Fatalf("WAN device reads = %d, want the single parked read: a test WAN device must block like a TUN read, not spin", got)
	}
}

// wanReaderState reads the manager's reader ownership under its own lock.
func wanReaderState(m *DirectEgressManager) (running bool, dev PacketDevice) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.readerRunning, m.wanDevice
}

func TestMockPacketDevReadParksUntilClose(t *testing.T) {
	dev := newMockPacketDev()
	read := make(chan error, 1)
	go func() {
		_, err := dev.Read(make([]byte, 1))
		read <- err
	}()

	select {
	case err := <-read:
		t.Fatalf("Read returned %v before Close; a WAN device read must park", err)
	case <-time.After(100 * time.Millisecond):
	}
	if got := dev.readCount(); got != 1 {
		t.Fatalf("Read calls = %d, want the one parked call", got)
	}

	if err := dev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-read:
		if err == nil {
			t.Fatal("the parked Read returned no error after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock the parked Read")
	}

	// Closing twice is normal: the manager's own Close is idempotent, and so is the
	// device it closes.
	if err := dev.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestMockPacketDevWriteCaptureIsUnchanged is the positive control for the read gate:
// admitting the read half must not touch what a WAN write does.
func TestMockPacketDevWriteCaptureIsUnchanged(t *testing.T) {
	dev := newMockPacketDev()
	pkt := []byte("wan-packet")
	n, err := dev.Write(pkt)
	if n != len(pkt) || err != nil {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(pkt))
	}
	if got := dev.getPackets(); len(got) != 1 || string(got[0]) != string(pkt) {
		t.Fatalf("captured packets = %q, want the written packet", got)
	}
	select {
	case <-dev.notifyCh:
	default:
		t.Fatal("Write did not notify the capture channel")
	}
}

func TestWANReaderParksForLiveManager(t *testing.T) {
	dev := newMockPacketDev()
	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP: netip.MustParseAddr("203.0.113.1"),
		WANDevice: dev,
	}, nil)
	t.Cleanup(func() { _ = dem.Close() })

	if running, wan := wanReaderState(dem); !running || wan != dev {
		t.Fatalf("manager reader state = (running %v, device %v), want the device it was built with", running, wan)
	}
	requireParkedWANReader(t, dev)
}

func TestWANManagerCloseJoinsOwnedReader(t *testing.T) {
	dev := newMockPacketDev()
	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP: netip.MustParseAddr("203.0.113.1"),
		WANDevice: dev,
	}, nil)
	requireParkedWANReader(t, dev)

	closed := make(chan error, 1)
	go func() { closed <- dem.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("manager Close did not join the parked WAN reader")
	}

	if running, _ := wanReaderState(dem); running {
		t.Fatal("manager still reports a running reader after Close")
	}
	reads := dev.readCount()
	time.Sleep(50 * time.Millisecond)
	if got := dev.readCount(); got != reads {
		t.Fatalf("device reads grew from %d to %d after Close", reads, got)
	}
	if _, err := dev.Read(make([]byte, 1)); err == nil {
		t.Fatal("manager Close did not close the WAN device it owned")
	}
	if err := dem.Close(); err != nil {
		t.Fatalf("second manager Close: %v", err)
	}
}

func TestAttachWANDeviceRetiresReplacedReader(t *testing.T) {
	dev1 := newMockPacketDev()
	dev2 := newMockPacketDev()
	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP: netip.MustParseAddr("203.0.113.1"),
		WANDevice: dev1,
	}, nil)
	t.Cleanup(func() { _ = dem.Close() })
	requireParkedWANReader(t, dev1)

	dem.AttachWANDevice(dev2)
	if _, err := dev1.Read(make([]byte, 1)); err == nil {
		t.Fatal("the replaced WAN device was not closed")
	}
	retired := dev1.readCount()
	requireParkedWANReader(t, dev2)
	if running, wan := wanReaderState(dem); !running || wan != dev2 {
		t.Fatalf("manager reader state = (running %v, device %v), want the replacement device", running, wan)
	}

	// Re-attaching the device the manager already runs keeps the single reader.
	dem.AttachWANDevice(dev2)
	if got := dev2.readCount(); got != 1 {
		t.Fatalf("re-attach started a second reader: device reads = %d", got)
	}
	if got := dev1.readCount(); got != retired {
		t.Fatalf("the retired device was read again: %d -> %d", retired, got)
	}
}

// TestWANFixtureCleanupRetiresReaderAfterEarlyExit proves the ownership registered by
// the fixture helper: the case ends without reaching a teardown of its own and the
// manager's reader is still joined. A fatal assertion leaves a test by the same path;
// a skip is used here because a deliberately failing case cannot belong to a green
// suite.
func TestWANFixtureCleanupRetiresReaderAfterEarlyExit(t *testing.T) {
	var dem *DirectEgressManager
	var dev *mockPacketDev

	t.Run("early exit", func(t *testing.T) {
		_, dem, dev = setupForwarderWithPBR(t)
		requireParkedWANReader(t, dev)
		t.Skip("leave before the case reaches any teardown of its own")
	})

	if running, _ := wanReaderState(dem); running {
		t.Fatal("the fixture cleanup did not retire the manager's WAN reader")
	}
	reads := dev.readCount()
	time.Sleep(50 * time.Millisecond)
	if got := dev.readCount(); got != reads {
		t.Fatalf("retired reader kept reading: %d -> %d", reads, got)
	}
	if _, err := dev.Read(make([]byte, 1)); err == nil {
		t.Fatal("the fixture cleanup did not close the WAN device it owned")
	}
}
