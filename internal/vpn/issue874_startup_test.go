package vpn

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

const (
	// firstReadStartTimeout bounds the fixture constructor's wait for the
	// device's TUN reader goroutine to reach its first read. The wait exists to
	// order the reader against IpcSet deterministically, not to pace the
	// fixture.
	firstReadStartTimeout = 10 * time.Second

	// firstReadShutdownTimeout bounds device shutdown while a gated read is
	// still pending, so a wrapper that fails to release on close surfaces as a
	// test failure instead of a hung suite.
	firstReadShutdownTimeout = 10 * time.Second
)

// errFirstReadGateClosed reports a read that was still held when the gated
// device was closed, that is, a device shut down before its transport
// configuration was applied.
var errFirstReadGateClosed = errors.New("tun reader gated on a configuration that never completed")

// startupReadObservation records one TUN read entry made by the upstream
// reader loop.
type startupReadObservation struct {
	// padding is the transport padding the reader loop loaded before this read.
	// The loop computes the read offset as MessageTransportHeaderSize+padding
	// and stamps that same value on every packet the read returns.
	padding uint32
	// delivered reports whether the wrapped device returned at least one packet
	// from this read.
	delivered bool
	// completed reports whether the read returned yet. A pending gated read is
	// recorded at entry and completed later.
	completed bool
	err       error
}

// firstReadGate is a test-only tun.Device wrapper that holds the upstream
// device's first read until the transport configuration has been applied.
//
// The upstream TUN reader loads the transport padding once per loop iteration
// and stamps it on every packet that iteration returns. A device is configured
// (IpcSet, which stores S4) after NewDevice has already started that loop, so
// the iteration pending at configuration time would stamp padding 0 on the
// first packet it reads. Holding the pending read and returning an empty read
// from it makes the loop reload the configured padding before it consumes
// anything, so no stacked packet is discarded and no packet is rewritten after
// the fact.
type firstReadGate struct {
	tun.Device

	mu       sync.Mutex
	observed []startupReadObservation
	// configured records that the caller applied the transport configuration
	// and released the gate.
	configured bool
	aborted    bool
	abortErr   error

	firstRead chan struct{}
	release   chan struct{}
	abort     chan struct{}
}

// newFirstReadGate wraps inner so its first read waits for MarkConfigured.
func newFirstReadGate(inner tun.Device) *firstReadGate {
	return &firstReadGate{
		Device:    inner,
		firstRead: make(chan struct{}),
		release:   make(chan struct{}),
		abort:     make(chan struct{}),
	}
}

// Read forwards to the wrapped device, except for the first read, which is held
// until MarkConfigured releases it as an empty read, or until the gate is
// aborted or closed.
func (g *firstReadGate) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	padding := transportPaddingAt(offset)

	g.mu.Lock()
	index := len(g.observed)
	g.observed = append(g.observed, startupReadObservation{padding: padding})
	hold := index == 0 && !g.configured && !g.aborted
	if index == 0 {
		close(g.firstRead)
	}
	g.mu.Unlock()

	if hold {
		select {
		case <-g.release:
			g.completeRead(index, 0, nil)
			return 0, nil
		case <-g.abort:
			err := g.abortReason()
			g.completeRead(index, 0, err)
			return 0, err
		}
	}

	n, err := g.Device.Read(bufs, sizes, offset)
	g.completeRead(index, n, err)
	return n, err
}

// Close releases a read that is still held and then closes the wrapped device.
// Device shutdown waits for the reader goroutine, so a gate that did not
// release here would deadlock on a device closed before configuration.
func (g *firstReadGate) Close() error {
	g.abortWith(errFirstReadGateClosed)
	return g.Device.Close()
}

// WaitFirstRead waits until the upstream reader has entered its first read.
func (g *firstReadGate) WaitFirstRead(timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-g.firstRead:
		return nil
	case <-g.abort:
		return g.abortReason()
	case <-timer.C:
		return fmt.Errorf("tun reader did not enter its first read within %s", timeout)
	}
}

// MarkConfigured releases the held read after the transport configuration has
// been applied, so the reader reloads the configured padding.
func (g *firstReadGate) MarkConfigured() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.configured || g.aborted {
		return
	}
	g.configured = true
	close(g.release)
}

// Abort releases a held read with err instead of applying configuration.
func (g *firstReadGate) Abort(err error) {
	if err == nil {
		err = errFirstReadGateClosed
	}
	g.abortWith(err)
}

// Observations returns a copy of the reads observed so far, in entry order.
func (g *firstReadGate) Observations() []startupReadObservation {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]startupReadObservation(nil), g.observed...)
}

// FirstDeliveringPadding returns the padding loaded for the first read that
// delivered a packet, and whether such a read happened.
func (g *firstReadGate) FirstDeliveringPadding() (uint32, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, obs := range g.observed {
		if obs.delivered {
			return obs.padding, true
		}
	}
	return 0, false
}

func (g *firstReadGate) completeRead(index, n int, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.observed[index].delivered = n > 0
	g.observed[index].completed = true
	g.observed[index].err = err
}

func (g *firstReadGate) abortWith(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.aborted {
		return
	}
	g.aborted = true
	g.abortErr = err
	close(g.abort)
}

func (g *firstReadGate) abortReason() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.abortErr != nil {
		return g.abortErr
	}
	return errFirstReadGateClosed
}

// transportPaddingAt recovers the transport padding from the packet offset the
// upstream reader computed for a read.
func transportPaddingAt(offset int) uint32 {
	if offset < device.MessageTransportHeaderSize {
		return 0
	}
	return uint32(offset - device.MessageTransportHeaderSize)
}

// gateOf returns the startup gate a fixture constructor installed on dev.
func gateOf(t *testing.T, name string, dev tun.Device) *firstReadGate {
	t.Helper()
	gate, ok := dev.(*firstReadGate)
	if !ok {
		t.Fatalf("%s is not gated on its first read: tun device is %T", name, dev)
	}
	return gate
}

// assertStartupGateHeldFirstRead asserts that dev's reader entered its first
// read before the device was configured (padding 0, nothing consumed), and that
// the next read entry carried the configured padding. Call it after a completed
// exchange so both observations are settled.
func assertStartupGateHeldFirstRead(t *testing.T, name string, dev tun.Device, configured uint32) {
	t.Helper()
	gate := gateOf(t, name, dev)
	obs := gate.Observations()
	if len(obs) == 0 {
		t.Fatalf("%s: reader recorded no read", name)
	}
	if !obs[0].completed {
		t.Fatalf("%s: first read is still held after configuration", name)
	}
	if obs[0].err != nil {
		t.Fatalf("%s: held first read failed: %v", name, obs[0].err)
	}
	if obs[0].delivered {
		t.Fatalf("%s: held first read consumed a packet with padding %d; the gate must return an empty read", name, obs[0].padding)
	}
	if obs[0].padding != 0 {
		t.Fatalf("%s: held first read observed padding %d, want 0 before configuration", name, obs[0].padding)
	}
	if len(obs) < 2 {
		t.Fatalf("%s: reader recorded %d read entries, want at least 2 (held read then configured read)", name, len(obs))
	}
	if obs[1].padding != configured {
		t.Fatalf("%s: first read after configuration observed padding %d, want %d", name, obs[1].padding, configured)
	}
}

// assertFirstDeliveredPadding asserts that the first packet the reader took from
// the stack was stamped with the configured transport padding.
func assertFirstDeliveredPadding(t *testing.T, name string, dev tun.Device, configured uint32) {
	t.Helper()
	gate := gateOf(t, name, dev)
	got, ok := gate.FirstDeliveringPadding()
	if !ok {
		t.Fatalf("%s: reader delivered no packet through the gated tun", name)
	}
	if got != configured {
		t.Fatalf("%s: first packet delivered to the transport carried padding %d, want %d", name, got, configured)
	}
}

// harnessTransportPadding returns the S4 transport padding the harness config
// configures for both fixture devices.
func harnessTransportPadding(t *testing.T, h *DifferentialHarness) uint32 {
	t.Helper()
	cfg, err := h.svc.GetConfig(t.Context())
	if err != nil {
		t.Fatalf("get harness config: %v", err)
	}
	if cfg.S4 < 0 {
		t.Fatalf("harness config has negative S4 %d", cfg.S4)
	}
	return uint32(cfg.S4)
}

// exchangeOnce runs one client payload exchange against the reference server and
// asserts the echoed payload identity.
func exchangeOnce(t *testing.T, client *HarnessClient, payload []byte) {
	t.Helper()
	udpConn, err := client.DialUDP()
	if err != nil {
		t.Fatalf("dial udp through tunnel: %v", err)
	}
	defer func() {
		if err := udpConn.Close(); err != nil {
			t.Errorf("close udp conn: %v", err)
		}
	}()

	echo, err := client.ExchangeUDP(udpConn, payload)
	if err != nil {
		t.Fatalf("udp exchange: %v", err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatalf("udp echo mismatch: got %q, want %q", echo, payload)
	}
}

// TestIssue874_FirstTransportReadUsesConfiguredPadding proves that both fixture
// devices apply the configured S4 padding to the first packet their upstream
// reader hands to the transport, on the same device the differential oracle
// uses.
func TestIssue874_FirstTransportReadUsesConfiguredPadding(t *testing.T) {
	harness := NewDifferentialHarness(t)
	configured := harnessTransportPadding(t, harness)
	if configured == 0 {
		t.Fatalf("harness config has S4=0; this case needs nonzero transport padding")
	}

	refServer, err := harness.StartReferenceServer()
	if err != nil {
		t.Fatalf("start reference server: %v", err)
	}
	defer func() {
		if err := harness.StopReferenceServer(refServer); err != nil {
			t.Errorf("stop reference server: %v", err)
		}
	}()

	client, err := harness.NewClient()
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Errorf("close client: %v", err)
		}
	}()

	// One exchange settles every observed read: the payload-carrying reads have
	// completed in both directions, so the assertions below cannot race the
	// reader goroutines.
	exchangeOnce(t, client, []byte("issue874-first-transport"))

	// Both constructors must have intercepted the pending pre-configuration
	// read, and the packet carrying the payload in each direction must have been
	// stamped with the configured padding.
	assertStartupGateHeldFirstRead(t, "reference server", refServer.tun, configured)
	assertStartupGateHeldFirstRead(t, "client", client.tun, configured)
	assertFirstDeliveredPadding(t, "reference server", refServer.tun, configured)
	assertFirstDeliveredPadding(t, "client", client.tun, configured)
}

// TestIssue874_FirstTransportReadWithoutPadding covers ordinary startup: a
// device configured without transport padding (no s4 in its UAPI) must gate its
// first read at padding 0 and take the first stacked packet at padding 0.
func TestIssue874_FirstTransportReadWithoutPadding(t *testing.T) {
	vt, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.124.1.2")}, nil, 1280)
	if err != nil {
		t.Fatalf("create tun: %v", err)
	}
	gate := newFirstReadGate(vt)
	dev := startUnpaddedDevice(t, gate)
	defer dev.Close()

	var priv device.NoisePrivateKey
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	if err := dev.IpcSet(fmt.Sprintf("private_key=%x\n", priv[:])); err != nil {
		t.Fatalf("ipc set: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("up: %v", err)
	}
	gate.MarkConfigured()

	udpConn, err := stack.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(netip.MustParseAddr("10.124.1.9"), 9))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer udpConn.Close()
	if _, err := udpConn.Write([]byte("issue874-unpadded-startup")); err != nil {
		t.Fatalf("write to stack: %v", err)
	}
	waitForFirstDelivery(t, "unpadded client", gate)

	assertStartupGateHeldFirstRead(t, "unpadded client", gate, 0)
	assertFirstDeliveredPadding(t, "unpadded client", gate, 0)
}

// startUnpaddedDevice builds a device on gate and waits for its reader to reach
// the gated first read.
func startUnpaddedDevice(t *testing.T, gate *firstReadGate) *device.Device {
	t.Helper()
	dev := device.NewDevice(gate, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "unpadded-client"))
	if err := gate.WaitFirstRead(firstReadStartTimeout); err != nil {
		dev.Close()
		t.Fatalf("reader did not start: %v", err)
	}
	return dev
}

// waitForFirstDelivery waits until the reader has delivered a stacked packet
// through the gated tun.
func waitForFirstDelivery(t *testing.T, name string, gate *firstReadGate) {
	t.Helper()
	deadline := time.Now().Add(firstReadStartTimeout)
	for {
		if _, ok := gate.FirstDeliveringPadding(); ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: reader never delivered the stacked packet", name)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestIssue874_StartupGateReleasesOnFailureAndClose covers the shutdown paths of
// the gate: a device whose configuration fails, and a device closed while its
// first read is still held. Neither may block device shutdown or consume a
// packet.
func TestIssue874_StartupGateReleasesOnFailureAndClose(t *testing.T) {
	t.Run("ConfigurationFailure", verifyGateShutdownAfterConfigurationFailure)
	t.Run("CloseBeforeConfiguration", verifyGateShutdownBeforeConfiguration)
}

// newGatedDevice builds a device whose first read is gated, without applying any
// transport configuration.
func newGatedDevice(t *testing.T) (*firstReadGate, *device.Device) {
	t.Helper()
	vt, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.124.0.2")}, nil, 1280)
	if err != nil {
		t.Fatalf("create tun: %v", err)
	}
	gate := newFirstReadGate(vt)
	dev := device.NewDevice(gate, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "first-read-gate"))
	if err := gate.WaitFirstRead(firstReadStartTimeout); err != nil {
		dev.Close()
		t.Fatalf("reader did not start: %v", err)
	}
	return gate, dev
}

// closeWithin runs closeFn and fails when it blocks on a held first read.
func closeWithin(t *testing.T, name string, closeFn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		closeFn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(firstReadShutdownTimeout):
		t.Fatalf("%s: device shutdown blocked on a held first read", name)
	}
}

// verifyGateShutdownAfterConfigurationFailure configures the device with an
// invalid UAPI document and requires shutdown to release the held read.
func verifyGateShutdownAfterConfigurationFailure(t *testing.T) {
	gate, dev := newGatedDevice(t)

	if err := dev.IpcSet("private_key=not-a-valid-key\n"); err == nil {
		dev.Close()
		t.Fatal("IpcSet accepted an invalid private key")
	}

	closeWithin(t, "configuration failure", dev.Close)

	obs := gate.Observations()
	if len(obs) != 1 {
		t.Fatalf("reader made %d observed reads after failed configuration, want 1", len(obs))
	}
	if !obs[0].completed {
		t.Fatal("held read never returned after shutdown")
	}
	if obs[0].err == nil {
		t.Fatal("held read returned without an error although configuration never completed")
	}
	if obs[0].delivered {
		t.Fatal("held read consumed a packet during shutdown")
	}
}

// verifyGateShutdownBeforeConfiguration closes the device while the first read
// is still held and requires the gate to release it with an error.
func verifyGateShutdownBeforeConfiguration(t *testing.T) {
	gate, dev := newGatedDevice(t)

	// The gate must keep holding while configuration is outstanding: an entry
	// observation without completion is the blocked state.
	select {
	case <-time.After(100 * time.Millisecond):
	}
	obs := gate.Observations()
	if len(obs) != 1 || obs[0].completed {
		t.Fatalf("reader left the gate before configuration or close: %d observations", len(obs))
	}

	// Device shutdown closes the tun through the gate, which must release the
	// held read instead of deadlocking on the reader goroutine.
	closeWithin(t, "close before configuration", dev.Close)

	obs = gate.Observations()
	if len(obs) != 1 {
		t.Fatalf("reader made %d observed reads, want 1", len(obs))
	}
	if !errors.Is(obs[0].err, errFirstReadGateClosed) {
		t.Fatalf("held read returned %v, want %v (observations: %+v)", obs[0].err, errFirstReadGateClosed, obs)
	}
	if obs[0].delivered {
		t.Fatal("held read consumed a packet during close")
	}
}
