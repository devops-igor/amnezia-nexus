package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestHealthProber_TransientFailures_PreservesActiveUnderViableDataPlane tests BLOCKER 2:
// Before reaching FailureThreshold, transient handshake probe failures must NOT prematurely
// mark the backend degraded when its data plane is viable or active sessions exist.
func TestHealthProber_TransientFailures_PreservesActiveUnderViableDataPlane(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	pool := NewPool(db)
	sID, _ := db.CreateServer(ctx, &models.Server{Name: "Transient-Host", Host: "10.0.0.5"})
	tun, err := pool.AddTunnel(ctx, sID, "10.0.0.5:51820", "pubkey5")
	if err != nil {
		t.Fatalf("failed to add tunnel: %v", err)
	}
	_ = pool.SetTunnelStatus(ctx, sID, models.TunnelStatusActive, 40)

	cfg := DefaultHealthConfig()
	cfg.FailureThreshold = 3

	// Outer handshake probe always fails (e.g. DPI blocks handshake packets)
	failOuterProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 0, errors.New("DPI handshake packet drop")
	}

	hp := NewHealthProber(pool, db, cfg, failOuterProbe)

	// Inner canary probe succeeds (data plane is fully viable)
	canaryCalls := 0
	hp.SetCanaryProbeFunc(func(ctx context.Context, tunnel *models.BackendTunnel) error {
		canaryCalls++
		return nil
	})

	// Failure 1: failures (1) < threshold (3), data plane viable -> transitions to handshake_blocked
	// to prevent new client admissions while preserving established sessions!
	_, err = hp.ProbeTunnel(ctx, tun)
	if err == nil {
		t.Fatal("expected probe error on outer probe failure 1")
	}
	cur, _ := pool.GetTunnel(sID)
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("failure 1: expected status handshake_blocked when data plane viable, got %q", cur.Status)
	}
	if len(pool.GetActiveTunnels()) != 0 {
		t.Fatalf("failure 1: expected tunnel excluded from active pool, got %d active tunnels", len(pool.GetActiveTunnels()))
	}

	// Failure 2: failures (2) < threshold (3), data plane viable -> remains handshake_blocked!
	_, err = hp.ProbeTunnel(ctx, tun)
	if err == nil {
		t.Fatal("expected probe error on outer probe failure 2")
	}
	cur, _ = pool.GetTunnel(sID)
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("failure 2: expected status handshake_blocked when data plane viable, got %q", cur.Status)
	}
	if len(pool.GetActiveTunnels()) != 0 {
		t.Fatalf("failure 2: expected tunnel excluded from active pool, got %d active tunnels", len(pool.GetActiveTunnels()))
	}

	// Failure 3: reaches FailureThreshold (3), canary succeeds -> transitions to handshake_blocked!
	_, err = hp.ProbeTunnel(ctx, tun)
	if err == nil {
		t.Fatal("expected probe error on outer probe failure 3")
	}
	cur, _ = pool.GetTunnel(sID)
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("failure 3: expected status handshake_blocked at threshold, got %q", cur.Status)
	}
	if cur.DisableReason != models.DisableReasonNone {
		t.Fatalf("expected DisableReason none, got %q", cur.DisableReason)
	}
}

// TestHealthProber_TransientFailures_PreservesActiveWithEstablishedSessions tests BLOCKER 2:
// When established sessions exist on the backend, transient handshake failures below threshold
// do not prematurely degrade the backend even if canary probe is not registered.
func TestHealthProber_TransientFailures_PreservesActiveWithEstablishedSessions(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	pool := NewPool(db)
	sID, _ := db.CreateServer(ctx, &models.Server{Name: "Session-Host", Host: "10.0.0.6"})
	tun, err := pool.AddTunnel(ctx, sID, "10.0.0.6:51820", "pubkey6")
	if err != nil {
		t.Fatalf("failed to add tunnel: %v", err)
	}
	_ = pool.SetTunnelStatus(ctx, sID, models.TunnelStatusActive, 40)

	// Simulate established connected session on tunnel
	pool.IncrementConnections(sID)

	cfg := DefaultHealthConfig()
	cfg.FailureThreshold = 3

	failOuterProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 0, errors.New("transient network timeout")
	}

	hp := NewHealthProber(pool, db, cfg, failOuterProbe)

	// Failure 1: below threshold, has active connections -> transitions to handshake_blocked
	// to prevent new client admissions while preserving established connections!
	_, _ = hp.ProbeTunnel(ctx, tun)
	cur, _ := pool.GetTunnel(sID)
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("failure 1: expected status handshake_blocked with active connections, got %q", cur.Status)
	}
	if len(pool.GetActiveTunnels()) != 0 {
		t.Fatalf("failure 1: expected tunnel excluded from active pool, got %d active tunnels", len(pool.GetActiveTunnels()))
	}
	if cur.ActiveConnections != 1 {
		t.Fatalf("failure 1: expected active connections preserved at 1, got %d", cur.ActiveConnections)
	}

	// Failure 2: below threshold, has active connections -> remains handshake_blocked!
	_, _ = hp.ProbeTunnel(ctx, tun)
	cur, _ = pool.GetTunnel(sID)
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("failure 2: expected status handshake_blocked with active connections, got %q", cur.Status)
	}
	if len(pool.GetActiveTunnels()) != 0 {
		t.Fatalf("failure 2: expected tunnel excluded from active pool, got %d active tunnels", len(pool.GetActiveTunnels()))
	}
	if cur.ActiveConnections != 1 {
		t.Fatalf("failure 2: expected active connections preserved at 1, got %d", cur.ActiveConnections)
	}
}

// mockConcurrentCanaryDevice routes ICMP and DNS responses back to hooks matching dynamic ID/Seq.
type mockConcurrentCanaryDevice struct {
	mu         sync.Mutex
	hooks      map[uint64]CanaryResponseHook
	nextHookID uint64
	written    int32
}

func (m *mockConcurrentCanaryDevice) RegisterCanaryResponseHook(hook CanaryResponseHook) func() {
	m.mu.Lock()
	if m.hooks == nil {
		m.hooks = make(map[uint64]CanaryResponseHook)
	}
	m.nextHookID++
	id := m.nextHookID
	m.hooks[id] = hook
	m.mu.Unlock()
	return func() {
		m.mu.Lock()
		delete(m.hooks, id)
		m.mu.Unlock()
	}
}

func (m *mockConcurrentCanaryDevice) Write(p []byte) (int, error) {
	atomic.AddInt32(&m.written, 1)

	// Build matching response
	var reply []byte
	if len(p) >= 28 && p[0]>>4 == 4 && p[9] == 1 && p[20] == 8 {
		// ICMP Echo Request -> reply with matching ID and Seq
		reqID := binary.BigEndian.Uint16(p[24:26])
		reqSeq := binary.BigEndian.Uint16(p[26:28])
		reply = BuildCanaryICMPEchoReply(net.IP(p[16:20]), net.IP(p[12:16]), reqID, reqSeq)
	}

	if len(reply) > 0 {
		m.mu.Lock()
		hooksCopy := make([]CanaryResponseHook, 0, len(m.hooks))
		for _, h := range m.hooks {
			if h != nil {
				hooksCopy = append(hooksCopy, h)
			}
		}
		m.mu.Unlock()

		go func(data []byte, hooks []CanaryResponseHook) {
			time.Sleep(5 * time.Millisecond) // simulate small in-tunnel flight latency
			for _, h := range hooks {
				h(data)
			}
		}(reply, hooksCopy)
	}

	return len(p), nil
}

func (m *mockConcurrentCanaryDevice) Read([]byte) (int, error) {
	return 0, errors.New("not implemented")
}
func (m *mockConcurrentCanaryDevice) Close() error { return nil }

// TestHealthCanary_ConcurrentOverlappingProbes_NoCollisions tests HIGH 3:
// Multiple concurrent canary probes on the same device generate unique atomic ID/Seq,
// eliminating collisions and false timeouts under parallel execution.
func TestHealthCanary_ConcurrentOverlappingProbes_NoCollisions(t *testing.T) {
	dev := &mockConcurrentCanaryDevice{}
	const concurrency = 25

	var wg sync.WaitGroup
	errCh := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			if err := ProbePacketDevice(ctx, dev, 1*time.Second); err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent canary probe failed: %v", err)
	}

	// Verify all response hooks were cleanly unregistered
	dev.mu.Lock()
	remainingHooks := len(dev.hooks)
	dev.mu.Unlock()
	if remainingHooks != 0 {
		t.Errorf("expected 0 lingering hooks after concurrent probes, got %d", remainingHooks)
	}
}

// TestHealthCanary_MultiSignal_PrimaryICMPFails_SecondarySucceeds tests HIGH 4:
// When the primary ICMP probe to 1.1.1.1 fails, the secondary signal (e.g. UDP DNS response)
// confirms data plane is viable, avoiding false eviction.
func TestHealthCanary_MultiSignal_PrimaryICMPFails_SecondaryDNSSucceeds(t *testing.T) {
	dev := &mockPacketDevice{}
	// Device answers UDP DNS queries targeting 8.8.8.8, but ignores ICMP to 1.1.1.1
	dev.setReplyData(nil)

	unregister := dev.RegisterCanaryResponseHook(nil)
	_ = unregister

	// Custom packet writer that answers only DNS queries (simulating ICMP-blocked middlebox)
	dnsDev := &mockDNSOnlyPacketDevice{
		srcIP: net.IPv4(10, 100, 0, 1),
		dstIP: net.IPv4(8, 8, 8, 8),
	}

	ctx := context.Background()
	// Probe with 600ms timeout: primary ICMP fails, secondary UDP DNS succeeds
	err := ProbePacketDevice(ctx, dnsDev, 600*time.Millisecond)
	if err != nil {
		t.Fatalf("expected secondary signal to succeed when primary ICMP fails, got: %v", err)
	}
}

type mockDNSOnlyPacketDevice struct {
	mu         sync.Mutex
	hooks      map[uint64]CanaryResponseHook
	nextHookID uint64
	srcIP      net.IP
	dstIP      net.IP
}

func (d *mockDNSOnlyPacketDevice) RegisterCanaryResponseHook(hook CanaryResponseHook) func() {
	d.mu.Lock()
	if d.hooks == nil {
		d.hooks = make(map[uint64]CanaryResponseHook)
	}
	d.nextHookID++
	id := d.nextHookID
	d.hooks[id] = hook
	d.mu.Unlock()
	return func() {
		d.mu.Lock()
		delete(d.hooks, id)
		d.mu.Unlock()
	}
}

func (d *mockDNSOnlyPacketDevice) Write(p []byte) (int, error) {
	// If packet is UDP DNS query (protocol 17, dst port 53)
	if len(p) >= 28 && p[0]>>4 == 4 && p[9] == 17 {
		ihl := int(p[0]&0x0f) * 4
		if len(p) >= ihl+8+12 {
			udpDstPort := binary.BigEndian.Uint16(p[ihl+2 : ihl+4])
			if udpDstPort == 53 {
				dnsID := binary.BigEndian.Uint16(p[ihl+8 : ihl+10])
				reply := BuildCanaryDNSResponse(d.dstIP, d.srcIP, dnsID)

				d.mu.Lock()
				hooksCopy := make([]CanaryResponseHook, 0, len(d.hooks))
				for _, h := range d.hooks {
					if h != nil {
						hooksCopy = append(hooksCopy, h)
					}
				}
				d.mu.Unlock()

				go func(resp []byte, hooks []CanaryResponseHook) {
					for _, h := range hooks {
						h(resp)
					}
				}(reply, hooksCopy)
			}
		}
	}
	// Drop ICMP packets completely (simulating ICMP filtering)
	return len(p), nil
}

func (d *mockDNSOnlyPacketDevice) Read([]byte) (int, error) { return 0, errors.New("not implemented") }
func (d *mockDNSOnlyPacketDevice) Close() error             { return nil }

// TestHealthCanary_MultiSignal_BothFail_ReturnsError tests HIGH 4:
// When both primary ICMP and secondary signals fail, data plane is declared dead.
func TestHealthCanary_MultiSignal_BothFail_ReturnsError(t *testing.T) {
	dev := &mockPacketDevice{} // answers nothing
	ctx := context.Background()

	err := ProbePacketDevice(ctx, dev, 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected error when both primary and secondary fail, got nil")
	}
}
