package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

func TestAudit713RecoveryRequiresWorkingDataPlane(t *testing.T) {
	db := setupTestDB(t)
	ctx := t.Context()
	pool := NewPool(db)
	sid, err := db.CreateServer(ctx, &models.Server{Name: "recovery", Host: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := pool.AddTunnel(ctx, sid, "192.0.2.10:51820", "probe-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.SetTunnelStatus(ctx, sid, models.TunnelStatusHandshakeBlocked, 20); err != nil {
		t.Fatal(err)
	}
	hp := NewHealthProber(pool, db, DefaultHealthConfig(), func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	})
	calls := 0
	hp.SetCanaryProbeFunc(func(context.Context, *models.BackendTunnel) error {
		calls++
		return errors.New("data peer payload blackhole")
	})
	// An attached device passes the existing onActiveHook without proving any payload transit.
	hp.SetOnActiveHook(func(context.Context, *models.BackendTunnel) error { return nil })
	_, probeErr := hp.ProbeTunnel(ctx, tun)
	got, _ := pool.GetTunnel(sid)
	persisted, _ := db.GetBackendTunnel(ctx, tun.ID)
	t.Logf("outer=success inner=blackhole canary_calls=%d err=%v pool=%s db=%s new_candidates=%d", calls, probeErr, got.Status, persisted.Status, len(pool.GetActiveTunnels()))
	if got.Status == models.TunnelStatusActive || persisted.Status == models.TunnelStatusActive {
		t.Error("unverified/broken data plane was advertised active to new peers")
	}
}

type auditDNSDevice struct {
	*AWGClientDevice
	mu      sync.Mutex
	queries [][]byte
	sent    bool
}

func (d *auditDNSDevice) Write(p []byte) (int, error) {
	if len(p) >= 40 && p[9] == 17 {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.queries = append(d.queries, append([]byte(nil), p...))
		if len(d.queries) == 2 && !d.sent {
			d.sent = true
			// Both legitimate responses arrive before either waiter gets CPU.
			for _, q := range d.queries {
				id := binary.BigEndian.Uint16(q[28:30])
				resp := BuildCanaryDNSResponse(net.IP(q[16:20]), net.IP(q[12:16]), id)
				// A normal NXDOMAIN response retains the full question and has no answer records.
				resp = append(resp[:28], q[28:]...)
				binary.BigEndian.PutUint16(resp[2:4], uint16(len(resp)))
				binary.BigEndian.PutUint16(resp[24:26], uint16(len(resp)-20))
				binary.BigEndian.PutUint16(resp[30:32], 0x8183)
				binary.BigEndian.PutUint16(resp[10:12], 0)
				binary.BigEndian.PutUint16(resp[10:12], internetChecksum(resp[:20]))
				if _, err := d.vtun.Write([][]byte{resp}, 0); err != nil {
					return 0, err
				}
			}
		}
	}
	return len(p), nil
}

func TestAudit713SecondaryDNSConcurrentActualDemux(t *testing.T) {
	// No encrypted engine/network: actual AWG Read/demux and VirtualTUN, synthetic decrypted DNS arrivals.
	collisions := 0
	failures := 0
	for attempt := 0; attempt < 12; attempt++ {
		vt, err := virtualtun.New(virtualtun.Config{Name: "audit-dns", MTU: 1340, InboundCapacity: 16, OutboundCapacity: 16})
		if err != nil {
			t.Fatal(err)
		}
		d := &auditDNSDevice{AWGClientDevice: &AWGClientDevice{vtun: vt, doneCh: make(chan struct{})}}
		readerDone := make(chan struct{})
		go func() {
			defer close(readerDone)
			b := make([]byte, 1500)
			for {
				if _, err := d.Read(b); err != nil {
					return
				}
			}
		}()
		errs := make(chan error, 2)
		for i := 0; i < 2; i++ {
			go func() { errs <- ProbePacketDevice(context.Background(), d, 80*time.Millisecond) }()
		}
		for i := 0; i < 2; i++ {
			if err := <-errs; err != nil {
				failures++
			}
		}
		d.mu.Lock()
		if len(d.queries) != 2 {
			t.Fatalf("expected two fallback DNS queries, got %d", len(d.queries))
		}
		a, b := d.queries[0], d.queries[1]
		if binary.BigEndian.Uint16(a[28:30]) == binary.BigEndian.Uint16(b[28:30]) && binary.BigEndian.Uint16(a[20:22]) == binary.BigEndian.Uint16(b[20:22]) {
			collisions++
		}
		d.mu.Unlock()
		_ = d.Close()
		<-readerDone
	}
	t.Logf("attempts=12 colliding_DNS_tuples=%d false_timeouts=%d (two valid replies each attempt)", collisions, failures)
	if collisions > 0 {
		t.Error("concurrent fallback probes reuse the DNS transaction/source-port tuple")
	}
	if failures > 0 {
		t.Error("actual first-consumer AWG demux starved a live fallback probe")
	}
}

func TestAudit713DNSCollisionDisablesViableBlockedTunnel(t *testing.T) {
	disabled := 0
	for attempt := 0; attempt < 6; attempt++ {
		db := setupTestDB(t)
		ctx := t.Context()
		pool := NewPool(db)
		sid, err := db.CreateServer(ctx, &models.Server{Name: "dns-state", Host: "192.0.2.20"})
		if err != nil {
			t.Fatal(err)
		}
		tun, err := pool.AddTunnel(ctx, sid, "192.0.2.20:51820", "key")
		if err != nil {
			t.Fatal(err)
		}
		if err := pool.SetTunnelStatus(ctx, sid, models.TunnelStatusHandshakeBlocked, 20); err != nil {
			t.Fatal(err)
		}
		vt, err := virtualtun.New(virtualtun.Config{Name: "audit-dns-state", MTU: 1340, InboundCapacity: 16, OutboundCapacity: 16})
		if err != nil {
			t.Fatal(err)
		}
		dev := &auditDNSDevice{AWGClientDevice: &AWGClientDevice{vtun: vt, doneCh: make(chan struct{})}}
		readerDone := make(chan struct{})
		go func() {
			defer close(readerDone)
			b := make([]byte, 1500)
			for {
				if _, err := dev.Read(b); err != nil {
					return
				}
			}
		}()
		cfg := DefaultHealthConfig()
		cfg.Timeout = 80 * time.Millisecond
		cfg.FailureThreshold = 1
		hp := NewHealthProber(pool, db, cfg, func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
			return 0, errors.New("outer DPI drop")
		})
		hp.RegisterDevice(tun.ID, dev)
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = hp.ProbeTunnel(ctx, tun)
			}()
		}
		wg.Wait()
		got, _ := pool.GetTunnel(sid)
		stored, _ := db.GetBackendTunnel(ctx, tun.ID)
		if got.Status == models.TunnelStatusDisabled && stored.Status == models.TunnelStatusDisabled && stored.DisableReason == models.DisableReasonHealth {
			disabled++
		}
		_ = dev.Close()
		<-readerDone
	}
	t.Logf("attempts=6 viable_DNS_replies_per_attempt=2 pool_and_SQLite_false_disabled_health=%d", disabled)
	if disabled > 0 {
		t.Error("working DNS data plane was persisted disabled/health after concurrent fallback")
	}
}

func TestAudit713ICMPConcurrentExactIdentity(t *testing.T) {
	const n = 100
	seen := map[uint32]bool{}
	for i := 0; i < n; i++ {
		a, b := nextCanaryIDAndSeq()
		k := uint32(a)<<16 | uint32(b)
		if seen[k] {
			t.Fatal("duplicate ICMP identity")
		}
		seen[k] = true
	}
	t.Logf("%d consecutive ICMP identities unique", n)
}

func TestAudit713DNSFallbackOwnResponseMatching(t *testing.T) {
	a, b := nextCanaryIDAndSeq()
	c, d := nextCanaryIDAndSeq()
	_, _ = b, d
	response := BuildCanaryDNSResponse(net.IPv4(8, 8, 8, 8), net.IPv4(10, 100, 0, 1), a)
	matchesOther := IsCanaryDNSResponseMatching(response, net.IPv4(8, 8, 8, 8), net.IPv4(10, 100, 0, 1), c)
	t.Logf("independent_secDNSID=%d,%d response_to_A_matches_B=%t", a, c, matchesOther)
	if matchesOther {
		t.Error("reply for one outstanding probe satisfies another outstanding probe")
	}
}

func TestAudit713ICMPRejectsWrongEndpointAndChecksum(t *testing.T) {
	a, b := nextCanaryIDAndSeq()
	src, dst := net.IPv4(1, 1, 1, 1), net.IPv4(10, 100, 0, 1)
	p := BuildCanaryICMPEchoReply(src, dst, a, b)
	if !IsCanaryEchoReplyMatching(p, src, dst, a, b) {
		t.Fatal("valid reply rejected")
	}
	if IsCanaryEchoReplyMatching(p, net.IPv4(8, 8, 8, 8), dst, a, b) {
		t.Fatal("wrong endpoint accepted")
	}
	p[22] ^= 1
	if IsCanaryEchoReplyMatching(p, src, dst, a, b) {
		t.Fatal("bad checksum accepted")
	}
}
