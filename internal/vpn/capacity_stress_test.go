package vpn

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
	"github.com/devops-igor/amnezia-web-ui-go/internal/vpn/loadbalancer"
)

// Concurrency stress test for issue #86: the backend capacity invariant.
//
// The check-then-allocate capacity pattern (FilterHealthy reads
// t.ActiveConnections, HandleIncomingPeer increments afterwards) is only
// safe because every production counter mutator serializes under the VPN
// service's single mutex s.mu. This test hammers that invariant the way a
// regression would break it: 200 goroutines fire concurrently into
// HandleIncomingPeer against a single-backend service with
// MaxPeersPerBackend set to a small k, all racing for the same gauge. If
// the select+increment sequence ever stops being serialized, two
// goroutines can both observe a below-cap snapshot and both increment,
// overshooting the cap.
//
// Note on reach: each distinct peer needs its own DB connection row and a
// sequential IPAM lease, so the observable steady state is
// active == cap (all connects succeed) or active < cap (some connects fail,
// e.g. IP-pool exhaustion). An overshoot (active > cap) is the failure this
// test exists to catch: its assertion runs after EVERY completed connect
// and from an observer goroutine sampling the gauge continuously while the
// connects are in flight, so a transient overshoot is visible too.
//
// Runtime: well under 1s even under -race (200 short DB-backed connects).

func TestHandleIncomingPeerCapacityStress(t *testing.T) {
	db := setupTestDB(t)

	const (
		peers    = 200
		capLimit = 6 // MaxPeersPerBackend: small on purpose — maximizes contention
	)

	svc, s1ID, _, _, _ := setupTestVPNService(t, db, func(c *models.VPNConfig) {
		c.MaxPeersPerBackend = capLimit
		c.MaxTotalPeers = peers
	})
	ctx := t.Context()

	// Single backend: every select that passes FilterHealthy contends on
	// exactly one gauge.
	tun := lbTunnel(t, svc, db, 971, "awg971", "pub971", "priv971", "10.9.9.171:51820")

	// 200 distinct users, each with one connection row (a distinct peer key),
	// so every goroutine drives a real, independent HandleIncomingPeer.
	peerKeys := make([]string, 0, peers)
	for i := 0; i < peers; i++ {
		uID, err := db.CreateUser(ctx, &models.User{
			Username: fmt.Sprintf("stress-user-%d", i),
			Enabled:  true,
		})
		if err != nil {
			t.Fatalf("CreateUser(%d): %v", i, err)
		}
		peerKey := fmt.Sprintf("stress-peer-key-%d", i)
		if _, err := db.CreateConnection(ctx, &models.UserConnection{
			UserID:   uID,
			ServerID: s1ID,
			Protocol: "awg",
			ClientID: peerKey,
			Name:     fmt.Sprintf("stress-device-%d", i),
		}); err != nil {
			t.Fatalf("CreateConnection(%d): %v", i, err)
		}
		peerKeys = append(peerKeys, peerKey)
	}

	snapshotGauge := func() (int, error) {
		cur, err := svc.pool.GetTunnelByID(tun.ID)
		if err != nil {
			return 0, err
		}
		return cur.ActiveConnections, nil
	}

	// Observer goroutine samples the gauge continuously while connects are
	// in flight; an overshoot at ANY point is recorded.
	stop := make(chan struct{})
	var overshoots []int
	var obsMu sync.Mutex
	observerDone := make(chan struct{})
	go func() {
		defer close(observerDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if active, err := snapshotGauge(); err == nil && active > capLimit {
				obsMu.Lock()
				overshoots = append(overshoots, active)
				obsMu.Unlock()
			}
		}
	}()

	var wg sync.WaitGroup
	errs := make(chan error, peers)
	var okMu sync.Mutex
	connected := 0
	for i := 0; i < peers; i++ {
		wg.Add(1)
		go func(pk string) {
			defer wg.Done()
			_, _, err := svc.HandleIncomingPeer(ctx, pk)
			if err != nil {
				// Capacity rejects are EXPECTED once the cap is reached —
				// ErrNoActiveBackends from FilterHealthy is exactly the
				// mechanism that enforces the cap. Anything else fails.
				if !errors.Is(err, loadbalancer.ErrNoActiveBackends) && !errors.Is(err, loadbalancer.ErrCapacityExceeded) {
					errs <- fmt.Errorf("peer %s: %w", pk, err)
				}
				return
			}
			okMu.Lock()
			connected++
			okMu.Unlock()
			// Post-connect snapshot: the gauge must never have grown past
			// the cap as a result of this connect either.
			active, err := snapshotGauge()
			if err != nil {
				errs <- fmt.Errorf("peer %s: %w", pk, err)
				return
			}
			if active > capLimit {
				errs <- fmt.Errorf("peer %s: gauge %d exceeds cap %d after connect", pk, active, capLimit)
			}
		}(peerKeys[i])
	}
	wg.Wait()
	close(stop)
	<-observerDone
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	obsMu.Lock()
	defer obsMu.Unlock()
	for _, v := range overshoots {
		t.Errorf("observed ActiveConnections=%d > cap %d mid-flight", v, capLimit)
	}

	active, err := snapshotGauge()
	if err != nil {
		t.Fatalf("final gauge snapshot: %v", err)
	}
	if active > capLimit {
		t.Fatalf("final gauge %d exceeds MaxPeersPerBackend cap %d", active, capLimit)
	}
	// Consistency: the gauge must equal exactly the number of accepted
	// connects — every success is one serialized increment, every capacity
	// reject contributed nothing.
	if active != connected {
		t.Errorf("gauge %d != connected %d (counter drifted from live sessions)", active, connected)
	}
	if connected == 0 {
		t.Errorf("no connects accepted; stress exercised nothing (cap=%d, peers=%d)", capLimit, peers)
	}
	t.Logf("stress done: %d concurrent HandleIncomingPeer against cap=%d, accepted=%d, final gauge=%d", peers, capLimit, connected, active)
}
