package orchestrator

import (
	"context"
	"errors"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestReachability_WarmCacheSurvivesUnchangedServerIdentity pins the cache's
// purpose: while the server identity is unchanged, a warm orchestrator must not
// re-read or re-register the backend.
func TestReachability_WarmCacheSurvivesUnchangedServerIdentity(t *testing.T) {
	mgr := newProbeIdentityFakeManager("server-pub-key-A==")
	orch := newProbeIdentityOrchestrator(t, mgr)
	ctx := context.Background()
	server := probeServer(t, 92)

	_, first, _ := orch.resolveAWGProbeKeys(ctx, server, awgInfoFor(t, server))
	if first == "" {
		t.Fatal("no identity on the first cycle")
	}
	// The next cycle receives the same server row (same public key).
	info := awgInfoFor(t, server)
	info["public_key"] = "server-pub-key-A=="

	mgr.mu.Lock()
	mgr.getClientsErr = errors.New("ssh: dial timeout")
	mgr.addClientErr = errors.New("ssh: dial timeout")
	mgr.mu.Unlock()

	_, second, _ := orch.resolveAWGProbeKeys(ctx, server, info)
	if second != first {
		t.Fatalf("an unchanged server identity must keep the warm identity: %q != %q", second, first)
	}
	if regs := mgr.registrationCount(); regs != 1 {
		t.Errorf("an unchanged server identity must not re-register, got %d registrations", regs)
	}
}

// TestReachability_ReinstallInvalidatesWarmCache is the named test/awg-install-
// lifecycle boundary for the warm cache.
//
// A probe8-style cache returns immediately when a private key exists. That is
// correct while the backend is the same, but an AWG REINSTALL replaces the
// server identity: new server keypair, new clientsTable, and the probe peer the
// cache remembers no longer exists. If the cache survives it, the same warm
// orchestrator keeps signing with a key the reinstalled backend never registered,
// and every cycle after the reinstall reports the outer handshake as failed
// against a backend that is actually healthy — indefinitely, because nothing
// clears the entry.
func TestReachability_ReinstallInvalidatesWarmCache(t *testing.T) {
	mgr := newProbeIdentityFakeManager("server-pub-key-A==")
	orch := newProbeIdentityOrchestrator(t, mgr)
	ctx := context.Background()
	server := probeServer(t, 93)

	_, before, _ := orch.resolveAWGProbeKeys(ctx, server, awgInfoFor(t, server))
	if before == "" {
		t.Fatal("no identity before the reinstall")
	}
	if regs := mgr.registrationCount(); regs != 1 {
		t.Fatalf("expected one registration before the reinstall, got %d", regs)
	}

	// Reinstall, observed as the SAME warm orchestrator: the backend's store is
	// gone, its clientsTable is empty, and the server row now reports a NEW
	// server public key.
	mgr.setStore(nil)
	mgr.mu.Lock()
	mgr.serverPub = "server-pub-key-B=="
	mgr.mu.Unlock()
	info := awgInfoFor(t, server)
	info["public_key"] = "server-pub-key-B=="

	serverPub, after, psk := orch.resolveAWGProbeKeys(ctx, server, info)
	if after == "" {
		t.Fatal("a reinstalled backend left the warm cache holding an identity the backend never registered")
	}
	if after == before {
		t.Fatal("the warm cache kept the pre-reinstall identity across a new server identity")
	}
	if serverPub != "server-pub-key-B==" {
		t.Errorf("the cached server key survived the reinstall: got %q, want the reinstalled %q", serverPub, "server-pub-key-B==")
	}
	if psk != "" {
		t.Errorf("post-reinstall probe used a PresharedKey for a PSK-less peer: %q", psk)
	}
	if regs := mgr.registrationCount(); regs != 2 {
		t.Fatalf("the reinstall must re-register the probe peer once, got %d registrations", regs)
	}
	derived, err := health.ComputePublicKeyFromPrivate(after)
	if err != nil {
		t.Fatalf("post-reinstall key is not decodable: %v", err)
	}
	if last := mgr.peerOrder[len(mgr.peerOrder)-1]; last != derived {
		t.Errorf("post-reinstall registration %q is not the public half of the signing key %q", last, derived)
	}
	// The new credential must be what the backend now stores, so the next cycle
	// reads the same identity rather than minting yet another one.
	if stored := mgr.storedPrivateKey(); stored != after {
		t.Errorf("backend stores %q but the prober signs with %q", stored, after)
	}
}

// TestReachability_ServerKeyRotationInvalidatesWarmCache covers the same fence
// from the rotation direction: the server row reports a different public key, so
// the cached identity belongs to a peer the backend no longer authenticates.
func TestReachability_ServerKeyRotationInvalidatesWarmCache(t *testing.T) {
	mgr := newProbeIdentityFakeManager("server-pub-key-A==")
	orch := newProbeIdentityOrchestrator(t, mgr)
	ctx := context.Background()
	server := probeServer(t, 94)

	_, before, _ := orch.resolveAWGProbeKeys(ctx, server, awgInfoFor(t, server))
	if before == "" {
		t.Fatal("no identity before rotation")
	}

	info := awgInfoFor(t, server)
	info["public_key"] = "server-pub-key-ROTATED=="
	serverPub, after, _ := orch.resolveAWGProbeKeys(ctx, server, info)

	if serverPub != "server-pub-key-ROTATED==" {
		t.Errorf("rotation kept the stale server key: got %q", serverPub)
	}
	if after == "" {
		t.Error("no identity after rotation")
	}
}

// TestReachability_UnavailableServerKeyKeepsWarmIdentity is the refusal-to-churn
// control: when the server row carries NO public key, that is absence of new
// information, not evidence of a new identity. It must not invalidate a working
// identity, or every cycle on a partially-populated row would re-register the
// peer.
func TestReachability_UnavailableServerKeyKeepsWarmIdentity(t *testing.T) {
	mgr := newProbeIdentityFakeManager("server-pub-key-A==")
	orch := newProbeIdentityOrchestrator(t, mgr)
	ctx := context.Background()
	server := probeServer(t, 95)

	_, first, _ := orch.resolveAWGProbeKeys(ctx, server, awgInfoFor(t, server))
	if first == "" {
		t.Fatal("no identity on the first cycle")
	}
	if regs := mgr.registrationCount(); regs != 1 {
		t.Fatalf("expected one registration, got %d", regs)
	}

	// Same server, but the row no longer carries a public key.
	mgr.mu.Lock()
	mgr.getClientsErr = errors.New("ssh: dial timeout")
	mgr.addClientErr = errors.New("ssh: dial timeout")
	mgr.mu.Unlock()
	_, second, _ := orch.resolveAWGProbeKeys(ctx, server, map[string]any{"port": "55424"})

	if second != first {
		t.Fatalf("an absent server key must not invalidate a working identity: %q != %q", second, first)
	}
	if regs := mgr.registrationCount(); regs != 1 {
		t.Errorf("an absent server key caused re-registration (%d total)", regs)
	}
}

// TestReachability_CacheIsPerServer keeps the fence from over-reaching: resolving
// one server must never disturb another server's warm identity.
func TestReachability_CacheIsPerServer(t *testing.T) {
	mgr := newProbeIdentityFakeManager("server-pub-key-A==")
	orch := newProbeIdentityOrchestrator(t, mgr)
	ctx := context.Background()

	first := probeServer(t, 96)
	_, privFirst, _ := orch.resolveAWGProbeKeys(ctx, first, awgInfoFor(t, first))
	if privFirst == "" {
		t.Fatal("no identity for the first server")
	}

	second := probeServer(t, 97)
	_, privSecond, _ := orch.resolveAWGProbeKeys(ctx, second, awgInfoFor(t, second))
	if privSecond == "" {
		t.Fatal("no identity for the second server")
	}

	// Re-resolve both; each must keep its own identity.
	_, again1, _ := orch.resolveAWGProbeKeys(ctx, first, awgInfoFor(t, first))
	_, again2, _ := orch.resolveAWGProbeKeys(ctx, second, awgInfoFor(t, second))
	if again1 != privFirst || again2 != privSecond {
		t.Fatalf("per-server identities were disturbed: %q/%q then %q/%q", privFirst, privSecond, again1, again2)
	}
}

var _ = models.Server{}
