package orchestrator

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func probeTestEncodeKey(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// probeTestKeypair derives a deterministic WireGuard keypair through the same
// crypto path the production manager uses.
func probeTestKeypair(seed byte) (privB64, pubB64 string, err error) {
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = seed + byte(i)
	}
	privB64 = probeTestEncodeKey(priv)
	pubB64, err = health.ComputePublicKeyFromPrivate(privB64)
	if err != nil {
		return "", "", err
	}
	return privB64, pubB64, nil
}

// probeIdentityFakeManager mirrors the AWG manager's probe-registration contract,
// because that contract decides what the reachability prober can know about its own
// identity.
//
// A name-only probe registration makes the MANAGER generate the keypair. The
// private half is stored in the backend's clientsTable — the only place it survives
// a panel restart — and returned to the caller, so the cycle that created the peer
// can sign immediately and later cycles recover the same key.
type probeIdentityFakeManager struct {
	mu sync.Mutex

	serverPub string
	// stored is the backend-side clientsTable: where a probe private key survives
	// between cycles and across panel restarts.
	stored []map[string]any
	// registrations counts AddClient calls, i.e. backend churn.
	registrations int
	// peerOrder records the peer identity observed on each registration.
	peerOrder     []string
	getClientsErr error
	addClientErr  error
	// addClientEntered is signalled once a registration has begun.
	addClientEntered chan struct{}
	// addClientGate, when set, holds a registration open until closed.
	addClientGate chan struct{}
}

func newProbeIdentityFakeManager(serverPub string) *probeIdentityFakeManager {
	return &probeIdentityFakeManager{serverPub: serverPub}
}

func (m *probeIdentityFakeManager) GetServerPublicKey(ctx context.Context, server *models.Server) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.serverPub == "" {
		return "", errors.New("no server public key")
	}
	return m.serverPub, nil
}

func (m *probeIdentityFakeManager) GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getClientsErr != nil {
		return nil, m.getClientsErr
	}
	out := make([]map[string]any, 0, len(m.stored))
	for _, c := range m.stored {
		out = append(out, map[string]any{
			"clientId": c["clientId"],
			"userData": copyUserData(c["userData"]),
		})
	}
	return out, nil
}

func copyUserData(v any) map[string]any {
	ud, ok := v.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	out := make(map[string]any, len(ud))
	for k, val := range ud {
		out[k] = val
	}
	return out
}

// AddClient implements the probe-registration contract. Only name-only probe
// registration is exercised by the reachability path after the fix; a caller-key
// registration is still accepted so a regression to it stays observable.
func (m *probeIdentityFakeManager) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	if entered := m.addClientEntered; entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if gate := m.addClientGate; gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.addClientErr != nil {
		return nil, m.addClientErr
	}

	name := "client"
	if n, ok := clientParams["clientName"].(string); ok && n != "" {
		name = n
	}

	m.registrations++
	callerPub, _ := clientParams["public_key"].(string)
	if callerPub != "" {
		// Caller-key probe: no credential exists here at all.
		m.peerOrder = append(m.peerOrder, callerPub)
		for i := range m.stored {
			if m.stored[i]["clientId"] == callerPub {
				return map[string]any{
					"client_id":      callerPub,
					"client_name":    name,
					"client_pub_key": callerPub,
					"is_upsert":      true,
				}, nil
			}
		}
		m.stored = append(m.stored, map[string]any{
			"clientId": callerPub,
			"userData": map[string]any{
				"clientName": name,
				"clientIp":   "192.0.2.99",
			},
		})
		return map[string]any{
			"client_id":      callerPub,
			"client_name":    name,
			"client_pub_key": callerPub,
		}, nil
	}

	// Name-only probe: the manager owns the keypair and stores it in the backend's
	// clientsTable. The response carries no credential at all — the peer is
	// PSK-less and has no client config — so the caller must read it back.
	storedPriv := m.storedPrivateKeyLocked()
	if storedPriv != "" {
		pub, _ := m.stored[0]["clientId"].(string)
		m.peerOrder = append(m.peerOrder, pub)
		return map[string]any{
			"client_id":      pub,
			"client_name":    name,
			"client_pub_key": pub,
			"is_upsert":      true,
		}, nil
	}

	priv, pub, err := probeTestKeypair(byte(11 + m.registrations))
	if err != nil {
		return nil, err
	}
	m.peerOrder = append(m.peerOrder, pub)
	m.stored = append(m.stored, map[string]any{
		"clientId": pub,
		"userData": map[string]any{
			"clientName":       name,
			"clientPrivateKey": priv,
			"clientIp":         "192.0.2.99",
		},
	})
	return map[string]any{
		"client_id":      pub,
		"client_name":    name,
		"client_pub_key": pub,
	}, nil
}

func (m *probeIdentityFakeManager) registrationCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.registrations
}

func (m *probeIdentityFakeManager) setStore(entries []map[string]any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stored = entries
}

func (m *probeIdentityFakeManager) setAddClientErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addClientErr = err
}

func (m *probeIdentityFakeManager) storedPrivateKey() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.storedPrivateKeyLocked()
}

func (m *probeIdentityFakeManager) storedPrivateKeyLocked() string {
	for _, c := range m.stored {
		if ud := copyUserData(c["userData"]); ud["clientName"] == "Health Probe" {
			priv, _ := ud["clientPrivateKey"].(string)
			return priv
		}
	}
	return ""
}

// probeServer builds a server row whose AWG metadata carries only the port, so
// the reachability path must discover the public key and the identity itself.
func probeServer(t *testing.T, id int64) *models.Server {
	t.Helper()
	return &models.Server{
		ID:   id,
		Host: "192.0.2.20",
		Protocols: map[string]any{
			"awg": map[string]any{
				"port": "55424",
			},
		},
	}
}

func awgInfoFor(t *testing.T, server *models.Server) map[string]any {
	t.Helper()
	info, ok := server.Protocols["awg"].(map[string]any)
	if !ok {
		t.Fatalf("server %d has no awg metadata", server.ID)
	}
	return info
}

// newProbeIdentityOrchestrator wires the fake manager into a fresh orchestrator
// through the same protocol registry the production wiring uses.
func newProbeIdentityOrchestrator(t *testing.T, mgr *probeIdentityFakeManager) *Orchestrator {
	t.Helper()
	orch := New(nil, nil)
	reg := newMockOrchRegistry()
	reg.Register(&probeIdentityRegistryAdapter{mgr: mgr})
	orch.registry = reg
	return orch
}

// probeIdentityRegistryAdapter exposes the fake manager through the shared
// protocol-manager registry, as the production wiring does.
type probeIdentityRegistryAdapter struct {
	mgr *probeIdentityFakeManager
}

func (a *probeIdentityRegistryAdapter) Protocol() string { return "awg" }

func (a *probeIdentityRegistryAdapter) GetServerPublicKey(ctx context.Context, server *models.Server) (string, error) {
	return a.mgr.GetServerPublicKey(ctx, server)
}

func (a *probeIdentityRegistryAdapter) Install(ctx context.Context, server *models.Server, params map[string]any) error {
	return nil
}

func (a *probeIdentityRegistryAdapter) Uninstall(ctx context.Context, server *models.Server) error {
	return nil
}

func (a *probeIdentityRegistryAdapter) GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error) {
	return a.mgr.GetClients(ctx, server)
}

func (a *probeIdentityRegistryAdapter) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	return a.mgr.AddClient(ctx, server, clientParams)
}

func (a *probeIdentityRegistryAdapter) RemoveClient(ctx context.Context, server *models.Server, clientID string) error {
	return nil
}

func (a *probeIdentityRegistryAdapter) GetClientConfig(ctx context.Context, server *models.Server, clientID string) (string, error) {
	return "", nil
}

// TestReachability_FirstCycleResolvesUsableProbeIdentity is the first-cycle
// reachability contract.
//
// On a freshly installed backend nothing is stored for the "Health Probe" peer.
// The prober registers it and must come out of that same cycle with a private key
// it can sign with. A caller that expects a key it supplied, or that only reads a
// credential back on the NEXT cycle, has no identity at all on the first cycle — so
// the outer handshake is skipped against a backend whose peer is in fact
// registered.
func TestReachability_FirstCycleResolvesUsableProbeIdentity(t *testing.T) {
	mgr := newProbeIdentityFakeManager("server-pub-key-base64-value==")
	orch := newProbeIdentityOrchestrator(t, mgr)
	server := probeServer(t, 71)

	serverPub, clientPriv, psk := orch.resolveAWGProbeKeys(context.Background(), server, awgInfoFor(t, server))

	if clientPriv == "" {
		t.Fatal("first-cycle probe identity is empty: the outer handshake would be skipped despite a successful registration")
	}
	if serverPub == "" {
		t.Error("first-cycle server public key is empty")
	}
	if psk != "" {
		t.Errorf("a PSK-less probe peer must derive the handshake with an empty PSK; got %q", psk)
	}

	// The registered peer must be the public half of the key the prober signs with.
	derived, err := health.ComputePublicKeyFromPrivate(clientPriv)
	if err != nil {
		t.Fatalf("the resolved probe private key is not decodable: %v", err)
	}
	if stored := mgr.storedPrivateKey(); stored != clientPriv {
		t.Errorf("backend stores a different credential than the prober signs with: stored %q, signing %q", stored, clientPriv)
	}
	if regs := mgr.registrationCount(); regs != 1 {
		t.Errorf("expected exactly one registration on the first cycle, got %d", regs)
	}
	if len(mgr.peerOrder) == 0 || mgr.peerOrder[0] != derived {
		t.Errorf("registered peer %v is not the public half of the signing key %q", mgr.peerOrder, derived)
	}
}

// TestReachability_RegistrationResponseCarriesNoCredential pins the manager
// contract this resolution relies on: a probe registration stores the keypair
// backend-side and returns no credential, so the prober must read it back rather
// than expect it in the response.
func TestReachability_RegistrationResponseCarriesNoCredential(t *testing.T) {
	mgr := newProbeIdentityFakeManager("server-pub-key-base64-value==")
	orch := newProbeIdentityOrchestrator(t, mgr)
	server := probeServer(t, 91)

	_, clientPriv, _ := orch.resolveAWGProbeKeys(context.Background(), server, awgInfoFor(t, server))
	if clientPriv == "" {
		t.Fatal("no identity after a registration that returns no credential")
	}
	if stored := mgr.storedPrivateKey(); stored != clientPriv {
		t.Errorf("prober signs with %q but the backend stores %q", clientPriv, stored)
	}
	if regs := mgr.registrationCount(); regs != 1 {
		t.Errorf("expected one registration, got %d", regs)
	}
}

// TestReachability_RepeatedCyclesKeepIdentityAndRegistration drives the same
// resolution repeatedly, exactly as the periodic cycle does, and asserts the
// identity stays stable and the backend is not churned.
func TestReachability_RepeatedCyclesKeepIdentityAndRegistration(t *testing.T) {
	mgr := newProbeIdentityFakeManager("server-pub-key-base64-value==")
	orch := newProbeIdentityOrchestrator(t, mgr)
	server := probeServer(t, 72)
	ctx := context.Background()

	_, firstPriv, _ := orch.resolveAWGProbeKeys(ctx, server, awgInfoFor(t, server))
	if firstPriv == "" {
		t.Fatal("no identity on the first cycle")
	}
	for cycle := 2; cycle <= 5; cycle++ {
		_, priv, psk := orch.resolveAWGProbeKeys(ctx, server, awgInfoFor(t, server))
		if priv != firstPriv {
			t.Fatalf("cycle %d changed the probe identity: %q != %q", cycle, priv, firstPriv)
		}
		if psk != "" {
			t.Errorf("cycle %d used a PresharedKey for a PSK-less probe peer: %q", cycle, psk)
		}
	}
	if regs := mgr.registrationCount(); regs != 1 {
		t.Errorf("repeated cycles re-registered the probe peer: %d registrations, want 1", regs)
	}
}

// TestReachability_RestartReusesStoredIdentity covers a panel restart: the
// in-memory cache is gone, so the identity must be recovered from what the backend
// stores for the peer and must be the SAME key as before the restart. A fresh key
// would re-point the peer and invalidate the credential the backend just held.
func TestReachability_RestartReusesStoredIdentity(t *testing.T) {
	mgr := newProbeIdentityFakeManager("server-pub-key-base64-value==")
	ctx := context.Background()
	server := probeServer(t, 73)

	before := newProbeIdentityOrchestrator(t, mgr)
	_, privBefore, _ := before.resolveAWGProbeKeys(ctx, server, awgInfoFor(t, server))
	if privBefore == "" {
		t.Fatal("no identity before restart")
	}

	// A restart is a new orchestrator over the same backend state.
	after := newProbeIdentityOrchestrator(t, mgr)
	_, privAfter, pskAfter := after.resolveAWGProbeKeys(ctx, server, awgInfoFor(t, server))

	if privAfter != privBefore {
		t.Fatalf("restart changed the probe identity: %q != %q", privAfter, privBefore)
	}
	if pskAfter != "" {
		t.Errorf("restart used a PresharedKey for a PSK-less probe peer: %q", pskAfter)
	}
	if regs := mgr.registrationCount(); regs != 1 {
		t.Errorf("restart re-registered the probe peer: %d registrations, want 1", regs)
	}
}

// TestReachability_ReinstallRegistersFreshIdentity covers an AWG reinstall: the
// backend's clientsTable is gone, so the stored credential no longer exists. The
// prober must register a new identity and still come out with a signing key — not
// with an empty one that silently disables the outer probe.
func TestReachability_ReinstallRegistersFreshIdentity(t *testing.T) {
	mgr := newProbeIdentityFakeManager("server-pub-key-base64-value==")
	ctx := context.Background()
	server := probeServer(t, 74)

	first := newProbeIdentityOrchestrator(t, mgr)
	_, privBefore, _ := first.resolveAWGProbeKeys(ctx, server, awgInfoFor(t, server))
	if privBefore == "" {
		t.Fatal("no identity before reinstall")
	}

	// Reinstall wipes the backend's clientsTable; the panel's cache is gone too.
	mgr.setStore(nil)

	after := newProbeIdentityOrchestrator(t, mgr)
	_, privAfter, pskAfter := after.resolveAWGProbeKeys(ctx, server, awgInfoFor(t, server))
	if privAfter == "" {
		t.Fatal("no identity after reinstall: the outer handshake would be skipped")
	}
	if pskAfter != "" {
		t.Errorf("post-reinstall probe used a PresharedKey for a PSK-less peer: %q", pskAfter)
	}
	derived, err := health.ComputePublicKeyFromPrivate(privAfter)
	if err != nil {
		t.Fatalf("post-reinstall private key is not decodable: %v", err)
	}
	if regs := mgr.registrationCount(); regs != 2 {
		t.Fatalf("expected a fresh registration after the reinstall, got %d registrations", regs)
	}
	if last := mgr.peerOrder[len(mgr.peerOrder)-1]; last != derived {
		t.Errorf("post-reinstall registration %q is not the public half of the signing key %q", last, derived)
	}
}

// TestReachability_FailedRegistrationYieldsNoIdentity is the refusal control: when
// registration fails, the prober must report no identity so the caller falls back
// (TCP/SSH) instead of signing with a key the backend does not know.
func TestReachability_FailedRegistrationYieldsNoIdentity(t *testing.T) {
	mgr := newProbeIdentityFakeManager("server-pub-key-base64-value==")
	mgr.addClientErr = errors.New("ssh: connection closed")
	orch := newProbeIdentityOrchestrator(t, mgr)
	server := probeServer(t, 75)

	serverPub, clientPriv, psk := orch.resolveAWGProbeKeys(context.Background(), server, awgInfoFor(t, server))
	if clientPriv != "" {
		t.Fatalf("a failed registration must not produce an identity the backend never accepted, got %q", clientPriv)
	}
	if psk != "" {
		t.Errorf("a failed registration must not carry a PresharedKey, got %q", psk)
	}
	if serverPub == "" {
		t.Error("the server public key is independent of peer registration and should still resolve")
	}
	if regs := mgr.registrationCount(); regs != 0 {
		t.Errorf("no peer should have been registered, got %d registrations", regs)
	}

	// The failure must not poison the next cycle.
	mgr.setAddClientErr(nil)
	_, retryPriv, _ := orch.resolveAWGProbeKeys(context.Background(), server, awgInfoFor(t, server))
	if retryPriv == "" {
		t.Error("a cycle after the transport recovered must be able to resolve an identity")
	}
}

// TestReachability_StoredLegacyPeerKeepsItsPSK covers the compatibility case: a
// peer registered by the older server-PSK path holds the server PSK, so its
// handshake must keep deriving with it. The PSK policy travels with the identity;
// picking the wrong one makes the same registered peer reject the handshake.
func TestReachability_StoredLegacyPeerKeepsItsPSK(t *testing.T) {
	mgr := newProbeIdentityFakeManager("server-pub-key-base64-value==")
	legacyPriv, legacyPub, err := probeTestKeypair(40)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	const legacyPSK = "legacy-server-psk-value=="
	mgr.setStore([]map[string]any{{
		"clientId": legacyPub,
		"userData": map[string]any{
			"clientName":       "Health Probe",
			"clientPrivateKey": legacyPriv,
			"clientIp":         "192.0.2.99",
			"psk":              legacyPSK,
		},
	}})

	orch := newProbeIdentityOrchestrator(t, mgr)
	server := probeServer(t, 76)
	_, clientPriv, psk := orch.resolveAWGProbeKeys(context.Background(), server, awgInfoFor(t, server))

	if clientPriv != legacyPriv {
		t.Fatalf("stored legacy probe identity was not reused: got %q, want %q", clientPriv, legacyPriv)
	}
	if psk != legacyPSK {
		t.Errorf("stored legacy peer must keep deriving with the PSK it was registered with, got %q", psk)
	}
	if regs := mgr.registrationCount(); regs != 0 {
		t.Errorf("a stored identity must not be re-registered, got %d registrations", regs)
	}
}

// TestReachability_ConcurrentCyclesRegisterOnce hammers one server from many
// goroutines — the shape of overlapping cycles plus any concurrent consumer — and
// asserts they converge on one identity from one registration. Two independent
// registrations would leave the backend holding whichever landed last while one
// caller signed with the other.
func TestReachability_ConcurrentCyclesRegisterOnce(t *testing.T) {
	mgr := newProbeIdentityFakeManager("server-pub-key-base64-value==")
	gate := make(chan struct{})
	mgr.addClientGate = gate
	entered := make(chan struct{}, 1)
	mgr.addClientEntered = entered

	orch := newProbeIdentityOrchestrator(t, mgr)
	server := probeServer(t, 77)
	ctx := context.Background()

	const workers = 8
	privs := make([]string, workers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, priv, _ := orch.resolveAWGProbeKeys(ctx, server, awgInfoFor(t, server))
			privs[i] = priv
		}(i)
	}
	close(start)

	// Wait until a registration is actually in flight, then release it. Coalesced
	// callers wait inside the resolution; this is the interleaving under test.
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(gate)
		wg.Wait()
		t.Fatal("no registration was attempted")
	}
	close(gate)
	wg.Wait()

	first := privs[0]
	if first == "" {
		t.Fatal("concurrent resolution produced no identity")
	}
	for i, priv := range privs {
		if priv != first {
			t.Fatalf("worker %d resolved a different identity (%q != %q): the backend and the prober disagree about the peer", i, priv, first)
		}
	}
	if regs := mgr.registrationCount(); regs != 1 {
		t.Fatalf("concurrent cycles registered %d times, want exactly 1", regs)
	}
}

// TestReachability_CachedIdentityAvoidsBackendIO asserts the steady state: once an
// identity is resolved, repeated cycles do not touch the backend at all.
func TestReachability_CachedIdentityAvoidsBackendIO(t *testing.T) {
	mgr := newProbeIdentityFakeManager("server-pub-key-base64-value==")
	orch := newProbeIdentityOrchestrator(t, mgr)
	server := probeServer(t, 78)
	ctx := context.Background()

	if _, priv, _ := orch.resolveAWGProbeKeys(ctx, server, awgInfoFor(t, server)); priv == "" {
		t.Fatal("no identity on the first cycle")
	}
	// An unreachable backend must not matter once the identity is cached.
	mgr.mu.Lock()
	mgr.getClientsErr = errors.New("ssh: dial timeout")
	mgr.addClientErr = errors.New("ssh: dial timeout")
	mgr.mu.Unlock()

	_, priv, psk := orch.resolveAWGProbeKeys(ctx, server, awgInfoFor(t, server))
	if priv == "" {
		t.Fatal("a cached identity must survive backend unavailability")
	}
	if psk != "" {
		t.Errorf("cached PSK-less identity must keep the empty PSK, got %q", psk)
	}
}
