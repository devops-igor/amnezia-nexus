package vpn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

type mockAWGStatusProvider struct {
	status map[string]any
	err    error
}

func (m *mockAWGStatusProvider) GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error) {
	return m.status, m.err
}

func TestEnableBackend_DynamicFallback(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	ctx := context.Background()

	// 1. Server with no AWG in DB, but awgProvider discovers it running
	srvID, err := db.CreateServer(ctx, &models.Server{
		Name:      "dynamic-awg-host",
		Host:      "198.51.100.20",
		Protocols: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	mockProv := &mockAWGStatusProvider{
		status: map[string]any{
			"container_running": true,
			"port":              51820,
			"public_key":        "dynamic-discovered-pubkey",
			"psk":               "dynamic-psk",
			"awg_params": map[string]string{
				"H1": "1",
			},
		},
	}
	svc.SetAWGStatusProvider(mockProv)

	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("EnableBackend with dynamic fallback failed: %v", err)
	}

	// Verify DB record was updated
	srv, err := db.GetServerByID(ctx, srvID)
	if err != nil {
		t.Fatalf("GetServerByID failed: %v", err)
	}
	awgInfo, ok := srv.Protocols["awg"].(map[string]any)
	if !ok {
		t.Fatalf("expected awg in srv.Protocols, got: %+v", srv.Protocols)
	}
	if installed, _ := awgInfo["installed"].(bool); !installed {
		t.Errorf("expected installed true, got: %v", awgInfo["installed"])
	}
	if awgInfo["public_key"] != "dynamic-discovered-pubkey" {
		t.Errorf("expected public_key dynamic-discovered-pubkey, got: %v", awgInfo["public_key"])
	}
	if fmt.Sprint(awgInfo["port"]) != "51820" {
		t.Errorf("expected port 51820, got: %v", awgInfo["port"])
	}

	// Verify backend tunnel exists and is active
	backends, err := svc.GetBackends(ctx)
	if err != nil {
		t.Fatalf("GetBackends failed: %v", err)
	}
	var found bool
	for _, b := range backends {
		if b.ServerID == srvID {
			found = true
			if b.Status != TunnelStatusActive {
				t.Errorf("expected tunnel status active, got %s", b.Status)
			}
			if b.PublicKey != "dynamic-discovered-pubkey" {
				t.Errorf("expected tunnel pubkey dynamic-discovered-pubkey, got %s", b.PublicKey)
			}
		}
	}
	if !found {
		t.Errorf("expected backend tunnel for server %d in backends list", srvID)
	}

	// 2. Server where AWG is NOT running
	srvNoAWGID, err := db.CreateServer(ctx, &models.Server{
		Name:      "not-running-host",
		Host:      "198.51.100.21",
		Protocols: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	svc.SetAWGStatusProvider(&mockAWGStatusProvider{
		status: map[string]any{
			"container_running": false,
		},
	})
	if err := svc.EnableBackend(ctx, srvNoAWGID); err == nil {
		t.Error("expected EnableBackend to fail when container is not running")
	}

	// 3. Provider returns error
	svc.SetAWGStatusProvider(&mockAWGStatusProvider{
		err: errors.New("ssh connection failed"),
	})
	if err := svc.EnableBackend(ctx, srvNoAWGID); err == nil {
		t.Error("expected EnableBackend to fail when provider returns error")
	}
}

type mockAWGManagerWithClientAdder struct {
	status         map[string]any
	statusErr      error
	addedClients   []map[string]any
	addClientErr   error
	addClientCalls int
	onAddClient    func()
}

func (m *mockAWGManagerWithClientAdder) GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error) {
	return m.status, m.statusErr
}

func (m *mockAWGManagerWithClientAdder) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	m.addClientCalls++
	m.addedClients = append(m.addedClients, clientParams)
	if m.onAddClient != nil {
		m.onAddClient()
	}
	if m.addClientErr != nil {
		return nil, m.addClientErr
	}
	return map[string]any{"client_id": clientParams["client_public_key"]}, nil
}

// TestEnableBackend_RegistersProberPeerOnBackend asserts the WIRING only:
// EnableBackend registers BOTH portal peers on the backend via AddClient —
// the DATA device peer (identity derive(PrivateKey), allowed_ips 0.0.0.0/0)
// first, then the dedicated probe peer (identity derive(ProbePrivateKey),
// no allowed_ips key). It uses a MOCK AddClient, so it cannot verify what the
// real manager does with those params (round-2 review: a mock asserting its
// own inputs is a false positive). The real-path coverage — [Peer] PublicKey
// == caller-supplied key, no PresharedKey, idempotent re-registration — lives
// in awg_probe_rework_test.go (TestAWGManager_AddClient_ProbePeerUsesCallerKey_R3),
// and the real-container acceptance test lives in
// awg_container_integration_test.go (TestAWGRealContainer_HandshakeWithPSKLessProbePeer).
func TestEnableBackend_RegistersProberPeerOnBackend(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	srvID, err := db.CreateServer(ctx, &models.Server{
		Name: "awg-peer-reg-server",
		Host: "198.51.100.30",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": "server-endpoint-pubkey",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	adder := &mockAWGManagerWithClientAdder{}
	svc.SetAWGStatusProvider(adder)

	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("EnableBackend failed: %v", err)
	}

	// Issue #43 key separation: exactly two registrations — DATA plane first,
	// health probe second.
	if adder.addClientCalls != 2 {
		t.Fatalf("expected 2 AddClient calls, got %d", adder.addClientCalls)
	}
	if len(adder.addedClients) != 2 {
		t.Fatalf("expected 2 added clients, got %d", len(adder.addedClients))
	}
	dataParams := adder.addedClients[0]
	probeParams := adder.addedClients[1]

	if dataParams["clientName"] != "Portal Data Plane" {
		t.Errorf("expected first clientName 'Portal Data Plane', got: %v", dataParams["clientName"])
	}
	if probeParams["clientName"] != "Portal Health Probe" {
		t.Errorf("expected second clientName 'Portal Health Probe', got: %v", probeParams["clientName"])
	}

	tun, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}

	// DATA peer: identity = derive(PrivateKey), allowed_ips = portal subnet (never 0.0.0.0/0).
	dataPub, ok := dataParams["client_public_key"].(string)
	if !ok || len(dataPub) == 0 {
		t.Fatalf("missing or empty client_public_key in data params: %+v", dataParams)
	}
	derivedDataPub, err := health.ComputePublicKeyFromPrivate(tun.PrivateKey)
	if err != nil {
		t.Fatalf("ComputePublicKeyFromPrivate (data) failed: %v", err)
	}
	if dataPub != derivedDataPub {
		t.Errorf("registered data public key %s does not match tunnel-derived data pubkey %s", dataPub, derivedDataPub)
	}
	if aip, ok := dataParams["allowed_ips"]; !ok || aip != "10.100.0.0/16" {
		t.Errorf("expected data peer allowed_ips '10.100.0.0/16', got: %v", dataParams["allowed_ips"])
	}
	if aip, ok := dataParams["allowed_ips"]; ok && aip == "0.0.0.0/0" {
		t.Errorf("data peer allowed_ips must NEVER be 0.0.0.0/0 (causes routing hijack on reboot)")
	}

	// PROBE peer: identity = derive(ProbePrivateKey), distinct from data key,
	// and NO allowed_ips key at all (manager defaults it to clientIP/32).
	probePub, ok := probeParams["client_public_key"].(string)
	if !ok || len(probePub) == 0 {
		t.Fatalf("missing or empty client_public_key in probe params: %+v", probeParams)
	}
	if tun.ProbePrivateKey == "" {
		t.Fatalf("tunnel must carry a dedicated probe private key after EnableBackend")
	}
	derivedProbePub, err := health.ComputePublicKeyFromPrivate(tun.ProbePrivateKey)
	if err != nil {
		t.Fatalf("ComputePublicKeyFromPrivate (probe) failed: %v", err)
	}
	if probePub != derivedProbePub {
		t.Errorf("registered probe public key %s does not match tunnel-derived probe pubkey %s", probePub, derivedProbePub)
	}
	if probePub == dataPub {
		t.Errorf("probe public key must differ from data public key (key separation is the whole fix)")
	}
	if aip, present := probeParams["allowed_ips"]; present {
		t.Errorf("probe peer must carry NO allowed_ips key (defaults to clientIP/32), got: %v", aip)
	}
}

func TestRegisterBackendPortalPeers_CustomSubnet(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	svc.cfg = &models.VPNConfig{SubnetCIDR: "10.200.0.0/16"}
	ctx := context.Background()

	srvID, err := db.CreateServer(ctx, &models.Server{
		Name: "awg-custom-subnet-server",
		Host: "198.51.100.44",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": "server-endpoint-pubkey-custom",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	adder := &mockAWGManagerWithClientAdder{}
	svc.SetAWGStatusProvider(adder)

	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("EnableBackend failed: %v", err)
	}

	if len(adder.addedClients) < 1 {
		t.Fatalf("expected at least 1 added client, got %d", len(adder.addedClients))
	}
	dataParams := adder.addedClients[0]
	if aip, ok := dataParams["allowed_ips"]; !ok || aip != "10.200.0.0/16" {
		t.Errorf("expected custom portal subnet '10.200.0.0/16', got: %v", dataParams["allowed_ips"])
	}
	if aip, ok := dataParams["allowed_ips"]; ok && aip == "0.0.0.0/0" {
		t.Errorf("portal data plane peer must never receive 0.0.0.0/0")
	}
}

func TestEnableBackend_AddClientErrorFailsLoudly(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	srvID, err := db.CreateServer(ctx, &models.Server{
		Name: "awg-peer-reg-err-server",
		Host: "198.51.100.31",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": "server-endpoint-pubkey-2",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	adder := &mockAWGManagerWithClientAdder{
		addClientErr: errors.New("remote SSH connection refused"),
	}
	svc.SetAWGStatusProvider(adder)

	// EnableBackend must fail loudly when AddClient fails, and not mark the tunnel active
	if err := svc.EnableBackend(ctx, srvID); err == nil {
		t.Fatal("expected EnableBackend to fail when AddClient fails, got nil")
	}

	if adder.addClientCalls != 1 {
		t.Errorf("expected 1 AddClient call attempt, got %d", adder.addClientCalls)
	}

	tun, err := svc.pool.GetTunnel(srvID)
	if err != nil || tun == nil {
		t.Fatalf("expected tunnel in pool, got %+v (err=%v)", tun, err)
	}
	if tun.Status == "active" {
		t.Errorf("expected tunnel not to be active after failed registration, got %s", tun.Status)
	}
	if tun.Status != "degraded" {
		t.Errorf("expected tunnel to be degraded after failed registration, got %s", tun.Status)
	}
}

func TestEnableBackend_UpdateBackendTunnelErrorAbortsAndLeavesStateIntact(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	initialHost := "198.51.100.45"
	initialPort := 51820
	initialPub := "server-endpoint-pubkey-initial"

	srvID, err := db.CreateServer(ctx, &models.Server{
		Name: "persist-fault-server",
		Host: initialHost,
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       initialPort,
				"public_key": initialPub,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	adder := &mockAWGManagerWithClientAdder{}
	svc.SetAWGStatusProvider(adder)

	// 1. Initial EnableBackend establishes tunnel in pool and DB
	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("initial EnableBackend failed: %v", err)
	}

	initialTun, err := svc.pool.GetTunnel(srvID)
	if err != nil || initialTun == nil {
		t.Fatalf("expected initial tunnel in pool, got %+v (err=%v)", initialTun, err)
	}
	expectedInitialEndpoint := "198.51.100.45:51820"
	if initialTun.Endpoint != expectedInitialEndpoint || initialTun.PublicKey != initialPub {
		t.Fatalf("initial tunnel mismatch: endpoint=%s, pub=%s", initialTun.Endpoint, initialTun.PublicKey)
	}
	initialPrivKey := initialTun.PrivateKey
	initialProbePrivKey := initialTun.ProbePrivateKey
	initialVersion := initialTun.StateVersion

	// 2. Update server configuration in DB with new host, port, and public key
	newHost := "198.51.100.46"
	newPort := 51822
	newPub := "server-endpoint-pubkey-updated"
	if err := db.UpdateServer(ctx, srvID, map[string]any{"host": newHost}); err != nil {
		t.Fatalf("UpdateServer host failed: %v", err)
	}
	if err := db.UpdateServerProtocols(ctx, srvID, map[string]any{
		"awg": map[string]any{
			"installed":  true,
			"port":       newPort,
			"public_key": newPub,
		},
	}); err != nil {
		t.Fatalf("UpdateServerProtocols failed: %v", err)
	}

	// 3. Trigger context cancellation right before pool.AddTunnel inside EnableBackend
	reqCtx, cancelReq := context.WithCancel(ctx)
	svc.SetEnableBackendPreAddTunnelHookForTest(func() {
		cancelReq()
	})

	initialClientAddCount := adder.addClientCalls

	// EnableBackend must fail when AddTunnel's DB persistence fails
	err = svc.EnableBackend(reqCtx, srvID)
	if err == nil {
		t.Fatal("expected EnableBackend to fail when DB persistence fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed to register backend tunnel") {
		t.Errorf("expected error wrapping failed to register backend tunnel, got: %v", err)
	}
	if !strings.Contains(err.Error(), "failed to persist backend tunnel updates") {
		t.Errorf("expected error wrapping failed to persist backend tunnel updates, got: %v", err)
	}

	// Verify AddClient was not called during this aborted round
	if adder.addClientCalls != initialClientAddCount {
		t.Errorf("AddClient was called %d times; expected no new calls on aborted update", adder.addClientCalls-initialClientAddCount)
	}

	// Verify in-memory pool state is completely untouched
	curTun, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if curTun.Endpoint != expectedInitialEndpoint {
		t.Errorf("in-memory endpoint mutated on DB failure: got %q, want %q", curTun.Endpoint, expectedInitialEndpoint)
	}
	if curTun.PublicKey != initialPub {
		t.Errorf("in-memory public key mutated on DB failure: got %q, want %q", curTun.PublicKey, initialPub)
	}
	if curTun.PrivateKey != initialPrivKey {
		t.Errorf("in-memory private key mutated on DB failure: got %q, want %q", curTun.PrivateKey, initialPrivKey)
	}
	if curTun.ProbePrivateKey != initialProbePrivKey {
		t.Errorf("in-memory probe private key mutated on DB failure: got %q, want %q", curTun.ProbePrivateKey, initialProbePrivKey)
	}
	if curTun.StateVersion != initialVersion {
		t.Errorf("in-memory state version mutated on DB failure: got %d, want %d", curTun.StateVersion, initialVersion)
	}

	// Verify DB record is also untouched
	dbTun, err := db.GetBackendTunnel(ctx, initialTun.ID)
	if err != nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	if dbTun.Endpoint != expectedInitialEndpoint {
		t.Errorf("DB endpoint mutated on DB failure: got %q, want %q", dbTun.Endpoint, expectedInitialEndpoint)
	}
	if dbTun.PublicKey != initialPub {
		t.Errorf("DB public key mutated on DB failure: got %q, want %q", dbTun.PublicKey, initialPub)
	}

	// 4. Retry EnableBackend with valid context and verify it cleanly updates memory and DB
	svc.SetEnableBackendPreAddTunnelHookForTest(nil)
	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("subsequent EnableBackend with valid context failed: %v", err)
	}

	expectedNewEndpoint := "198.51.100.46:51822"
	updatedTun, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel after retry failed: %v", err)
	}
	if updatedTun.Endpoint != expectedNewEndpoint {
		t.Errorf("expected updated endpoint %q, got %q", expectedNewEndpoint, updatedTun.Endpoint)
	}
	if updatedTun.PublicKey != newPub {
		t.Errorf("expected updated public key %q, got %q", newPub, updatedTun.PublicKey)
	}

	updatedDBTun, err := db.GetBackendTunnel(ctx, initialTun.ID)
	if err != nil {
		t.Fatalf("GetBackendTunnel after retry failed: %v", err)
	}
	if updatedDBTun.Endpoint != expectedNewEndpoint {
		t.Errorf("expected DB endpoint %q, got %q", expectedNewEndpoint, updatedDBTun.Endpoint)
	}
	if updatedDBTun.PublicKey != newPub {
		t.Errorf("expected DB public key %q, got %q", newPub, updatedDBTun.PublicKey)
	}
}

func TestVPNEnableBackend_ExistingMissingDBRowFailsWithoutMemoryMutation(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	initialHost := "198.51.100.47"
	initialPort := 51820
	initialPub := "server-endpoint-pubkey-initial"

	srvID, err := db.CreateServer(ctx, &models.Server{
		Name: "missing-db-twin-server",
		Host: initialHost,
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       initialPort,
				"public_key": initialPub,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	adder := &mockAWGManagerWithClientAdder{}
	svc.SetAWGStatusProvider(adder)

	// 1. Initial EnableBackend establishes tunnel in pool and DB
	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("initial EnableBackend failed: %v", err)
	}

	initialTun, err := svc.pool.GetTunnel(srvID)
	if err != nil || initialTun == nil {
		t.Fatalf("expected initial tunnel in pool, got %+v (err=%v)", initialTun, err)
	}
	expectedInitialEndpoint := "198.51.100.47:51820"
	if initialTun.Endpoint != expectedInitialEndpoint || initialTun.PublicKey != initialPub {
		t.Fatalf("initial tunnel mismatch: endpoint=%s, pub=%s", initialTun.Endpoint, initialTun.PublicKey)
	}
	initialPrivKey := initialTun.PrivateKey
	initialProbePrivKey := initialTun.ProbePrivateKey
	initialVersion := initialTun.StateVersion

	// 2. Delete the DB row directly, leaving in-memory pool entry intact
	if err := db.DeleteBackendTunnel(ctx, initialTun.ID); err != nil {
		t.Fatalf("DeleteBackendTunnel failed: %v", err)
	}

	// 3. Update server configuration in DB with new host, port, and public key
	newHost := "198.51.100.48"
	newPort := 51822
	newPub := "server-endpoint-pubkey-updated"
	if err := db.UpdateServer(ctx, srvID, map[string]any{"host": newHost}); err != nil {
		t.Fatalf("UpdateServer host failed: %v", err)
	}
	if err := db.UpdateServerProtocols(ctx, srvID, map[string]any{
		"awg": map[string]any{
			"installed":  true,
			"port":       newPort,
			"public_key": newPub,
		},
	}); err != nil {
		t.Fatalf("UpdateServerProtocols failed: %v", err)
	}

	initialClientAddCalls := adder.addClientCalls

	// 4. Call EnableBackend: must fail because DB row is missing
	err = svc.EnableBackend(ctx, srvID)
	if err == nil {
		t.Fatal("expected EnableBackend to fail when DB row is missing, got nil")
	}
	if !strings.Contains(err.Error(), "failed to register backend tunnel") {
		t.Errorf("expected error wrapping failed to register backend tunnel, got: %v", err)
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected error containing 'not found', got: %v", err)
	}

	// Verify no AddClient calls were made on failed update
	if adder.addClientCalls != initialClientAddCalls {
		t.Errorf("AddClient was called %d times; expected no new calls on aborted update", adder.addClientCalls-initialClientAddCalls)
	}

	// 5. Verify in-memory pool state is not mutated
	curTun, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if curTun.Endpoint != expectedInitialEndpoint {
		t.Errorf("in-memory endpoint mutated on missing DB row: got %q, want %q", curTun.Endpoint, expectedInitialEndpoint)
	}
	if curTun.PublicKey != initialPub {
		t.Errorf("in-memory public key mutated on missing DB row: got %q, want %q", curTun.PublicKey, initialPub)
	}
	if curTun.PrivateKey != initialPrivKey {
		t.Errorf("in-memory private key mutated on missing DB row: got %q, want %q", curTun.PrivateKey, initialPrivKey)
	}
	if curTun.ProbePrivateKey != initialProbePrivKey {
		t.Errorf("in-memory probe private key mutated on missing DB row: got %q, want %q", curTun.ProbePrivateKey, initialProbePrivKey)
	}
	if curTun.StateVersion != initialVersion {
		t.Errorf("in-memory state version mutated on missing DB row: got %d, want %d", curTun.StateVersion, initialVersion)
	}

	// Verify DB row remains absent
	dbTun, err := db.GetBackendTunnel(ctx, initialTun.ID)
	if err != nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	if dbTun != nil {
		t.Errorf("expected DB row to remain absent, got %+v", dbTun)
	}
}

func TestEnableBackend_NetworkCallDoesNotHoldServiceLock(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	srvID, err := db.CreateServer(ctx, &models.Server{
		Name: "lock-scope-server",
		Host: "198.51.100.44",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": "server-lock-pubkey",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	adderCalled := false
	lockWasFree := false
	adder := &mockAWGManagerWithClientAdder{
		onAddClient: func() {
			adderCalled = true
			// If svc.mu was held with Lock(), calling IsRunning() or GetStatus()
			// (which acquire svc.mu.RLock()) would cause an immediate deadlock.
			_ = svc.IsRunning()
			st, err := svc.GetStatus(ctx)
			if err == nil && st != nil {
				lockWasFree = true
			}
		},
	}
	svc.SetAWGStatusProvider(adder)

	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("EnableBackend failed: %v", err)
	}

	if !adderCalled {
		t.Error("expected AddClient to be called")
	}
	if !lockWasFree {
		t.Error("expected service lock to be free during AddClient network call")
	}
}

func TestEnableBackend_ConcurrentStateModification(t *testing.T) {
	ctx := context.Background()

	t.Run("ExistingTunnel_ConcurrentHealthWriteDoesNotAbortEnable", func(t *testing.T) {
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService failed: %v", err)
		}
		t.Cleanup(func() { closeBackendDevices(svc) })

		srvID, err := db.CreateServer(ctx, &models.Server{
			Name: "concurrent-enable-server",
			Host: "198.51.100.77",
			Protocols: map[string]any{
				"awg": map[string]any{
					"installed":  true,
					"port":       51820,
					"public_key": "server-concurrent-enable-pubkey",
				},
			},
		})
		if err != nil {
			t.Fatalf("CreateServer failed: %v", err)
		}

		adder := &mockAWGManagerWithClientAdder{}
		svc.SetAWGStatusProvider(adder)

		// 1. Initial EnableBackend establishes tunnel in pool and DB
		if err := svc.EnableBackend(ctx, srvID); err != nil {
			t.Fatalf("initial EnableBackend failed: %v", err)
		}

		tun, err := svc.pool.GetTunnel(srvID)
		if err != nil || tun == nil {
			t.Fatalf("expected initial tunnel, got: %v (err=%v)", tun, err)
		}
		initialVersion := tun.StateVersion

		// 2. Set postAddTunnelHook to simulate a concurrent event occurring during
		// EnableBackend network operations (after AddTunnel, before finishEnableBackend):
		// Mutate tunnel state (via SetTunnelStatusWithReason), incrementing StateVersion.
		hookFired := false
		svc.SetEnableBackendPostAddTunnelHookForTest(func() {
			hookFired = true
			if hookErr := svc.pool.SetTunnelStatusWithReason(ctx, srvID, models.TunnelStatusDegraded, models.DisableReasonNone, 45); hookErr != nil {
				t.Errorf("concurrent SetTunnelStatusWithReason failed: %v", hookErr)
			}
		})
		defer svc.SetEnableBackendPostAddTunnelHookForTest(nil)

		// 3. Call EnableBackend again: a health-status write bumps StateVersion but
		// must not abort the enable (issue #607).
		if err := svc.EnableBackend(ctx, srvID); err != nil {
			t.Fatalf("expected EnableBackend to tolerate concurrent health write, got: %v", err)
		}
		if !hookFired {
			t.Fatal("expected postAddTunnelHook to fire")
		}

		// 4. Assert in-memory pool state reflects the concurrent modification, not overwritten state
		finalTun, err := svc.pool.GetTunnel(srvID)
		if err != nil || finalTun == nil {
			t.Fatalf("expected tunnel in pool, got %v (err=%v)", finalTun, err)
		}
		if finalTun.Status != models.TunnelStatusDegraded {
			t.Errorf("expected tunnel status %q to remain intact, got %q", models.TunnelStatusDegraded, finalTun.Status)
		}
		if finalTun.StateVersion <= initialVersion {
			t.Errorf("expected StateVersion to reflect concurrent mutation (> %d), got %d", initialVersion, finalTun.StateVersion)
		}
	})

	t.Run("NewTunnel_ConcurrentHealthWriteDoesNotAbortEnable", func(t *testing.T) {
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService failed: %v", err)
		}
		t.Cleanup(func() { closeBackendDevices(svc) })

		srvID, err := db.CreateServer(ctx, &models.Server{
			Name: "concurrent-enable-new-server",
			Host: "198.51.100.78",
			Protocols: map[string]any{
				"awg": map[string]any{
					"installed":  true,
					"port":       51820,
					"public_key": "server-concurrent-enable-new-pubkey",
				},
			},
		})
		if err != nil {
			t.Fatalf("CreateServer failed: %v", err)
		}

		adder := &mockAWGManagerWithClientAdder{}
		svc.SetAWGStatusProvider(adder)

		hookFired := false
		svc.SetEnableBackendPostAddTunnelHookForTest(func() {
			hookFired = true
			if hookErr := svc.pool.SetTunnelStatusWithReason(ctx, srvID, models.TunnelStatusDegraded, models.DisableReasonNone, 30); hookErr != nil {
				t.Errorf("concurrent SetTunnelStatusWithReason failed: %v", hookErr)
			}
		})
		defer svc.SetEnableBackendPostAddTunnelHookForTest(nil)

		// Brand new backend: the prober writes status after AddTunnel (issue #607).
		// StateVersion is bumped but the enable must still succeed.
		if err := svc.EnableBackend(ctx, srvID); err != nil {
			t.Fatalf("expected EnableBackend to tolerate concurrent health write, got: %v", err)
		}
		if !hookFired {
			t.Fatal("expected postAddTunnelHook to fire")
		}

		finalTun, err := svc.pool.GetTunnel(srvID)
		if err != nil || finalTun == nil {
			t.Fatalf("expected tunnel in pool, got %v (err=%v)", finalTun, err)
		}
		if finalTun.Status != models.TunnelStatusDegraded {
			t.Errorf("expected tunnel status %q to remain intact, got %q", models.TunnelStatusDegraded, finalTun.Status)
		}
		if finalTun.StateVersion <= 1 {
			t.Errorf("expected StateVersion > 1 after concurrent mutation, got %d", finalTun.StateVersion)
		}
	})

	t.Run("NewTunnel_ConcurrentEndpointChangeAbortsEnable", func(t *testing.T) {
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService failed: %v", err)
		}
		t.Cleanup(func() { closeBackendDevices(svc) })

		srvID, err := db.CreateServer(ctx, &models.Server{
			Name: "concurrent-enable-endpoint-server",
			Host: "198.51.100.79",
			Protocols: map[string]any{
				"awg": map[string]any{
					"installed":  true,
					"port":       51820,
					"public_key": "server-concurrent-enable-endpoint-pubkey",
				},
			},
		})
		if err != nil {
			t.Fatalf("CreateServer failed: %v", err)
		}
		svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})

		svc.SetEnableBackendPostAddTunnelHookForTest(func() {
			if _, hookErr := svc.pool.AddTunnel(ctx, srvID, "203.0.113.9:51820", "server-concurrent-enable-endpoint-pubkey"); hookErr != nil {
				t.Errorf("concurrent AddTunnel failed: %v", hookErr)
			}
		})
		defer svc.SetEnableBackendPostAddTunnelHookForTest(nil)

		err = svc.EnableBackend(ctx, srvID)
		if err == nil || !strings.Contains(err.Error(), "backend state modified concurrently; aborting enable") {
			t.Fatalf("expected concurrent modification error, got: %v", err)
		}
	})
}

func TestEnableBackend_TypedSentinelErrors(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	ctx := context.Background()

	// 1. Non-existent server should return ErrServerNotFound wrapped
	err = svc.EnableBackend(ctx, 99999)
	if err == nil {
		t.Fatal("expected error for non-existent server")
	}
	if !errors.Is(err, ErrServerNotFound) {
		t.Errorf("expected ErrServerNotFound, got: %v", err)
	}

	// 2. Server without AWG credentials should return ErrAWGNotInstalled
	srvID, err := db.CreateServer(ctx, &models.Server{
		Name:      "no-awg-server",
		Host:      "10.200.0.1",
		Protocols: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	err = svc.EnableBackend(ctx, srvID)
	if err == nil {
		t.Fatal("expected error for server without AWG")
	}
	if !errors.Is(err, ErrAWGNotInstalled) {
		t.Errorf("expected ErrAWGNotInstalled, got: %v", err)
	}
}
