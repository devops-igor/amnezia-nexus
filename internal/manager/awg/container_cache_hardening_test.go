package awg

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
)

type mockFaultyIPAllocator struct {
	allocCount   atomic.Int32
	releaseCount atomic.Int32
	failRelease  bool
	allocFunc    func(ctx context.Context, serverID int64, clientID, clientPubKey string, usedIPs []string, subnetAddr string, subnetCIDR int, gatewayIP string) (string, error)
}

func (m *mockFaultyIPAllocator) AllocateAWGClientIP(
	ctx context.Context,
	serverID int64,
	clientID, clientPubKey string,
	usedIPs []string,
	subnetAddr string,
	subnetCIDR int,
	gatewayIP string,
) (string, error) {
	m.allocCount.Add(1)
	if m.allocFunc != nil {
		return m.allocFunc(ctx, serverID, clientID, clientPubKey, usedIPs, subnetAddr, subnetCIDR, gatewayIP)
	}
	return "10.66.66.2", nil
}

func (m *mockFaultyIPAllocator) ReleaseAWGClientIP(ctx context.Context, serverID int64, clientID, ip string) error {
	m.releaseCount.Add(1)
	if m.failRelease {
		return errors.New("simulated database release failure")
	}
	return nil
}

func (m *mockFaultyIPAllocator) AdoptAWGClientIPLease(ctx context.Context, serverID int64, clientID, clientPubKey, ip string) (bool, error) {
	return true, nil
}

func (m *mockFaultyIPAllocator) TransferAWGClientIPLease(ctx context.Context, serverID int64, oldClientID, newClientID, ip string) error {
	return nil
}

func TestAWGManager_FailedContainerDiscovery_DoesNotPopulateCache(t *testing.T) {
	ctx := context.Background()

	var dockerPsCalls atomic.Int32
	discoveryWorking := atomic.Bool{}
	discoveryWorking.Store(false)

	client := newMockAWGSSHClient()
	client.host = "192.0.2.50"
	client.port = 22
	serverID := int64(101)
	client.serverID = &serverID

	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker ps") {
			dockerPsCalls.Add(1)
			if discoveryWorking.Load() {
				// Later discovery succeeds with legacy amnezia-awg container
				return "amnezia-awg\n", "", 0, nil
			}
			// Discovery failure (e.g. daemon error or no running containers)
			return "", "docker daemon unreachable", 1, errors.New("docker daemon unreachable")
		}
		return "OK", "", 0, nil
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})

	// 1. ResolveContainerName on discovery failure returns safe fallback but does NOT cache it
	cName := mgr.ResolveContainerName(ctx, client)
	if cName != "amnezia-awg2" {
		t.Fatalf("expected fallback amnezia-awg2 on discovery failure, got: %s", cName)
	}

	mgr.cacheMu.RLock()
	cacheLen := len(mgr.containerCache)
	mgr.cacheMu.RUnlock()
	if cacheLen != 0 {
		t.Fatalf("expected containerCache to remain empty after failed discovery, but got %d entries", cacheLen)
	}

	if _, ok := mgr.getCachedContainerForClient(client); ok {
		t.Fatalf("expected getCachedContainerForClient to return false after failed discovery")
	}

	// 2. ResolveLockResource unifies remote locking on the physical interface without cache dependency
	lockRes := mgr.ResolveLockResource(ctx, client, serverID)
	if lockRes != "iface_awg0" {
		t.Fatalf("expected stable interface lock iface_awg0 on failed discovery, got: %s", lockRes)
	}

	mgr.cacheMu.RLock()
	cacheLenAfterLock := len(mgr.containerCache)
	mgr.cacheMu.RUnlock()
	if cacheLenAfterLock != 0 {
		t.Fatalf("expected containerCache to remain empty after ResolveLockResource with failed discovery, got %d entries", cacheLenAfterLock)
	}

	if _, ok := mgr.getCachedContainer("id:101"); ok {
		t.Fatalf("expected getCachedContainer(id:101) to return false after failed discovery")
	}

	// 3. Verify that after Docker discovery recovers, it correctly discovers and caches amnezia-awg
	discoveryWorking.Store(true)

	cNameRecovered := mgr.ResolveContainerName(ctx, client)
	if cNameRecovered != "amnezia-awg" {
		t.Fatalf("expected discovered amnezia-awg after recovery, got: %s", cNameRecovered)
	}

	cachedName, ok := mgr.getCachedContainerForClient(client)
	if !ok || cachedName != "amnezia-awg" {
		t.Fatalf("expected containerCache to contain verified amnezia-awg, got: %s (ok=%v)", cachedName, ok)
	}

	lockResRecovered := mgr.ResolveLockResource(ctx, client, serverID)
	if lockResRecovered != "iface_awg0" {
		t.Fatalf("expected lock resource iface_awg0 after recovery, got: %s", lockResRecovered)
	}
	if lockRes != lockResRecovered {
		t.Fatalf("lock resource must not diverge across discovery states: got %s vs %s", lockRes, lockResRecovered)
	}
}

func TestAWGManager_AllocateNonConflictingIP_ReleaseFailure_AbortsWithError(t *testing.T) {
	ctx := context.Background()

	allocator := &mockFaultyIPAllocator{
		failRelease: true,
	}
	allocator.allocFunc = func(ctx context.Context, serverID int64, clientID, clientPubKey string, usedIPs []string, subnetAddr string, subnetCIDR int, gatewayIP string) (string, error) {
		// First allocation yields 10.66.66.2 (conflicts with remote peer)
		// Second allocation yields 10.66.66.3 (clean)
		for _, used := range usedIPs {
			if used == "10.66.66.2" {
				return "10.66.66.3", nil
			}
		}
		return "10.66.66.2", nil
	}

	mgr := NewAWGManager(nil)
	mgr.SetIPAllocator(allocator)

	remotePeers := []AWGPeer{
		{
			PublicKey:  "ConflictingKey==============================",
			AllowedIPs: "10.66.66.2/32",
		},
	}

	allocatedIP, err := mgr.allocateNonConflictingIP(
		ctx,
		1,
		"new-client",
		"NewKey======================================",
		nil,
		"10.66.66.0",
		24,
		"10.66.66.1",
		remotePeers,
	)
	if err == nil {
		t.Fatalf("expected allocateNonConflictingIP to abort on release failure, got nil error and IP: %s", allocatedIP)
	}
	if allocatedIP != "" {
		t.Fatalf("expected empty IP on release failure, got: %s", allocatedIP)
	}
	if !strings.Contains(err.Error(), "failed to release conflicting allocated IP lease") {
		t.Fatalf("expected descriptive release failure error, got: %v", err)
	}
	if allocator.releaseCount.Load() != 1 {
		t.Fatalf("expected 1 release attempt, got: %d", allocator.releaseCount.Load())
	}
	if allocator.allocCount.Load() != 1 {
		t.Fatalf("expected exactly 1 allocation attempt (aborted before retry), got: %d", allocator.allocCount.Load())
	}
}

func TestAWGManager_AllocateNonConflictingIP_ExhaustsRetries_ReturnsDescriptiveError(t *testing.T) {
	ctx := context.Background()

	allocator := &mockFaultyIPAllocator{
		failRelease: false,
	}
	// Always returns 10.66.66.2 simulating persistent conflict where candidates conflict with remote peers
	allocator.allocFunc = func(ctx context.Context, serverID int64, clientID, clientPubKey string, usedIPs []string, subnetAddr string, subnetCIDR int, gatewayIP string) (string, error) {
		return "10.66.66.2", nil
	}

	mgr := NewAWGManager(nil)
	mgr.SetIPAllocator(allocator)

	remotePeers := []AWGPeer{
		{
			PublicKey:  "RemotePeerKey===============================",
			AllowedIPs: "10.66.66.2/32",
		},
	}

	allocatedIP, err := mgr.allocateNonConflictingIP(
		ctx,
		1,
		"stuck-client",
		"ClientKey===================================",
		nil,
		"10.66.66.0",
		24,
		"10.66.66.1",
		remotePeers,
	)
	if err == nil {
		t.Fatalf("expected error after exhausting conflict retries, got nil and IP: %s", allocatedIP)
	}
	if allocatedIP != "" {
		t.Fatalf("expected empty IP on failure, got: %s", allocatedIP)
	}
	if !strings.Contains(err.Error(), "after 10 attempts") || !strings.Contains(err.Error(), "all candidates conflict with remote peers") {
		t.Fatalf("expected descriptive error mentioning 10 attempts and conflict, got: %v", err)
	}
	if allocator.allocCount.Load() != 10 {
		t.Fatalf("expected exactly 10 allocation attempts, got: %d", allocator.allocCount.Load())
	}
	if allocator.releaseCount.Load() != 10 {
		t.Fatalf("expected exactly 10 release attempts, got: %d", allocator.releaseCount.Load())
	}
}

func TestAWGManager_ObtainExistingClientIP_ReleaseFailure_AbortsWithError(t *testing.T) {
	ctx := context.Background()

	allocator := &mockFaultyIPAllocator{
		failRelease: true,
	}
	allocator.allocFunc = func(ctx context.Context, serverID int64, clientID, clientPubKey string, usedIPs []string, subnetAddr string, subnetCIDR int, gatewayIP string) (string, error) {
		return "10.66.66.2", nil
	}

	mgr := NewAWGManager(nil)
	mgr.SetIPAllocator(allocator)

	remotePeers := []AWGPeer{
		{
			PublicKey:  "ConflictingKey==============================",
			AllowedIPs: "10.66.66.2/32",
		},
	}

	existingClient := AWGClient{
		ClientID: "existing-client-key",
		UserData: AWGClientUserData{
			ClientIP: "10.66.66.99",
		},
	}

	allocatedIP, _, _, _, _, err := mgr.obtainExistingClientIPWithAllocator(
		ctx,
		1,
		"client-1",
		"existing-client-key",
		existingClient,
		nil,
		"10.66.66.0",
		24,
		"10.66.66.1",
		remotePeers,
	)
	if err == nil {
		t.Fatalf("expected error from obtainExistingClientIPWithAllocator on release failure, got nil")
	}
	if allocatedIP != "" {
		t.Fatalf("expected empty IP on release failure, got: %s", allocatedIP)
	}
	if !strings.Contains(err.Error(), "failed to release conflicting allocated IP lease") {
		t.Fatalf("expected release failure error message, got: %v", err)
	}
	if allocator.releaseCount.Load() != 1 {
		t.Fatalf("expected 1 release attempt, got: %d", allocator.releaseCount.Load())
	}
	if allocator.allocCount.Load() != 1 {
		t.Fatalf("expected exactly 1 allocation attempt before abort, got: %d", allocator.allocCount.Load())
	}
}
