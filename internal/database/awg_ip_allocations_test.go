package database

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

func setupTestDBForAllocations(t *testing.T) (*DB, func()) {
	t.Helper()
	db, err := Open(":memory:", "")
	if err != nil {
		t.Fatalf("failed to open test in-memory database: %v", err)
	}
	return db, func() {
		_ = db.Close()
	}
}

func TestAllocateAWGClientIP_Sequential(t *testing.T) {
	db, cleanup := setupTestDBForAllocations(t)
	defer cleanup()

	ctx := context.Background()
	serverID := int64(1)
	subnetAddr := "10.66.66.0"
	subnetCIDR := 24
	gatewayIP := "10.66.66.1"

	// Allocate for client 1
	ip1, err := db.AllocateAWGClientIP(ctx, serverID, "client1", "pubkey1", nil, subnetAddr, subnetCIDR, gatewayIP)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if ip1 != "10.66.66.2" {
		t.Fatalf("expected 10.66.66.2, got: %s", ip1)
	}

	// Allocate for client 2
	ip2, err := db.AllocateAWGClientIP(ctx, serverID, "client2", "pubkey2", nil, subnetAddr, subnetCIDR, gatewayIP)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if ip2 != "10.66.66.3" {
		t.Fatalf("expected 10.66.66.3, got: %s", ip2)
	}

	// GetAllocatedAWGIPs
	allocated, err := db.GetAllocatedAWGIPs(ctx, serverID)
	if err != nil {
		t.Fatalf("failed to get allocated IPs: %v", err)
	}
	if len(allocated) != 2 || allocated[0] != "10.66.66.2" || allocated[1] != "10.66.66.3" {
		t.Fatalf("unexpected allocated IPs: %+v", allocated)
	}
}

func TestAllocateAWGClientIP_Idempotency(t *testing.T) {
	db, cleanup := setupTestDBForAllocations(t)
	defer cleanup()

	ctx := context.Background()
	serverID := int64(1)
	subnetAddr := "10.66.66.0"
	subnetCIDR := 24
	gatewayIP := "10.66.66.1"

	// First allocation
	ip1, err := db.AllocateAWGClientIP(ctx, serverID, "client1", "pubkey1", nil, subnetAddr, subnetCIDR, gatewayIP)
	if err != nil {
		t.Fatalf("first allocation failed: %v", err)
	}

	// Re-allocation for same clientID
	ip2, err := db.AllocateAWGClientIP(ctx, serverID, "client1", "pubkey1", nil, subnetAddr, subnetCIDR, gatewayIP)
	if err != nil {
		t.Fatalf("second allocation failed: %v", err)
	}
	if ip1 != ip2 {
		t.Fatalf("expected idempotent IP %s, got %s", ip1, ip2)
	}

	// Re-allocation identifying by clientPubKey as clientID
	ip3, err := db.AllocateAWGClientIP(ctx, serverID, "pubkey1", "pubkey1", nil, subnetAddr, subnetCIDR, gatewayIP)
	if err != nil {
		t.Fatalf("third allocation failed: %v", err)
	}
	if ip1 != ip3 {
		t.Fatalf("expected idempotent IP %s, got %s", ip1, ip3)
	}

	// Verify only 1 row exists in DB
	allocated, err := db.GetAllocatedAWGIPs(ctx, serverID)
	if err != nil {
		t.Fatalf("failed to get allocated IPs: %v", err)
	}
	if len(allocated) != 1 {
		t.Fatalf("expected 1 allocated IP, got %d", len(allocated))
	}
}

func TestAllocateAWGClientIP_ReleaseAndReallocation(t *testing.T) {
	db, cleanup := setupTestDBForAllocations(t)
	defer cleanup()

	ctx := context.Background()
	serverID := int64(1)
	subnetAddr := "10.66.66.0"
	subnetCIDR := 24
	gatewayIP := "10.66.66.1"

	// Allocate client 1 (gets .2)
	ip1, err := db.AllocateAWGClientIP(ctx, serverID, "client1", "pubkey1", nil, subnetAddr, subnetCIDR, gatewayIP)
	if err != nil || ip1 != "10.66.66.2" {
		t.Fatalf("unexpected allocation 1: ip=%s, err=%v", ip1, err)
	}

	// Allocate client 2 (gets .3)
	ip2, err := db.AllocateAWGClientIP(ctx, serverID, "client2", "pubkey2", nil, subnetAddr, subnetCIDR, gatewayIP)
	if err != nil || ip2 != "10.66.66.3" {
		t.Fatalf("unexpected allocation 2: ip=%s, err=%v", ip2, err)
	}

	// Release client 1 (.2 is freed)
	if err := db.ReleaseAWGClientIP(ctx, serverID, "client1", ip1); err != nil {
		t.Fatalf("release failed: %v", err)
	}

	// Verify only client 2 is allocated
	allocated, err := db.GetAllocatedAWGIPs(ctx, serverID)
	if err != nil {
		t.Fatalf("failed to get allocated: %v", err)
	}
	if len(allocated) != 1 || allocated[0] != "10.66.66.3" {
		t.Fatalf("expected only 10.66.66.3, got: %+v", allocated)
	}

	// Allocate new client 3 — should get the freed .2
	ip3, err := db.AllocateAWGClientIP(ctx, serverID, "client3", "pubkey3", nil, subnetAddr, subnetCIDR, gatewayIP)
	if err != nil {
		t.Fatalf("allocation 3 failed: %v", err)
	}
	if ip3 != "10.66.66.2" {
		t.Fatalf("expected freed IP 10.66.66.2, got: %s", ip3)
	}
}

func TestAllocateAWGClientIP_UsedConfigIPs(t *testing.T) {
	db, cleanup := setupTestDBForAllocations(t)
	defer cleanup()

	ctx := context.Background()
	serverID := int64(1)
	subnetAddr := "10.66.66.0"
	subnetCIDR := 24
	gatewayIP := "10.66.66.1"

	// Suppose remote configuration already has 10.66.66.2 and 10.66.66.3 assigned
	usedConfigIPs := []string{"10.66.66.2", "10.66.66.3"}

	ip, err := db.AllocateAWGClientIP(ctx, serverID, "client1", "pubkey1", usedConfigIPs, subnetAddr, subnetCIDR, gatewayIP)
	if err != nil {
		t.Fatalf("allocation failed: %v", err)
	}
	if ip != "10.66.66.4" {
		t.Fatalf("expected 10.66.66.4, got: %s", ip)
	}
}

func TestAllocateAWGClientIP_SubnetExhaustion(t *testing.T) {
	db, cleanup := setupTestDBForAllocations(t)
	defer cleanup()

	ctx := context.Background()
	serverID := int64(1)
	// /30 subnet: .0 (network), .1 (gateway), .2 (usable host), .3 (broadcast)
	// Only 1 usable host IP (.2)
	subnetAddr := "10.66.66.0"
	subnetCIDR := 30
	gatewayIP := "10.66.66.1"

	// 1st allocation: gets .2
	ip1, err := db.AllocateAWGClientIP(ctx, serverID, "client1", "pubkey1", nil, subnetAddr, subnetCIDR, gatewayIP)
	if err != nil || ip1 != "10.66.66.2" {
		t.Fatalf("unexpected allocation 1: ip=%s, err=%v", ip1, err)
	}

	// 2nd allocation: subnet is exhausted
	_, err = db.AllocateAWGClientIP(ctx, serverID, "client2", "pubkey2", nil, subnetAddr, subnetCIDR, gatewayIP)
	if err == nil {
		t.Fatalf("expected subnet exhaustion error, got nil")
	}
}

func TestAllocateAWGClientIP_ConcurrentAllocations(t *testing.T) {
	db, cleanup := setupTestDBForAllocations(t)
	defer cleanup()

	ctx := context.Background()
	serverID := int64(1)
	subnetAddr := "10.66.66.0"
	subnetCIDR := 24
	gatewayIP := "10.66.66.1"

	const numClients = 30
	var wg sync.WaitGroup
	allocatedIPs := make([]string, numClients)
	errors := make([]error, numClients)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cID := fmt.Sprintf("client-%d", idx)
			pKey := fmt.Sprintf("pubkey-%d", idx)
			ip, err := db.AllocateAWGClientIP(ctx, serverID, cID, pKey, nil, subnetAddr, subnetCIDR, gatewayIP)
			allocatedIPs[idx] = ip
			errors[idx] = err
		}(i)
	}

	wg.Wait()

	seen := make(map[string]bool)
	for i := 0; i < numClients; i++ {
		if errors[i] != nil {
			t.Fatalf("client %d allocation failed: %v", i, errors[i])
		}
		ip := allocatedIPs[i]
		if ip == "" {
			t.Fatalf("client %d got empty IP", i)
		}
		if seen[ip] {
			t.Fatalf("duplicate IP allocated: %s for client %d", ip, i)
		}
		seen[ip] = true
	}

	if len(seen) != numClients {
		t.Fatalf("expected %d unique IPs, got %d", numClients, len(seen))
	}
}

func TestTransferAWGClientIPLease_ReKeying(t *testing.T) {
	db, cleanup := setupTestDBForAllocations(t)
	defer cleanup()

	ctx := context.Background()
	serverID := int64(1)
	subnetAddr := "10.66.66.0"
	subnetCIDR := 24
	gatewayIP := "10.66.66.1"

	const (
		keyK1 = "pubkey-K1"
		keyK2 = "pubkey-K2"
	)

	// 1. Initial allocation with K1
	ip1, err := db.AllocateAWGClientIP(ctx, serverID, keyK1, keyK1, nil, subnetAddr, subnetCIDR, gatewayIP)
	if err != nil {
		t.Fatalf("first allocation failed: %v", err)
	}

	// 2. Transfer lease from K1 to K2
	if err := db.TransferAWGClientIPLease(ctx, serverID, keyK2, keyK1, ip1); err != nil {
		t.Fatalf("transfer to K2 failed: %v", err)
	}

	// 3. Allocate with K2 — should verify ownership and return same IP
	ip2, err := db.AllocateAWGClientIP(ctx, serverID, keyK2, keyK2, nil, subnetAddr, subnetCIDR, gatewayIP)
	if err != nil {
		t.Fatalf("allocation with K2 failed: %v", err)
	}
	if ip2 != ip1 {
		t.Fatalf("expected K2 to retain IP %s, got: %s", ip1, ip2)
	}

	// 4. Transfer lease back from K2 to K1
	if err := db.TransferAWGClientIPLease(ctx, serverID, keyK1, keyK2, ip2); err != nil {
		t.Fatalf("transfer back to K1 failed: %v", err)
	}

	// 5. Allocate with K1 — should verify ownership and return same IP
	ip3, err := db.AllocateAWGClientIP(ctx, serverID, keyK1, keyK1, nil, subnetAddr, subnetCIDR, gatewayIP)
	if err != nil {
		t.Fatalf("allocation with K1 failed: %v", err)
	}
	if ip3 != ip1 {
		t.Fatalf("expected K1 to retain IP %s, got: %s", ip1, ip3)
	}

	// Total allocations count in DB should be exactly 1
	allocated, err := db.GetAllocatedAWGIPs(ctx, serverID)
	if err != nil || len(allocated) != 1 {
		t.Fatalf("expected 1 allocation in DB, got: %+v", allocated)
	}
}

func TestAllocateAWGClientIP_OwnershipVerification_ClaimedByOther(t *testing.T) {
	db, cleanup := setupTestDBForAllocations(t)
	defer cleanup()

	ctx := context.Background()
	serverID := int64(1)
	subnetAddr := "10.66.66.0"
	subnetCIDR := 24
	gatewayIP := "10.66.66.1"

	// Client Alice allocates first IP (10.66.66.2)
	ipAlice, err := db.AllocateAWGClientIP(ctx, serverID, "alice", "alice-key", nil, subnetAddr, subnetCIDR, gatewayIP)
	if err != nil {
		t.Fatalf("alice allocation failed: %v", err)
	}
	if ipAlice != "10.66.66.2" {
		t.Fatalf("expected 10.66.66.2, got: %s", ipAlice)
	}

	// Verify that Bob cannot claim Alice's IP
	claimed, err := db.isAllocationClaimedByOther(ctx, serverID, ipAlice, "bob", "bob-key")
	if err != nil {
		t.Fatalf("isAllocationClaimedByOther check failed: %v", err)
	}
	if !claimed {
		t.Fatalf("expected IP %s to be claimed by other (alice) from bob's perspective", ipAlice)
	}

	// When Bob allocates, he gets 10.66.66.3, not Alice's IP
	ipBob, err := db.AllocateAWGClientIP(ctx, serverID, "bob", "bob-key", nil, subnetAddr, subnetCIDR, gatewayIP)
	if err != nil {
		t.Fatalf("bob allocation failed: %v", err)
	}
	if ipBob == ipAlice {
		t.Fatalf("bob collided with alice's IP: %s", ipBob)
	}
	if ipBob != "10.66.66.3" {
		t.Fatalf("expected 10.66.66.3 for bob, got: %s", ipBob)
	}
}
