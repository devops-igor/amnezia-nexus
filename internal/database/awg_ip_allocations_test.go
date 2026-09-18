package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
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
	if err := db.ReleaseAWGClientIP(ctx, serverID, "pubkey1", ip1); err != nil {
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

func TestTransferAWGClientIPLease_RejectionWhenNotOwned(t *testing.T) {
	db, cleanup := setupTestDBForAllocations(t)
	defer cleanup()

	ctx := context.Background()
	serverID := int64(1)
	subnetAddr := "10.66.66.0"
	subnetCIDR := 24
	gatewayIP := "10.66.66.1"

	ipAlice, err := db.AllocateAWGClientIP(ctx, serverID, "alice", "alice-key", nil, subnetAddr, subnetCIDR, gatewayIP)
	if err != nil {
		t.Fatalf("alice allocation failed: %v", err)
	}

	// Attempt to transfer Alice's IP claiming it was owned by Bob (who does not own it)
	err = db.TransferAWGClientIPLease(ctx, serverID, "eve-key", "bob-key", ipAlice)
	if err == nil {
		t.Fatalf("expected transfer to fail when oldClientID is not the owner")
	}
	expectedErrMsg := fmt.Sprintf("lease transfer rejected: IP %s on server %d is not owned by bob-key", ipAlice, serverID)
	if err.Error() != expectedErrMsg {
		t.Fatalf("expected error %q, got: %q", expectedErrMsg, err.Error())
	}

	// Attempt to transfer an unallocated IP
	err = db.TransferAWGClientIPLease(ctx, serverID, "eve-key", "alice-key", "10.66.66.99")
	if err == nil {
		t.Fatalf("expected transfer of unallocated IP to fail")
	}
}

func TestAdoptAWGClientIPLease_Scenarios(t *testing.T) {
	db, cleanup := setupTestDBForAllocations(t)
	defer cleanup()

	ctx := context.Background()
	serverID := int64(1)
	subnetAddr := "10.66.66.0"
	subnetCIDR := 24
	gatewayIP := "10.66.66.1"

	// 1. Adopt an existing legacy client's IP that has no DB lease row
	legacyIP := "10.66.66.50"
	adopted, err := db.AdoptAWGClientIPLease(ctx, serverID, "legacy-client", "legacy-key", legacyIP)
	if err != nil {
		t.Fatalf("adopt legacy IP failed: %v", err)
	}
	if !adopted {
		t.Fatalf("expected legacy IP to be adopted successfully")
	}

	// Submitting AllocateAWGClientIP for this client should preserve the adopted IP
	allocIP, err := db.AllocateAWGClientIP(ctx, serverID, "legacy-client", "legacy-key", nil, subnetAddr, subnetCIDR, gatewayIP)
	if err != nil {
		t.Fatalf("allocate after adopt failed: %v", err)
	}
	if allocIP != legacyIP {
		t.Fatalf("expected adopted IP %s to be preserved, got %s", legacyIP, allocIP)
	}

	// 2. Attempt to adopt the same IP by another client should be rejected
	adopted2, err := db.AdoptAWGClientIPLease(ctx, serverID, "attacker", "attacker-key", legacyIP)
	if err != nil {
		t.Fatalf("adopt check failed: %v", err)
	}
	if adopted2 {
		t.Fatalf("expected adoption of already claimed IP to return false")
	}

	// 3. Idempotent adoption by the same client should return true
	adoptedAgain, err := db.AdoptAWGClientIPLease(ctx, serverID, "legacy-client", "legacy-key", legacyIP)
	if err != nil {
		t.Fatalf("idempotent adopt failed: %v", err)
	}
	if !adoptedAgain {
		t.Fatalf("expected idempotent adoption to return true")
	}
}

func TestAWGIPAllocations_ConcurrentClientIdentity_EnforcesUniqueness(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_concurrent_identity.db")

	db1, err := Open(dbPath, "")
	if err != nil {
		t.Fatalf("failed to open db1: %v", err)
	}
	defer db1.Close()

	db2, err := Open(dbPath, "")
	if err != nil {
		t.Fatalf("failed to open db2: %v", err)
	}
	defer db2.Close()

	ctx := context.Background()
	serverID := int64(1)
	clientID := "concurrent-client-identity"
	clientPubKey := "concurrent-pubkey-identity"
	subnetAddr := "10.66.66.0"
	subnetCIDR := 24
	gatewayIP := "10.66.66.1"

	const concurrency = 20
	var wg sync.WaitGroup
	results := make([]string, concurrency)
	errors := make([]error, concurrency)

	startBarrier := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-startBarrier

			targetDB := db1
			if idx%2 != 0 {
				targetDB = db2
			}

			ip, allocErr := targetDB.AllocateAWGClientIP(ctx, serverID, clientID, clientPubKey, nil, subnetAddr, subnetCIDR, gatewayIP)
			results[idx] = ip
			errors[idx] = allocErr
		}(i)
	}

	close(startBarrier)
	wg.Wait()

	// 1. All calls succeed without returning errors
	for i := 0; i < concurrency; i++ {
		if errors[i] != nil {
			t.Fatalf("goroutine %d returned unexpected error: %v", i, errors[i])
		}
		if results[i] == "" {
			t.Fatalf("goroutine %d returned empty IP", i)
		}
	}

	// 2. All returned IPs are identical
	firstIP := results[0]
	for i := 1; i < concurrency; i++ {
		if results[i] != firstIP {
			t.Fatalf("goroutine %d got different IP %s, expected %s", i, results[i], firstIP)
		}
	}

	// 3. Exactly ONE row with status = 'allocated' exists in awg_ip_allocations for that (server_id, client_id)
	var count int
	err = db1.SQLDB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM awg_ip_allocations WHERE server_id = ? AND (client_id = ? OR client_id = ?) AND status = 'allocated'",
		serverID, clientID, clientPubKey,
	).Scan(&count)
	if err != nil {
		t.Fatalf("failed to query active lease count: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 active row for client in awg_ip_allocations, got %d", count)
	}
}

func TestAWGIPAllocations_MismatchedRelease_PreservesOtherClientLease(t *testing.T) {
	db, cleanup := setupTestDBForAllocations(t)
	defer cleanup()

	ctx := context.Background()
	serverID := int64(1)
	clientA := "ClientA"
	ipA := "10.66.66.5"
	clientB := "ClientB"
	ipB := "10.66.66.6"

	// Insert allocation for Client A with IP A (10.66.66.5)
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.SQLDB().ExecContext(ctx,
		"INSERT INTO awg_ip_allocations (server_id, client_id, ip, status, created_at, updated_at) VALUES (?, ?, ?, 'allocated', ?, ?)",
		serverID, clientA, ipA, now, now,
	)
	if err != nil {
		t.Fatalf("failed to insert Client A allocation: %v", err)
	}

	// Insert allocation for Client B with IP B (10.66.66.6)
	_, err = db.SQLDB().ExecContext(ctx,
		"INSERT INTO awg_ip_allocations (server_id, client_id, ip, status, created_at, updated_at) VALUES (?, ?, ?, 'allocated', ?, ?)",
		serverID, clientB, ipB, now, now,
	)
	if err != nil {
		t.Fatalf("failed to insert Client B allocation: %v", err)
	}

	// Call ReleaseAWGClientIP(ctx, serverID, "ClientA", "10.66.66.6") (Client A with Client B's IP)
	err = db.ReleaseAWGClientIP(ctx, serverID, clientA, ipB)
	if err != nil {
		t.Fatalf("unexpected error from mismatched ReleaseAWGClientIP: %v", err)
	}

	// Assert Client B's allocation for 10.66.66.6 is still present and active in the database!
	var ownerB string
	err = db.SQLDB().QueryRowContext(ctx,
		"SELECT client_id FROM awg_ip_allocations WHERE server_id = ? AND ip = ? AND status = 'allocated'",
		serverID, ipB,
	).Scan(&ownerB)
	if err != nil {
		t.Fatalf("expected Client B allocation for %s to remain active, got: %v", ipB, err)
	}
	if ownerB != clientB {
		t.Fatalf("expected owner of %s to be %s, got: %s", ipB, clientB, ownerB)
	}

	// Call ReleaseAWGClientIP(ctx, serverID, "ClientA", "10.66.66.5") (matching)
	err = db.ReleaseAWGClientIP(ctx, serverID, clientA, ipA)
	if err != nil {
		t.Fatalf("unexpected error from matching ReleaseAWGClientIP: %v", err)
	}

	// Assert Client A's allocation is removed, and Client B's allocation remains intact
	var ownerA string
	err = db.SQLDB().QueryRowContext(ctx,
		"SELECT client_id FROM awg_ip_allocations WHERE server_id = ? AND ip = ? AND status = 'allocated'",
		serverID, ipA,
	).Scan(&ownerA)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected Client A allocation to be removed, got: %v (owner=%s)", err, ownerA)
	}

	err = db.SQLDB().QueryRowContext(ctx,
		"SELECT client_id FROM awg_ip_allocations WHERE server_id = ? AND ip = ? AND status = 'allocated'",
		serverID, ipB,
	).Scan(&ownerB)
	if err != nil {
		t.Fatalf("expected Client B allocation for %s to remain active after Client A release, got: %v", ipB, err)
	}
	if ownerB != clientB {
		t.Fatalf("expected owner of %s to remain %s, got: %s", ipB, clientB, ownerB)
	}
}

func TestAWGIPAllocations_Migration_CleansLegacyDuplicateActiveRecords(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_legacy_migration.db")

	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", dbPath)
	rawDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("failed to open raw sqlite db: %v", err)
	}

	// Setup legacy table without uq_awg_ip_allocations_server_client_active index
	_, err = rawDB.Exec(`
		CREATE TABLE awg_ip_allocations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			server_id INTEGER NOT NULL,
			client_id TEXT NOT NULL,
			ip TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'allocated',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			UNIQUE(server_id, ip)
		);
	`)
	if err != nil {
		t.Fatalf("failed to create legacy table: %v", err)
	}

	// Insert duplicate active allocations for same (server_id=1, client_id="dup-client")
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = rawDB.Exec(`
		INSERT INTO awg_ip_allocations (id, server_id, client_id, ip, status, created_at, updated_at) VALUES
		(1, 1, 'dup-client', '10.66.66.2', 'allocated', ?, ?),
		(2, 1, 'dup-client', '10.66.66.3', 'allocated', ?, ?),
		(3, 1, 'other-client', '10.66.66.4', 'allocated', ?, ?);
	`, now, now, now, now, now, now)
	if err != nil {
		t.Fatalf("failed to insert duplicate records: %v", err)
	}
	_ = rawDB.Close()

	// Open with database.Open which runs runMigrationsLocked -> migrateAWGIPAllocations
	db, err := Open(dbPath, "")
	if err != nil {
		t.Fatalf("Open failed on legacy DB: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Verify earliest row (id=1) was retained as allocated without user_connections match
	var remainingIP string
	var remainingID int64
	err = db.SQLDB().QueryRowContext(ctx,
		"SELECT id, ip FROM awg_ip_allocations WHERE server_id = 1 AND client_id = 'dup-client' AND status = 'allocated'",
	).Scan(&remainingID, &remainingIP)
	if err != nil {
		t.Fatalf("failed to query remaining lease: %v", err)
	}
	if remainingID != 1 || remainingIP != "10.66.66.2" {
		t.Fatalf("expected earliest record id=1 ip=10.66.66.2, got id=%d ip=%s", remainingID, remainingIP)
	}

	// Verify divergent row (id=2) was not deleted but marked superseded
	var supersededIP, supersededStatus string
	err = db.SQLDB().QueryRowContext(ctx,
		"SELECT ip, status FROM awg_ip_allocations WHERE id = 2",
	).Scan(&supersededIP, &supersededStatus)
	if err != nil {
		t.Fatalf("failed to query superseded record id=2: %v", err)
	}
	if supersededIP != "10.66.66.3" || supersededStatus != "superseded" {
		t.Fatalf("expected id=2 ip=10.66.66.3 status=superseded, got ip=%s status=%s", supersededIP, supersededStatus)
	}

	// Verify 'other-client' remains intact
	var otherIP string
	err = db.SQLDB().QueryRowContext(ctx,
		"SELECT ip FROM awg_ip_allocations WHERE server_id = 1 AND client_id = 'other-client' AND status = 'allocated'",
	).Scan(&otherIP)
	if err != nil || otherIP != "10.66.66.4" {
		t.Fatalf("expected other-client 10.66.66.4 intact, got: %s, err: %v", otherIP, err)
	}

	// Verify unique index prevents inserting another duplicate active record
	_, err = db.SQLDB().ExecContext(ctx,
		"INSERT INTO awg_ip_allocations (server_id, client_id, ip, status, created_at, updated_at) VALUES (1, 'dup-client', '10.66.66.99', 'allocated', ?, ?)",
		now, now,
	)
	if err == nil {
		t.Fatalf("expected unique index constraint violation when inserting duplicate active client lease, got nil")
	}
	if !isUniqueConstraintError(err) {
		t.Fatalf("expected unique constraint error, got: %v", err)
	}
}

func TestAWGIPAllocations_Migration_OlderRowValid_PreservesOlderLease(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_migration_older_valid.db")

	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", dbPath)
	rawDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("failed to open raw sqlite db: %v", err)
	}

	_, err = rawDB.Exec(SchemaSQL)
	if err != nil {
		t.Fatalf("failed to init schema in raw sqlite db: %v", err)
	}
	_, err = rawDB.Exec("DROP INDEX IF EXISTS uq_awg_ip_allocations_server_client_active")
	if err != nil {
		t.Fatalf("failed to drop unique index: %v", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err = rawDB.Exec(`
		INSERT INTO users (id, username, created_at) VALUES ('u1', 'testuser1', ?);
		INSERT INTO user_connections (id, user_id, server_id, protocol, client_id, name, client_params, created_at)
		VALUES ('conn-1', 'u1', 1, 'amnezia-wg', 'test-client', 'Test Client', '{"assigned_ip": "10.66.66.2"}', ?);
		INSERT INTO awg_ip_allocations (id, server_id, client_id, ip, status, created_at, updated_at) VALUES
		(1, 1, 'test-client', '10.66.66.2', 'allocated', ?, ?),
		(2, 1, 'test-client', '10.66.66.3', 'allocated', ?, ?);
	`, now, now, now, now, now, now)
	if err != nil {
		t.Fatalf("failed to seed legacy records: %v", err)
	}
	_ = rawDB.Close()

	db, err := Open(dbPath, "")
	if err != nil {
		t.Fatalf("Open failed on legacy DB: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Assert id=1 is retained with status = 'allocated' and ip = 10.66.66.2
	var id1Status, id1IP string
	err = db.SQLDB().QueryRowContext(ctx,
		"SELECT status, ip FROM awg_ip_allocations WHERE id = 1",
	).Scan(&id1Status, &id1IP)
	if err != nil {
		t.Fatalf("failed to query id=1: %v", err)
	}
	if id1Status != "allocated" || id1IP != "10.66.66.2" {
		t.Fatalf("expected id=1 status=allocated ip=10.66.66.2, got status=%s ip=%s", id1Status, id1IP)
	}

	// Assert id=2 is preserved with status = 'superseded'
	var id2Status, id2IP string
	err = db.SQLDB().QueryRowContext(ctx,
		"SELECT status, ip FROM awg_ip_allocations WHERE id = 2",
	).Scan(&id2Status, &id2IP)
	if err != nil {
		t.Fatalf("failed to query id=2: %v", err)
	}
	if id2Status != "superseded" || id2IP != "10.66.66.3" {
		t.Fatalf("expected id=2 status=superseded ip=10.66.66.3, got status=%s ip=%s", id2Status, id2IP)
	}
}

func TestAWGIPAllocations_Migration_NewerRowValid_PreservesNewerLease(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_migration_newer_valid.db")

	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", dbPath)
	rawDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("failed to open raw sqlite db: %v", err)
	}

	_, err = rawDB.Exec(SchemaSQL)
	if err != nil {
		t.Fatalf("failed to init schema in raw sqlite db: %v", err)
	}
	_, err = rawDB.Exec("DROP INDEX IF EXISTS uq_awg_ip_allocations_server_client_active")
	if err != nil {
		t.Fatalf("failed to drop unique index: %v", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err = rawDB.Exec(`
		INSERT INTO users (id, username, created_at) VALUES ('u1', 'testuser2', ?);
		INSERT INTO user_connections (id, user_id, server_id, protocol, client_id, name, client_params, created_at)
		VALUES ('conn-2', 'u1', 1, 'amnezia-wg', 'test-client', 'Test Client', '{"assigned_ip": "10.66.66.3"}', ?);
		INSERT INTO awg_ip_allocations (id, server_id, client_id, ip, status, created_at, updated_at) VALUES
		(1, 1, 'test-client', '10.66.66.2', 'allocated', ?, ?),
		(2, 1, 'test-client', '10.66.66.3', 'allocated', ?, ?);
	`, now, now, now, now, now, now)
	if err != nil {
		t.Fatalf("failed to seed legacy records: %v", err)
	}
	_ = rawDB.Close()

	db, err := Open(dbPath, "")
	if err != nil {
		t.Fatalf("Open failed on legacy DB: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Assert id=2 is retained with status = 'allocated' and ip = 10.66.66.3
	var id2Status, id2IP string
	err = db.SQLDB().QueryRowContext(ctx,
		"SELECT status, ip FROM awg_ip_allocations WHERE id = 2",
	).Scan(&id2Status, &id2IP)
	if err != nil {
		t.Fatalf("failed to query id=2: %v", err)
	}
	if id2Status != "allocated" || id2IP != "10.66.66.3" {
		t.Fatalf("expected id=2 status=allocated ip=10.66.66.3, got status=%s ip=%s", id2Status, id2IP)
	}

	// Assert id=1 is preserved with status = 'superseded'
	var id1Status, id1IP string
	err = db.SQLDB().QueryRowContext(ctx,
		"SELECT status, ip FROM awg_ip_allocations WHERE id = 1",
	).Scan(&id1Status, &id1IP)
	if err != nil {
		t.Fatalf("failed to query id=1: %v", err)
	}
	if id1Status != "superseded" || id1IP != "10.66.66.2" {
		t.Fatalf("expected id=1 status=superseded ip=10.66.66.2, got status=%s ip=%s", id1Status, id1IP)
	}
}

func TestAdoptAWGClientIPLease_ReactivatesSupersededLease(t *testing.T) {
	db, cleanup := setupTestDBForAllocations(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)

	// Seed superseded allocation for an IP
	_, err := db.SQLDB().ExecContext(ctx,
		"INSERT INTO awg_ip_allocations (server_id, client_id, ip, status, created_at, updated_at) VALUES (1, 'old-client', '10.66.66.5', 'superseded', ?, ?)",
		now, now,
	)
	if err != nil {
		t.Fatalf("failed to seed superseded allocation: %v", err)
	}

	// Call AdoptAWGClientIPLease
	adopted, err := db.AdoptAWGClientIPLease(ctx, 1, "new-client", "", "10.66.66.5")
	if err != nil {
		t.Fatalf("AdoptAWGClientIPLease failed: %v", err)
	}
	if !adopted {
		t.Fatalf("expected adoption to succeed, got false")
	}

	// Assert status is updated to 'allocated'
	var status, clientID string
	err = db.SQLDB().QueryRowContext(ctx,
		"SELECT status, client_id FROM awg_ip_allocations WHERE server_id = 1 AND ip = '10.66.66.5'",
	).Scan(&status, &clientID)
	if err != nil {
		t.Fatalf("failed to query allocation: %v", err)
	}
	if status != "allocated" || clientID != "new-client" {
		t.Fatalf("expected status=allocated client_id=new-client, got status=%s client_id=%s", status, clientID)
	}
}

func TestAdoptAWGClientIPLease_ReconcilesDifferentLiveIP(t *testing.T) {
	db, cleanup := setupTestDBForAllocations(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)

	// Client has active allocation on 10.66.66.2
	_, err := db.SQLDB().ExecContext(ctx,
		"INSERT INTO awg_ip_allocations (server_id, client_id, ip, status, created_at, updated_at) VALUES (1, 'client-reconcile', '10.66.66.2', 'allocated', ?, ?)",
		now, now,
	)
	if err != nil {
		t.Fatalf("failed to seed active lease: %v", err)
	}

	// Adopt a different live IP 10.66.66.3
	adopted, err := db.AdoptAWGClientIPLease(ctx, 1, "client-reconcile", "", "10.66.66.3")
	if err != nil {
		t.Fatalf("adopt new live IP failed: %v", err)
	}
	if !adopted {
		t.Fatalf("expected adoption of new live IP to succeed")
	}

	// Verify old lease is superseded
	var oldStatus string
	err = db.SQLDB().QueryRowContext(ctx,
		"SELECT status FROM awg_ip_allocations WHERE server_id = 1 AND ip = '10.66.66.2'",
	).Scan(&oldStatus)
	if err != nil {
		t.Fatalf("failed to query old lease: %v", err)
	}
	if oldStatus != "superseded" {
		t.Fatalf("expected old lease status=superseded, got %s", oldStatus)
	}

	// Verify new lease is allocated
	var newStatus, newClientID string
	err = db.SQLDB().QueryRowContext(ctx,
		"SELECT status, client_id FROM awg_ip_allocations WHERE server_id = 1 AND ip = '10.66.66.3'",
	).Scan(&newStatus, &newClientID)
	if err != nil {
		t.Fatalf("failed to query new lease: %v", err)
	}
	if newStatus != "allocated" || newClientID != "client-reconcile" {
		t.Fatalf("expected new lease status=allocated client_id=client-reconcile, got status=%s client_id=%s", newStatus, newClientID)
	}
}

func TestLoadData_AWGIPAllocationsQueryFailure_AbortsBackupExport(t *testing.T) {
	db, cleanup := setupTestDBForAllocations(t)
	defer cleanup()

	ctx := context.Background()

	// 1. Open database and seed users and servers
	_, err := db.CreateServer(ctx, &models.Server{
		Name:      "Fault Injection Server",
		Host:      "192.0.2.10",
		SSHUser:   "root",
		SSHPort:   22,
		Protocols: map[string]any{"awg": map[string]any{"port": 51820}},
	})
	if err != nil {
		t.Fatalf("failed to seed test server: %v", err)
	}

	uEmail := "test_fault@example.com"
	_, err = db.CreateUser(ctx, &models.User{
		Username:     "fault_test_user",
		Email:        &uEmail,
		PasswordHash: "secret_hash",
		Role:         models.RoleUser,
		Enabled:      true,
	})
	if err != nil {
		t.Fatalf("failed to seed test user: %v", err)
	}

	// 2. Inject fault into awg_ip_allocations (drop table)
	_, err = db.SQLDB().ExecContext(ctx, "DROP TABLE awg_ip_allocations")
	if err != nil {
		t.Fatalf("failed to drop table awg_ip_allocations: %v", err)
	}

	// 3. Call db.LoadData(ctx)
	backup, err := db.LoadData(ctx)

	// 4. Assert LoadData returns non-nil error indicating failure to query AWG IP allocations
	if err == nil {
		t.Fatalf("expected error from LoadData after dropping awg_ip_allocations, got nil")
	}
	if backup != nil {
		t.Fatalf("expected nil backup on query failure, got: %+v", backup)
	}
	if !strings.Contains(err.Error(), "AWG IP allocations") {
		t.Fatalf("expected error message to mention AWG IP allocations, got: %v", err)
	}
}
