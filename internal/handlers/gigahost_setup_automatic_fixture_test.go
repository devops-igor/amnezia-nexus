package handlers

// Shared fixtures for the unattended setup entry and its real-consumer proofs.
//
// The opt-in source is a fixture only: no production implementation of
// AutomationPolicy ships, which is what keeps the shipped binary default-off. The
// order seeders record a purchase the way the pre-purchase intent writer does, and an
// empty address is a real case rather than an omission - a fresh purchase has none
// until provisioning reports one.

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

type stubAutomationPolicy struct {
	enabled bool
	err     error
	calls   int
	mu      sync.Mutex
}

func (p *stubAutomationPolicy) Enabled(context.Context) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	return p.enabled, p.err
}

func (p *stubAutomationPolicy) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// stepHostTrustUnavailableLiteral is the step the tracker records when the host
// answered but the panel may not record its identity. It is spelled here rather than
// imported because the tracker keeps it unexported; a change to that vocabulary
// should fail this test, not silently agree with it.
const stepHostTrustUnavailableLiteral = "host_trust_unavailable"

// automaticOptions is the explicit option set the entry accepts.
var automaticOptions = AutomaticGigahostSetupOptions{
	Protocol: models.ProtocolAWG,
	Port:     "51820",
}

// enableAutomaticSetup installs the fixture opt-in on the environment's handlers.
func (e *installEnv) enableAutomaticSetup(enabled bool) *stubAutomationPolicy {
	e.t.Helper()
	policy := &stubAutomationPolicy{enabled: enabled}
	e.h.SetGigahostSetupAutomationPolicyForTest(policy)
	return policy
}

// mainDatabasePath reports the file the environment's SQLite store lives in, so a
// test can reopen the same durable state through a second connection.
func (e *installEnv) mainDatabasePath() string {
	e.t.Helper()
	rows, err := e.db.SQLDB().Query(`PRAGMA database_list`)
	if err != nil {
		e.t.Fatalf("read database list: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var seq int
	var name, path string
	for rows.Next() {
		if err := rows.Scan(&seq, &name, &path); err != nil {
			e.t.Fatalf("read database list: %v", err)
		}
		if name == "main" && strings.TrimSpace(path) != "" {
			return path
		}
	}
	e.t.Fatal("the fixture database has no file path on disk")
	return ""
}

// seedPurchasedOrder records a ledger row the way the pre-purchase intent writer
// does, which is the only provenance the unattended entry accepts.
//
// ip is written as given, and an empty ip is a real case rather than an oversight:
// a fresh purchase has no address until provisioning reports one.
func (e *installEnv) seedPurchasedOrder(orderID string, providerServerID int64, ip string) {
	e.t.Helper()
	now := time.Now().UTC()
	if err := e.db.InsertGigahostOrder(context.Background(), &models.GigahostOrder{
		OrderID: orderID, ServerID: providerServerID, Status: gigahost.StatusDeploying,
		PlanID: 7, RegionID: 3, AssignedIP: ip,
		PurchaseOrigin:     models.PurchaseOriginPanelPurchase,
		PurchaseRecordedAt: now, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		e.t.Fatalf("seed purchased order %s: %v", orderID, err)
	}
}

// seedOrderCredential stores real generated key material against the order, because
// the challenge and install paths parse it and a placeholder would fail before the
// handshake.
func (e *installEnv) seedOrderCredential(orderID string, key managedTestKey) {
	e.t.Helper()
	if err := e.db.SetGigahostOrderCredential(context.Background(), &models.GigahostOrderCredential{
		OrderID: orderID, PrivateKey: key.privPEM, PublicKey: key.pubText, ProviderKeyID: 4242,
	}); err != nil {
		e.t.Fatalf("seed credential for %s: %v", orderID, err)
	}
}

// seedAutomaticOrder records everything the unattended entry reads for one order:
// the purchase stamp, the managed credential and a provider that has an answer.
func (e *installEnv) seedAutomaticOrder(orderID string, providerServerID int64, ip string) managedTestKey {
	e.t.Helper()
	key := newManagedTestKey(e.t)
	e.seedPurchasedOrder(orderID, providerServerID, ip)
	e.seedOrderCredential(orderID, key)
	if ip != "" {
		e.providerServes(orderID, providerServerID, ip)
	}
	return key
}

// startAutomatic calls the entry with the environment's enabled policy.
func (e *installEnv) startAutomatic(orderID string, opts AutomaticGigahostSetupOptions) *models.GigahostSetupIntent {
	e.t.Helper()
	intent, created, err := e.h.StartAutomaticGigahostSetup(context.Background(), orderID, opts)
	if err != nil {
		e.t.Fatalf("start automatic setup for %s: %v", orderID, err)
	}
	if !created {
		e.t.Fatalf("start automatic setup for %s reported created=false", orderID)
	}
	return intent
}
