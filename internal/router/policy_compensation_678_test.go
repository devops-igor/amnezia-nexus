package router

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/handlers"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// This is the permanent regression oracle for issue #678 finding F678-02
// (round-1 audit HEAD c161a2a), the inverted successor of the auditor's
// TestAuditCanceledPutLeavesRejectedSettingsPersisted.
//
// It runs the real router with the real auth/role/CSRF middleware, the real
// handler, the real policy service and a real SQLite settings table. Only the WAN
// packet device is substituted, and only so that activation is genuinely in flight
// and then canceled at the decisive moment.
//
// There is no fetched source any more, so the activation work that can be held is
// the device acquisition: the production constructor is replaced by one that
// signals when it is entered and then waits for the test. That keeps the window
// between "the record is durable" and "activation finished" real.

// activationStall holds the production WAN device constructor open, so a request
// can be canceled deterministically after its settings write committed and while
// activation is still in flight. Releasing it makes activation fail at that
// prerequisite, which is what puts the compensation path under a canceled request
// context — the exact F678-02 condition.
type activationStall struct {
	started <-chan struct{}
	release func()
}

func stallPolicyActivation(t *testing.T) activationStall {
	t.Helper()
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var releaseOnce sync.Once
	t.Cleanup(vpn.SetWANDeviceFactoryForTest(func(string) (forwarder.PacketDevice, error) {
		once.Do(func() { close(started) })
		<-release
		return nil, errors.New("activation refused: the data path is unavailable")
	}))
	return activationStall{
		started: started,
		release: func() { releaseOnce.Do(func() { close(release) }) },
	}
}

// TestCanceledPutDoesNotLeaveRejectedSettingsPersisted is the F678-02 regression.
//
// RED on c161a2a: the rollback reused the request context, which is already
// canceled by the time activation fails (client disconnect, or the shipped
// 60-second OperationTimeout). database/sql refuses that write, so the rejected
// enabled/custom record stayed durable while the runtime stayed disabled — and
// the next boot would treat the rejected intent as authoritative.
//
// The post-commit barrier is deliberate: the test reads the row back and requires
// it to be the rejected record BEFORE cancelling. Without that check the
// cancellation could land before any write and the test would pass vacuously.
func TestCanceledPutDoesNotLeaveRejectedSettingsPersisted(t *testing.T) {
	stall := stallPolicyActivation(t)
	t.Cleanup(stall.release)

	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)

	previous := policy.DefaultSettings()
	previous.ProxyExceptions = []string{"203.0.113.0/24"}
	if err := db.SetSetting(context.Background(), policy.SettingsKey, previous); err != nil {
		t.Fatalf("seed policy settings: %v", err)
	}

	svc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	t.Cleanup(svc.StopPolicyRouting)
	r := NewRouterWithDeps(handlers.Dependencies{Config: cfg, DB: db, VPNService: svc})

	incoming := previous
	incoming.Enabled = true
	incoming.ProxyExceptions = []string{"198.51.100.0/24"}
	body, err := json.Marshal(incoming)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	req := adminRequest(t, http.MethodPut, "/api/vpn/policy", body)
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.ServeHTTP(w, req)
	}()

	select {
	case <-stall.started:
	case <-time.After(10 * time.Second):
		t.Fatal("request never reached activation; it was never in flight")
	}

	// Post-commit barrier: the handler persists before activating, so the row
	// this request owns must already be the rejected one.
	var mid policy.Settings
	if err := db.GetSetting(context.Background(), policy.SettingsKey, &mid); err != nil {
		t.Fatalf("read back mid-flight settings: %v", err)
	}
	if !mid.Enabled || len(mid.ProxyExceptions) != 1 || mid.ProxyExceptions[0] != "198.51.100.0/24" {
		t.Fatalf("cancellation would be vacuous: the request had not committed its record yet (got %+v)", mid)
	}

	// Cancel exactly like a client disconnect or the shipped request deadline,
	// then let activation fail at its prerequisite. The compensation that follows
	// runs with the request already canceled, which is the defect this pins.
	cancel()
	stall.release()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("canceled request did not return")
	}

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("canceled PUT = %d, want 422; body=%s", w.Code, w.Body.String())
	}

	// The decisive assertion: the rejected record must NOT be durable. A fresh
	// read with an independent context is what a restart's settings loader does.
	var after policy.Settings
	if err := db.GetSetting(context.Background(), policy.SettingsKey, &after); err != nil {
		t.Fatalf("read back settings after cancellation: %v", err)
	}
	if after.Enabled || len(after.ProxyExceptions) != 1 || after.ProxyExceptions[0] != "203.0.113.0/24" {
		t.Fatalf("rejected settings remained durable after a canceled request (F678-02): got enabled=%t exceptions=%v; a restart would treat rejected intent as authoritative",
			after.Enabled, after.ProxyExceptions)
	}
	if svc.PBREnabled() {
		t.Fatal("rejected activation still left PBR enabled")
	}
}

// TestRejectedEnableWithAbsentPreviousRowRemovesTheRow is the adjacent control
// for F678-02: when there was no durable record before the request, compensation
// must restore "absent" rather than materialize a default row. Otherwise the
// fresh-install default would be persisted as if an operator had set it.
func TestRejectedEnableWithAbsentPreviousRowRemovesTheRow(t *testing.T) {
	stall := stallPolicyActivation(t)
	t.Cleanup(stall.release)

	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)

	svc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	t.Cleanup(svc.StopPolicyRouting)
	r := NewRouterWithDeps(handlers.Dependencies{Config: cfg, DB: db, VPNService: svc})

	enable := policy.DefaultSettings()
	enable.Enabled = true
	enable.ProxyExceptions = []string{"203.0.113.0/24"}
	body, err := json.Marshal(enable)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	req := adminRequest(t, http.MethodPut, "/api/vpn/policy", body)
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.ServeHTTP(w, req)
	}()

	select {
	case <-stall.started:
	case <-time.After(10 * time.Second):
		t.Fatal("request never reached activation; it was never in flight")
	}
	_, found, err := db.GetSettingRaw(context.Background(), policy.SettingsKey)
	if err != nil {
		t.Fatalf("read raw mid-flight setting: %v", err)
	}
	if !found {
		t.Fatal("cancellation would be vacuous: the request had not committed a record yet")
	}

	cancel()
	stall.release()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("canceled request did not return")
	}
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("canceled PUT = %d, want 422; body=%s", w.Code, w.Body.String())
	}

	raw, found, err := db.GetSettingRaw(context.Background(), policy.SettingsKey)
	if err != nil {
		t.Fatalf("read raw setting after cancellation: %v", err)
	}
	if found && raw.Valid && raw.String != "" {
		t.Fatalf("compensation materialized a record where none existed before: %q", raw.String)
	}
	if svc.PBREnabled() {
		t.Fatal("rejected activation still left PBR enabled")
	}
}
