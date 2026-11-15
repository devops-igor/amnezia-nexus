package router

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/handlers"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

// This is the permanent regression oracle for issue #678 finding F678-02
// (round-1 audit HEAD c161a2a), the inverted successor of the auditor's
// TestAuditCanceledPutLeavesRejectedSettingsPersisted.
//
// It runs the real router with the real auth/role/CSRF middleware, the real
// handler, the real policy service and a real SQLite settings table. Only DNS is
// stalled, and only so that activation is genuinely in flight and then
// canceled at the decisive moment.

// stallPolicyDNS replaces the default resolver with one that signals when a
// lookup starts and then blocks until the caller's context is canceled, so a
// request can be canceled deterministically after its settings write committed.
func stallPolicyDNS(t *testing.T) <-chan struct{} {
	t.Helper()
	oldResolver := net.DefaultResolver
	started := make(chan struct{})
	var once sync.Once
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			once.Do(func() { close(started) })
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	t.Cleanup(func() { net.DefaultResolver = oldResolver })
	return started
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
	stalled := stallPolicyDNS(t)

	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)

	previous := policy.DefaultSettings()
	previous.Preset = policy.PresetGeoblock
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
	incoming.Preset = policy.PresetCustom
	incoming.CustomURLs = []string{"https://audit-cancel.example.invalid/list.lst"}
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
	case <-stalled:
	case <-time.After(10 * time.Second):
		t.Fatal("request never reached DNS; activation was never in flight")
	}

	// Post-commit barrier: the handler persists before activating, so the row
	// this request owns must already be the rejected one.
	var mid policy.Settings
	if err := db.GetSetting(context.Background(), policy.SettingsKey, &mid); err != nil {
		t.Fatalf("read back mid-flight settings: %v", err)
	}
	if !mid.Enabled || mid.Preset != policy.PresetCustom {
		t.Fatalf("cancellation would be vacuous: the request had not committed its record yet (got %+v)", mid)
	}

	// Cancel exactly like a client disconnect or the shipped request deadline.
	cancel()
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
	if after.Enabled || after.Preset != policy.PresetGeoblock {
		t.Fatalf("rejected settings remained durable after a canceled request (F678-02): got enabled=%t preset=%q custom=%v; a restart would treat rejected intent as authoritative",
			after.Enabled, after.Preset, after.CustomURLs)
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
	stalled := stallPolicyDNS(t)

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
	enable.Preset = policy.PresetCustom
	enable.CustomURLs = []string{"https://audit-absent.example.invalid/list.lst"}
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
	case <-stalled:
	case <-time.After(10 * time.Second):
		t.Fatal("request never reached DNS; activation was never in flight")
	}
	_, found, err := db.GetSettingRaw(context.Background(), policy.SettingsKey)
	if err != nil {
		t.Fatalf("read raw mid-flight setting: %v", err)
	}
	if !found {
		t.Fatal("cancellation would be vacuous: the request had not committed a record yet")
	}

	cancel()
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
