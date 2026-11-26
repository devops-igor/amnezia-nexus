package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

func TestSetupProxyAbsenceIsNotMeasuredPause(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolVLESS)
	validVLESSClientFixture(t, env)
	env.seedOrder("ord_absent_qualification", 6091, "198.51.100.71")
	env.seedManagedCredential("ord_absent_qualification")
	env.providerServes("ord_absent_qualification", 6091, "198.51.100.71")
	env.h.vpnSvc.SetEnableBackendPostAddTunnelHookForTest(func() {
		server := env.registeredServer(6091)
		if server == nil {
			t.Fatal("registered server not found")
		}
		if err := env.db.SetServerProviderAbsence(context.Background(), server.ID, time.Now().UTC(), ""); err != nil {
			t.Fatal(err)
		}
	})
	env.approve("ord_absent_qualification", models.ProtocolVLESS, "443", installFixtureFingerprint)
	env.trackerAndInstall()
	got := env.requireState("ord_absent_qualification", models.SetupStateInstallPaused)
	if got.Step != "not_measured" || got.InstallPhaseDone == models.SetupPhaseEnabled {
		t.Fatalf("refusal recorded qualification verdict: %+v", got)
	}
	tun, err := env.h.vpnSvc.GetTunnel(got.NexusServerID)
	if err != nil {
		t.Fatal(err)
	}
	if !tun.Enabled || tun.Status == models.TunnelStatusActive || tun.Status == models.TunnelStatusDegraded {
		t.Fatalf("refusal promoted or withdrew backend: %+v", tun)
	}
}

func TestProxyQualificationRefusal_PreservesEnrollment(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	db := h.db
	ctx := context.Background()
	id, err := db.CreateServer(ctx, &models.Server{Name: "qualification", Host: "192.0.2.15", SSHPort: 22})
	if err != nil {
		t.Fatal(err)
	}
	params := []byte(lateReplacementParams)
	if err := h.vpnSvc.EnableBackendWithConfig(ctx, id, tunnel.BackendTunnelOptions{Protocol: models.ProtocolVLESS, ProtocolParams: params}); err != nil {
		t.Fatal(err)
	}
	observed, err := h.vpnSvc.GetTunnel(id)
	if err != nil {
		t.Fatal(err)
	}
	before, err := db.GetBackendTunnelByServerID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	pendingBefore, err := db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetServerProviderAbsence(ctx, id, time.Now().UTC(), ""); err != nil {
		t.Fatal(err)
	}
	var calls int
	h.vpnSvc.SetProxyTrafficProbeFuncForTest(func(context.Context, *models.BackendTunnel) (int64, error) { calls++; return 3, nil })
	server, err := db.GetServer(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	err = h.qualifyProxyBackendTraffic(ctx, server, observed, models.ProtocolVLESS)
	if !errors.Is(err, tunnel.ErrProviderAbsent) || calls != 0 {
		t.Fatalf("qualification = %v, calls=%d", err, calls)
	}
	after, err := db.GetBackendTunnelByServerID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	pendingAfter, err := db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(pendingBefore, pendingAfter) {
		t.Error("refusal mutated backend/enrollment ownership or prior health")
	}
	rec := httptest.NewRecorder()
	h.writeGigahostDeployFailure(rec, nil, tunnel.ErrProviderAbsent)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"not_measured":true`) || strings.Contains(rec.Body.String(), `"failed"`) {
		t.Fatalf("HTTP refusal: %d %s", rec.Code, rec.Body.String())
	}
}
