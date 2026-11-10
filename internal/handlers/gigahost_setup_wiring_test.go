package handlers

// Tests for the read-only provider wrapper the tracker uses.
//
// The wrapper is what makes "the background tracker cannot place an order" a
// compile-time fact rather than a convention: it exposes exactly two reads. These
// tests pin both halves of that claim — the reads forward correctly, and there is
// no write method to forward to.

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostsetup"
)

// TestReadOnlyProviderForwardsTheTwoReads proves the wrapper forwards both reads
// to the underlying client with the same arguments and results.
func TestReadOnlyProviderForwardsTheTwoReads(t *testing.T) {
	wantStatus := &gigahost.DeployStatusResponse{OrderID: "ord_w", Status: gigahost.StatusReady}
	wantServers := []gigahost.ServerInfo{{ID: 7, OrderID: "ord_w"}}

	var gotOrderID string
	inner := &mockGigahostClient{
		getDeployStatusFn: func(_ context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
			gotOrderID = orderID
			return wantStatus, nil
		},
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			return wantServers, nil
		},
	}
	wrapper := readOnlyGigahostProvider{client: inner}

	status, err := wrapper.GetDeployStatus(context.Background(), "ord_w")
	if err != nil {
		t.Fatalf("GetDeployStatus: %v", err)
	}
	if status != wantStatus || gotOrderID != "ord_w" {
		t.Fatalf("status not forwarded: %+v orderID=%q", status, gotOrderID)
	}
	servers, err := wrapper.GetServers(context.Background())
	if err != nil {
		t.Fatalf("GetServers: %v", err)
	}
	if len(servers) != 1 || servers[0].ID != 7 {
		t.Fatalf("servers not forwarded: %+v", servers)
	}
}

// TestReadOnlyProviderExposesNoWriteMethod is the structural claim: the interface
// the tracker holds has no ordering, cancellation or key-registration method, so
// no code path in the tracker can cause a provider write.
func TestReadOnlyProviderExposesNoWriteMethod(t *testing.T) {
	iface := reflect.TypeOf((*gigahostsetup.ProviderReader)(nil)).Elem()
	var methods []string
	for i := 0; i < iface.NumMethod(); i++ {
		methods = append(methods, iface.Method(i).Name)
	}
	want := map[string]bool{"GetDeployStatus": true, "GetServers": true}
	if len(methods) != len(want) {
		t.Fatalf("ProviderReader methods = %v, want exactly the two reads", methods)
	}
	for _, m := range methods {
		if !want[m] {
			t.Fatalf("ProviderReader exposes %q, which is not a read", m)
		}
	}
}

// TestReadOnlyProviderWithoutClientReportsUnavailable proves a nil inner client
// is an explicit "unavailable" rather than a panic or a zero-value success.
func TestReadOnlyProviderWithoutClientReportsUnavailable(t *testing.T) {
	wrapper := readOnlyGigahostProvider{}
	if _, err := wrapper.GetDeployStatus(context.Background(), "ord"); !errors.Is(err, gigahostsetup.ErrProviderUnavailable) {
		t.Fatalf("GetDeployStatus error = %v, want ErrProviderUnavailable", err)
	}
	if _, err := wrapper.GetServers(context.Background()); !errors.Is(err, gigahostsetup.ErrProviderUnavailable) {
		t.Fatalf("GetServers error = %v, want ErrProviderUnavailable", err)
	}
}

// TestResolveSetupProviderUsesHandlerClient proves the tracker resolves the
// provider through the handler's own client, so the approval path and the tracker
// cannot disagree about which account they read.
func TestResolveSetupProviderUsesHandlerClient(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	inner := &mockGigahostClient{
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{Status: gigahost.StatusReady}, nil
		},
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{{ID: 9}}, nil
		},
	}
	h.SetGigahostClient(inner)

	reader, err := h.ResolveGigahostSetupProvider(context.Background())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	status, err := reader.GetDeployStatus(context.Background(), "ord_r")
	if err != nil || status.Status != gigahost.StatusReady {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	servers, err := reader.GetServers(context.Background())
	if err != nil || len(servers) != 1 {
		t.Fatalf("servers=%+v err=%v", servers, err)
	}
}

// TestResolveSetupProviderWithoutKeyIsUnavailable proves an unconfigured panel is
// reported as unavailable, which the tracker records as "could not ask" instead
// of mistaking it for a provider answer.
func TestResolveSetupProviderWithoutKeyIsUnavailable(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	h.SetGigahostClient(nil)
	t.Setenv("GIGAHOST_API_KEY", "")

	if _, err := h.ResolveGigahostSetupProvider(context.Background()); !errors.Is(err, gigahostsetup.ErrProviderUnavailable) {
		t.Fatalf("resolve error = %v, want ErrProviderUnavailable", err)
	}
}

// TestNewSetupTrackerReturnsNilWithoutDatabase proves the tracker is only built
// when there is something to track against, so startup cannot register a worker
// that can never work.
func TestNewSetupTrackerReturnsNilWithoutDatabase(t *testing.T) {
	h := NewHandlers(Dependencies{})
	if tracker := h.NewGigahostSetupTracker(); tracker != nil {
		t.Fatalf("tracker built without a database: %+v", tracker)
	}
	var nilHandlers *Handlers
	if tracker := nilHandlers.NewGigahostSetupTracker(); tracker != nil {
		t.Fatal("tracker built from a nil handler")
	}

	h, _, _ = setupTestHandlers(t)
	tracker := h.NewGigahostSetupTracker()
	if tracker == nil {
		t.Fatal("tracker not built for a real database")
	}
	if tracker.Name() != "gigahost-setup-tracker" {
		t.Fatalf("name = %q", tracker.Name())
	}
}
