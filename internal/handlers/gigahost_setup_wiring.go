package handlers

// Wiring seam between the HTTP layer and the background Gigahost setup tracker.
//
// Provisioning takes far longer than a browser session, so the progress cannot
// live in a request. The tracker that owns it is a supervised background worker
// built here from the same Handlers instance the router serves, which is what
// keeps the two sides in agreement:
//
//   - one provider resolution, so an approval recorded through the panel and the
//     tracker's reads always refer to the same provider account;
//   - one tracker, so a second approval cannot double the provider reads or race
//     another pass's progress writes on the same row.
//
// The tracker is started by the real application lifecycle (cmd/panel and
// cmd/server register it with the supervisor at startup), never by a request and
// never only by a test.

import (
	"context"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostsetup"
)

// SetGigahostSetupNudge registers the callback a new approval uses to request an
// immediate tracking pass. It is set once during application startup.
func (h *Handlers) SetGigahostSetupNudge(fn func()) {
	h.setupNudge = fn
}

// NewGigahostSetupTracker builds the tracker the application supervises over this
// handler's database and provider resolution. It returns nil when there is no
// database to track against.
func (h *Handlers) NewGigahostSetupTracker() *gigahostsetup.Tracker {
	if h == nil || h.db == nil {
		return nil
	}
	return gigahostsetup.New(h.db, gigahostsetup.Options{
		Resolve:     h.ResolveGigahostSetupProvider,
		Interval:    gigahostsetup.DefaultInterval,
		CallTimeout: 30 * time.Second,
	})
}

// ResolveGigahostSetupProvider returns a read-only provider reader built from the
// same credential resolution the request path uses.
//
// A missing API key is reported as ErrProviderUnavailable so the tracker records
// "could not ask" and leaves intents pending, rather than mistaking an
// unconfigured panel for a provisioned server.
func (h *Handlers) ResolveGigahostSetupProvider(ctx context.Context) (gigahostsetup.ProviderReader, error) {
	client, err := h.getGigahostClient(ctx, nil)
	if err != nil {
		return nil, gigahostsetup.ErrProviderUnavailable
	}
	return readOnlyGigahostProvider{client: client}, nil
}

// readOnlyGigahostProvider narrows a gigahost.Client to the two reads the tracker
// is allowed to perform. Wrapping rather than storing the full interface is what
// makes "the tracker cannot place an order" a compile-time fact.
type readOnlyGigahostProvider struct {
	client gigahost.Client
}

func (p readOnlyGigahostProvider) GetDeployStatus(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
	if p.client == nil {
		return nil, gigahostsetup.ErrProviderUnavailable
	}
	return p.client.GetDeployStatus(ctx, orderID)
}

func (p readOnlyGigahostProvider) GetServers(ctx context.Context) ([]gigahost.ServerInfo, error) {
	if p.client == nil {
		return nil, gigahostsetup.ErrProviderUnavailable
	}
	return p.client.GetServers(ctx)
}
