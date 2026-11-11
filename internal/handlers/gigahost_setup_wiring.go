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
	"errors"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
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
		Resolve:       h.ResolveGigahostSetupProvider,
		ChallengeHost: h.challengeGigahostSetupHostIdentity,
		// Automatic host trust is wired with both halves it needs: the durable pin
		// and the ownership proof. Neither is reachable from a request, so wiring
		// them here grants no job authority; a job must already carry the policy
		// before either is consulted.
		FirstContactEligible: h.firstContactEligible,
		Pinner:               h.db,
		// The current-policy gate is wired next to the trust halves, for the same
		// reason: it is a question this package cannot answer for itself, and it
		// must be asked again at each effect rather than inferred from the row.
		AutomaticEffectAllowed: h.automaticEffectPermitted,
		Interval:               gigahostsetup.DefaultInterval,
		CallTimeout:            30 * time.Second,
	})
}

// challengeGigahostSetupHostIdentity reports the SSH host identity the address
// presented, using the panel's existing trust machinery and nothing else.
//
// It calls the same verification the install path calls, with the same client
// configuration, credentials and strict host-key callback, and it stops at host
// key verification: host key checks run before authentication, so a first contact
// sends no credential and runs no command. The answer is carried by the existing
// typed challenge, which names the exact key the host presented. A host whose key
// contradicts a bound identity still raises the existing mismatch error.
//
// What comes back is a candidate for an administrator to confirm. It confers no
// authority: the challenge binds no key, records no approval and issues no
// install, and confirmation of the same value is still required.
func (h *Handlers) challengeGigahostSetupHostIdentity(
	ctx context.Context, intent models.GigahostSetupIntent,
) (string, error) {
	req, err := h.buildChallengeRequest(ctx, intent)
	if err != nil {
		return "", err
	}
	fingerprint, err := h.verifyDeploySSHAccess(ctx, req.AssignedIP, req)
	if err == nil {
		// A registered server with a bound identity: the presented key already
		// matches it, and the verification returned that same value.
		return fingerprint, nil
	}
	var required *ssh.ErrFingerprintRequired
	if errors.As(err, &required) && validateFingerprintFormat(required.Fingerprint) == nil {
		// First contact: the typed challenge is the answer.
		return required.Fingerprint, nil
	}
	return "", err
}

// buildChallengeRequest assembles the credential the challenge needs. It reuses
// the install path's own request builder so the challenge observes the host with
// the same identity and options the install would use.
func (h *Handlers) buildChallengeRequest(
	ctx context.Context, intent models.GigahostSetupIntent,
) (GigahostDeployRequest, error) {
	req := GigahostDeployRequest{
		OrderID:          intent.OrderID,
		ProviderServerID: intent.ProviderServerID,
		AssignedIP:       strings.TrimSpace(intent.AssignedIP),
		Protocol:         intent.EffectiveProtocol(),
		Port:             intent.Port,
	}
	if req.AssignedIP == "" || req.ProviderServerID <= 0 {
		return req, errors.New("the approval has no provider address or server identity to challenge")
	}
	if intent.CredentialMode == models.SetupCredentialManaged {
		req.UseOrderCredential = true
	}
	return h.applyStoredOrderCredential(ctx, req)
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
