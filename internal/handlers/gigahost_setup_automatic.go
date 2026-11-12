package handlers

// The internal entry point that starts an unattended Gigahost setup job.
//
// Unattended setup is the one path where the panel, not an administrator, decides
// that an already placed order should be configured. Two things keep it from being
// a second and laxer approval path:
//
//   - an opt-in policy gate, consulted before anything at all is written. The zero
//     value is "not enabled": this checkpoint ships no production policy source, so
//     a deployment that never installs one cannot create an automatic job, and a
//     policy that cannot be read is a refusal rather than a default;
//   - the durable authority it records is only the *statement* that this job may
//     some day trust its own first observation. It records no binding, so the pin
//     and every install effect still have nothing authorizing them: granting the
//     binding is a separate, later decision that this entry deliberately does not
//     make.
//
// The job itself is the existing one. It is created through the same intent
// construction and the same store writer the administrator path uses, so its
// options, credential reference and state machine cannot drift from a manual job's.
// What differs is only what a manual approval cannot express: the automation
// policy, and the absence of a person.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// stepAutomaticQueued is the recorded step of a job this entry created.
//
// It says what actually happened - the job was queued by the panel, not approved by
// a person - and it is overwritten by the tracker's own progress step on the first
// pass, so it is a readable initial value rather than durable provenance. The
// durable provenance is the monotonic facts on the row: the automation policy, and
// whether a binding was ever granted.
const stepAutomaticQueued = "automatic_queued"

// ErrAutomaticSetupDisabled reports that this panel has not enabled unattended
// setup. It is a refusal, not a fault: no job was created and no authority was
// recorded, which is the deployed state of every panel that has not opted in.
var ErrAutomaticSetupDisabled = errors.New("automatic gigahost setup is not enabled on this panel")

// ErrAutomaticSetupUnavailable reports that the opt-in could not be read.
//
// It is kept distinct from ErrAutomaticSetupDisabled because the operator's question
// is different - the panel's setting could not be consulted rather than answering
// "no" - and because "could not ask" must never become consent.
var ErrAutomaticSetupUnavailable = errors.New("the automatic gigahost setup policy could not be read")

// AutomationPolicy is the durable opt-in source for unattended setup.
//
// It is an interface, and it has no production implementation in this checkpoint, so
// "off" is expressed by the absence of one. When the administrator-facing setting
// arrives it becomes a second implementation of this same question; nothing else in
// the entry has to change.
type AutomationPolicy interface {
	// Enabled reports whether an administrator has turned unattended setup on. An
	// error is not an answer: callers must refuse when it is non-nil.
	Enabled(ctx context.Context) (bool, error)
}

// SetGigahostSetupAutomationPolicyForTest installs the opt-in source.
//
// It is the seam through which the entry and its refusal path are proved against a
// real database and the real workers. No production caller exists: the shipped
// binary leaves the field nil, which is exactly the default-off deployment this
// checkpoint must not change.
func (h *Handlers) SetGigahostSetupAutomationPolicyForTest(policy AutomationPolicy) {
	h.setupAutomationPolicy = policy
}

// AutomaticGigahostSetupOptions is the explicit setup choice an internal caller
// makes for an unattended job.
//
// It deliberately has no host fingerprint and no credential selector. A person is
// not present to confirm an identity, so a pre-confirmed fingerprint would be a
// trust decision smuggled through a payload; and unattended setup only ever uses the
// credential the purchase itself stored, so there is nothing to select.
type AutomaticGigahostSetupOptions struct {
	// Protocol is the protocol to install; it is recorded, never defaulted.
	Protocol string
	// Port is the install port. Empty means the protocol's existing default, which
	// is written into the durable row so the handoff cannot disagree with it.
	Port string
	// TLSDomain and EngineProfile are carried through unchanged for the protocols
	// that use them.
	TLSDomain     string
	EngineProfile string
}

// validate rejects an option set that could not describe a real install.
//
// The protocol is held to the three the install path can actually perform, not to
// the wider set of selectable backends: an unattended job that names a protocol this
// path cannot install would be created and then stall with nobody watching, which is
// worse than refusing it here.
func (o AutomaticGigahostSetupOptions) validate() error {
	proto := models.NormalizeProtocol(strings.TrimSpace(o.Protocol))
	if proto == "" {
		return errors.New("protocol is required: an unattended setup job needs an explicit protocol (awg, vless, naive)")
	}
	switch proto {
	case models.ProtocolAWG, models.ProtocolVLESS, models.ProtocolNaive:
	default:
		return fmt.Errorf("unsupported protocol %q: unattended setup can install awg, vless or naive", o.Protocol)
	}
	if port := strings.TrimSpace(o.Port); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("port must be an integer between 1 and 65535")
		}
	}
	return nil
}

// StartAutomaticGigahostSetup records the durable job for one already placed order.
//
// The order of the checks is the point of the function:
//
//  1. the opt-in is consulted first, because a panel that has not enabled
//     unattended setup must not write anything - not even read an order;
//  2. the options must describe a real install;
//  3. the order must be a confirmed purchase of this panel, carrying the managed
//     credential that purchase stored. A foreign, imported, synthetic or
//     unresolved row is refused, and so is a real order whose credential is gone,
//     because an unattended job that cannot log in has nobody to tell;
//  4. only then is the job written.
//
// created=false answers a replay: the existing row is returned exactly as stored, so
// a repeated or concurrent call cannot create a second job, cannot re-point the first
// one, and cannot upgrade a manual, canceled or completed job into an automatic one.
//
// The returned row is intentionally allowed to have no provider address and no server
// id. Provisioning is what reveals them, and requiring them here would make the
// entry unusable at the only moment it is useful: right after the purchase.
func (h *Handlers) StartAutomaticGigahostSetup(
	ctx context.Context, orderID string, opts AutomaticGigahostSetupOptions,
) (*models.GigahostSetupIntent, bool, error) {
	if err := h.requireAutomaticSetupEnabled(ctx); err != nil {
		return nil, false, err
	}
	if err := opts.validate(); err != nil {
		return nil, false, newSetupValidationError(err.Error())
	}
	if h.db == nil {
		return nil, false, errors.New("database not available")
	}
	orderID = strings.TrimSpace(orderID)

	order, err := h.loadAutomaticSetupOrder(ctx, orderID)
	if err != nil {
		return nil, false, err
	}

	intent := buildAutomaticSetupIntent(orderID, order, opts)
	if err := h.db.CreateGigahostSetupIntent(ctx, intent); err != nil {
		if !errors.Is(err, database.ErrSetupIntentExists) {
			return nil, false, err
		}
		return h.existingAutomaticSetup(ctx, orderID, err)
	}
	h.nudgeSetupTracker()
	return intent, true, nil
}

// existingAutomaticSetup answers a call whose job already exists with the stored row,
// untouched.
//
// It is its own function because it is the opposite decision to the create path above:
// a job that already exists is somebody else's decision, and this entry returns it
// rather than acting on it. A manual approval, a completed setup and a revocation are
// all decisions this entry has no authority to overwrite or revive.
func (h *Handlers) existingAutomaticSetup(
	ctx context.Context, orderID string, cause error,
) (*models.GigahostSetupIntent, bool, error) {
	existing, found, err := h.GetGigahostSetupIntent(ctx, orderID)
	if err != nil {
		return nil, false, err
	}
	if !found {
		// The insert reported a duplicate, so the row exists unless it was removed
		// in between. Reporting the original error is the only honest answer to a
		// contradictory store.
		return nil, false, cause
	}
	return existing, false, nil
}

// requireAutomaticSetupEnabled answers the opt-in question, treating every answer
// other than an explicit "yes" as a refusal.
func (h *Handlers) requireAutomaticSetupEnabled(ctx context.Context) error {
	if h == nil || h.setupAutomationPolicy == nil {
		return ErrAutomaticSetupDisabled
	}
	enabled, err := h.setupAutomationPolicy.Enabled(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAutomaticSetupUnavailable, err)
	}
	if !enabled {
		return ErrAutomaticSetupDisabled
	}
	return nil
}

// loadAutomaticSetupOrder resolves the placed order an unattended job may reference
// and proves the two facts the job will depend on later.
//
// The "is this a real placed order" question is answered by the same helper the
// administrator path uses, so the two entries cannot disagree about which order ids
// exist. What is added is what unattended setup needs and a manual approval does not:
// the purchase provenance stamp, which is the only evidence that this panel bought
// the order, and a stored managed credential, which is the only way the job can log
// in with nobody present.
func (h *Handlers) loadAutomaticSetupOrder(ctx context.Context, orderID string) (*models.GigahostOrder, error) {
	order, err := h.loadApprovableOrder(ctx, orderID)
	if err != nil {
		return nil, err
	}
	if order.PurchaseOrigin != models.PurchaseOriginPanelPurchase {
		return nil, newSetupValidationError(fmt.Sprintf(
			"order %s is not a confirmed purchase of this panel; unattended setup is refused for it", orderID))
	}
	hasCredential, err := h.db.HasGigahostOrderCredential(ctx, orderID)
	if err != nil {
		return nil, fmt.Errorf("failed to read the managed credential for order %s: %w", orderID, err)
	}
	if !hasCredential {
		return nil, newSetupValidationError(fmt.Sprintf(
			"order %s has no managed credential; unattended setup needs the credential its purchase stored", orderID))
	}
	return order, nil
}

// buildAutomaticSetupIntent assembles the durable row through the approval
// construction, so an automatic job and a manual one are the same shape.
//
// The differences are stated, not inherited: the automation policy is recorded
// because that is what makes the job unattended, no administrator is recorded
// because none approved it, and no binding is recorded because granting one is a
// separate decision. Leaving the binding empty is what keeps the row inert: the pin
// statement requires a granted binding, so a job in this state cannot trust anything
// and cannot reach an install effect.
func buildAutomaticSetupIntent(
	orderID string, order *models.GigahostOrder, opts AutomaticGigahostSetupOptions,
) *models.GigahostSetupIntent {
	intent := buildSetupIntent(orderID, order, GigahostSetupApproveRequest{
		Protocol:           opts.Protocol,
		Port:               opts.Port,
		TLSDomain:          opts.TLSDomain,
		EngineProfile:      opts.EngineProfile,
		UseOrderCredential: true,
	}, "")
	intent.Step = stepAutomaticQueued
	intent.HostTrustPolicy = models.SetupTrustPolicyFirstContact
	return intent
}
