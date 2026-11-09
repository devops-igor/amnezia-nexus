package models

import (
	"strings"
	"time"
)

// Durable setup-intent states.
//
// The intent is the administrator's explicit approval to set up one already
// placed order, plus the progress of the provider provisioning that has to
// finish first. It is tracked by a background worker, so it must describe
// itself completely without any browser or request being open.
//
// The states below are the whole lifecycle of this checkpoint. Installer
// effects are deliberately absent: ready_for_setup is a handoff, and the
// installer workflow that consumes it is a separate piece of work.
const (
	// SetupStatePending means the approval is recorded and the provider has not
	// yet reported a terminal provisioning result. A provider read failure
	// leaves the row here too: an unreadable provider is not an answer.
	SetupStatePending = "pending"
	// SetupStateAwaitingHostConfirm means provisioning finished but the SSH host
	// identity for this provider server is neither confirmed by the approval nor
	// already bound to a registered server. Trust pauses work here.
	SetupStateAwaitingHostConfirm = "awaiting_host_confirmation"
	// SetupStateAwaitingCredentials means provisioning finished but no usable
	// credential reference exists for the order, so setup cannot log in. The
	// operator supplies credentials out of band; nothing is stored.
	SetupStateAwaitingCredentials = "awaiting_credentials"
	// SetupStateReadyForSetup means the provider server is ready, associated with
	// this exact order, and its credential and host trust are settled. This is
	// the handoff point; no installer has run.
	SetupStateReadyForSetup = "ready_for_setup"
	// SetupStateFailed means the provider reported a terminal failure. The order
	// and the VPS are kept; nothing is canceled or deleted.
	SetupStateFailed = "failed"
	// SetupStateCanceled means the administrator revoked the approval. No
	// further panel effects may follow from this intent.
	SetupStateCanceled = "canceled"
)

// Credential modes recorded on a setup intent.
//
// Only a reference is ever stored. A pasted password or private key is never
// persisted here: managed means the order already carries an encrypted
// credential, manual means the operator must supply one when setup runs.
const (
	SetupCredentialManaged = "managed"
	SetupCredentialManual  = "manual"
)

// GigahostSetupIntent is the durable, administrator-approved setup job for one
// Gigahost order.
//
// It reuses the existing order identity rather than introducing a second one:
// order_id is the provider order the row belongs to, exactly as recorded in the
// order ledger. ProviderServerID and AssignedIP are filled in as the provider
// reveals them and are never guessed.
//
// ProviderStatus is the last status the provider actually reported. A read that
// fails records LastError and ReadFailures and leaves ProviderStatus alone, so
// "the provider said it is provisioning" and "we could not ask" stay distinct.
type GigahostSetupIntent struct {
	ID               int64  `json:"id"`
	OrderID          string `json:"order_id"`
	ProviderServerID int64  `json:"provider_server_id,omitempty"`
	AssignedIP       string `json:"assigned_ip,omitempty"`

	// Selected setup options, recorded from the administrator's explicit
	// approval. They are what handoff will use; nothing is defaulted here.
	Protocol      string `json:"protocol"`
	Port          string `json:"port"`
	TLSDomain     string `json:"tls_domain,omitempty"`
	EngineProfile string `json:"engine_profile,omitempty"`

	// CredentialMode is a reference, never material. See SetupCredential*.
	CredentialMode string `json:"credential_mode"`

	State          string `json:"state"`
	ProviderStatus string `json:"provider_status,omitempty"`
	Step           string `json:"step,omitempty"`
	LastError      string `json:"last_error,omitempty"`

	// HostFingerprint is the identity the administrator confirmed for this
	// server, when the approval carried one. HostMismatch reports that a
	// registered server's bound identity contradicts it.
	HostFingerprint string `json:"host_fingerprint,omitempty"`
	HostMismatch    bool   `json:"host_mismatch,omitempty"`

	// ReadFailures counts consecutive provider read failures and resets on the
	// next successful read. Attempts counts every scheduled provider read.
	ReadFailures int `json:"read_failures"`
	Attempts     int `json:"attempts"`

	// NextAttemptAt is when the tracker may read the provider again. It is
	// persisted so a restart neither hammers the provider nor waits a full
	// interval for work that is already due.
	NextAttemptAt time.Time `json:"next_attempt_at,omitempty"`
	LastCheckedAt time.Time `json:"last_checked_at,omitempty"`

	// ApprovedBy is the administrator who recorded the approval.
	ApprovedBy string    `json:"approved_by,omitempty"`
	RevokedAt  time.Time `json:"revoked_at,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// IsTrackable reports whether the background worker still owes this intent a
// provider read.
func (i *GigahostSetupIntent) IsTrackable() bool {
	return i != nil && i.State == SetupStatePending
}

// IsSettled reports whether the intent reached a state no further automatic
// work follows from.
func (i *GigahostSetupIntent) IsSettled() bool {
	if i == nil {
		return false
	}
	switch i.State {
	case SetupStateReadyForSetup, SetupStateFailed, SetupStateCanceled,
		SetupStateAwaitingHostConfirm, SetupStateAwaitingCredentials:
		return true
	default:
		return false
	}
}

// IsCanceled reports whether the administrator revoked this approval.
func (i *GigahostSetupIntent) IsCanceled() bool {
	return i != nil && i.State == SetupStateCanceled
}

// NeedsOperator reports whether the intent is paused waiting for the
// administrator rather than progressing on its own.
func (i *GigahostSetupIntent) NeedsOperator() bool {
	if i == nil {
		return false
	}
	switch i.State {
	case SetupStateAwaitingHostConfirm, SetupStateAwaitingCredentials:
		return true
	default:
		return false
	}
}

// EffectiveProtocol returns the recorded protocol, normalized.
func (i *GigahostSetupIntent) EffectiveProtocol() string {
	if i == nil {
		return ""
	}
	return NormalizeProtocol(strings.TrimSpace(i.Protocol))
}
