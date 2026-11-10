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
	// this exact order, and its credential and host trust are settled. It is the
	// install handoff point: a claimed install (below) may pick it up.
	SetupStateReadyForSetup = "ready_for_setup"
	// SetupStateInstalling means one install attempt owns this row. It records a
	// generation, so a worker that lost its claim cannot issue further remote
	// commands. A row still in this state when a pass begins is a leftover claim
	// from an attempt that never finished; its effects must be verified, never
	// replayed blindly.
	SetupStateInstalling = "installing"
	// SetupStateInstallPaused means an install attempt stopped without a proven
	// outcome, or could not continue safely (missing credential, changed host,
	// failed step, unverifiable partial effect). Progressing again requires an
	// explicit administrator resume; nothing retries this on its own.
	SetupStateInstallPaused = "install_paused"
	// SetupStateReady means the selected protocol is installed, the backend was
	// admitted only after real traffic qualification, and the order is complete.
	// An admitted backend is removed through the existing backend disable path,
	// not by revoking the setup approval.
	SetupStateReady = "ready"
	// SetupStateFailed means the provider reported a terminal failure. The order
	// and the VPS are kept; nothing is canceled or deleted.
	SetupStateFailed = "failed"
	// SetupStateCanceled means the administrator revoked the approval. No
	// further panel effects may follow from this intent.
	SetupStateCanceled = "canceled"
)

// Install phases, recorded durably around every side-effecting install step.
//
// The pair (install_phase, install_phase_done) is the crash journal: phase names
// the step that was in flight, phase_done names the last step whose effect is
// proven complete. A restart reads the pair and either proves the in-flight step
// finished or pauses, so a completed remote command is never re-issued.
const (
	SetupPhaseVerified   = "ssh_verified"
	SetupPhaseRegistered = "server_registered"
	SetupPhaseInstalled  = "protocol_installed"
	SetupPhaseEnabled    = "backend_enabled"
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
	// HostCandidateFingerprint is the identity the panel observed on its own
	// read-only first-contact challenge, and nothing more. It exists so an
	// administrator can be shown exactly which identity the address presented;
	// it authorizes nothing, and confirmation is accepted only for this exact
	// value. It is cleared when a confirmation records HostFingerprint.
	HostCandidateFingerprint string `json:"host_candidate_fingerprint,omitempty"`

	// ReadFailures counts consecutive provider read failures and resets on the
	// next successful read. Attempts counts every scheduled provider read.
	ReadFailures int `json:"read_failures"`
	Attempts     int `json:"attempts"`

	// InstallGeneration is the fencing token of the install attempt that owns
	// this row. Every remote command is issued only by the attempt holding the
	// current generation, so a worker that was superseded cannot keep acting.
	InstallGeneration int64 `json:"install_generation"`
	// InstallPhase is the side-effecting step that was in flight, and
	// InstallPhaseDone the last one whose effect is proven complete. Together
	// they are the crash journal read on restart.
	InstallPhase     string `json:"install_phase,omitempty"`
	InstallPhaseDone string `json:"install_phase_done,omitempty"`
	// InstallAttempts counts how many times an install was started, so an
	// operator can see that a paused job has already been tried.
	InstallAttempts int `json:"install_attempts"`
	// NexusServerID is the registered panel server once registration completed.
	// It is 0 before registration, and it is the identity a resumed install
	// must find rather than create.
	NexusServerID int64 `json:"nexus_server_id,omitempty"`

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
	case SetupStateReadyForSetup, SetupStateReady, SetupStateFailed, SetupStateCanceled,
		SetupStateAwaitingHostConfirm, SetupStateAwaitingCredentials,
		SetupStateInstallPaused:
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
	case SetupStateAwaitingHostConfirm, SetupStateAwaitingCredentials, SetupStateInstallPaused:
		return true
	default:
		return false
	}
}

// IsInstallable reports whether the intent is at the install handoff point and a
// pass may claim it.
func (i *GigahostSetupIntent) IsInstallable() bool {
	return i != nil && i.State == SetupStateReadyForSetup
}

// IsInstalling reports whether an install attempt currently owns this row.
func (i *GigahostSetupIntent) IsInstalling() bool {
	return i != nil && i.State == SetupStateInstalling
}

// EffectiveProtocol returns the recorded protocol, normalized.
func (i *GigahostSetupIntent) EffectiveProtocol() string {
	if i == nil {
		return ""
	}
	return NormalizeProtocol(strings.TrimSpace(i.Protocol))
}
