package handlers

// Wiring seam between the HTTP layer and the background Gigahost setup installer.
//
// The tracker built here and in gigahost_setup_wiring.go are two background
// workers over one durable approval:
//
//   - the tracker reads the provider and settles the credential/host-trust gates;
//   - the installer performs the side-effecting install and admission steps.
//
// They are separate because their failure policies are opposite. A tracker pass
// is read-only and can be repeated freely; an install pass issues remote
// commands and must never be repeated blindly. Keeping them in one worker would
// make "read again" and "install again" the same decision.
//
// The installer is built from the same *Handlers instance the router serves, so
// a resumed attempt uses the same provider resolution, protocol registry and VPN
// service as the request path that approved it. Both are registered with the real
// application lifecycle in cmd/panel and cmd/server.

import (
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostsetup"
)

// SetGigahostInstallNudge registers the callback an explicit resume uses to
// request an immediate install pass. It is set once during application startup.
func (h *Handlers) SetGigahostInstallNudge(fn func()) {
	h.installNudge = fn
}

// NewGigahostSetupInstaller builds the installer the application supervises. It
// returns nil when there is no database or no runner to drive.
func (h *Handlers) NewGigahostSetupInstaller() *gigahostsetup.Installer {
	if h == nil || h.db == nil {
		return nil
	}
	return gigahostsetup.NewInstaller(h.db, h.NewSetupInstallRunner(), gigahostsetup.InstallOptions{
		Interval: gigahostsetup.DefaultInstallInterval,
		Batch:    gigahostsetup.DefaultInstallBatch,
	})
}

// nudgeSetupInstaller asks the background installer to run a pass now.
//
// Like the tracker's nudge it is a hint, not a mechanism: the interval sweep
// picks a claimed row up regardless, so a nil callback is a latency cost and not
// a functional gap.
func (h *Handlers) nudgeSetupInstaller() {
	if h.installNudge != nil {
		h.installNudge()
	}
}
