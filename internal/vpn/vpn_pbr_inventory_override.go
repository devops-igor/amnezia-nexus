package vpn

import "github.com/devops-igor/amnezia-nexus/internal/policy"

// This file owns the service-side state of the operator inventory override
// (issue #920): the accepted value the policy status reports and the classifier
// the live packet path consults.
//
// The value is not part of the compiled policy snapshot — it answers set
// membership for the address classifier only — so it is applied by replacing the
// installed classifier rather than by rebuilding the data path or the routing
// table. Keeping it in its own file leaves the activation and ownership of the
// data path in vpn_pbr.go unchanged.

// SetInventoryOverride records the accepted operator override and, when policy
// routing is live, installs a classifier built from it.
//
// The override is not part of the compiled policy snapshot: it answers set
// membership for the address classifier only, so it is applied to the installed
// classifier instead of rebuilding the data path. A nil override restores the
// shipped set alone.
//
// Nothing is validated here beyond the value's own construction: the settings
// record was parsed and validated before it was persisted, and the parsed value
// is immutable, so this method cannot accept a half-applied body.
func (s *Service) SetInventoryOverride(override *policy.InventoryOverride) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.inventoryOverride = override
	// The classifier is installed only while policy routing is on. With it off
	// there is no packet path to consult it, and the next activation builds its
	// own from the same record.
	if s.forwarder != nil && s.forwarder.PBREnabled() {
		s.forwarder.SetDestinationClassifier(newDestinationClassifier(override))
	}
	s.mu.Unlock()
}

// effectiveInventoryOverride returns the accepted override, nil when the
// shipped set is the only authority.
func (s *Service) effectiveInventoryOverride() *policy.InventoryOverride {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inventoryOverride
}
