package awg

import (
	"fmt"
	"strings"
)

// AllocationKey returns the single identity under which an AWG IP allocation is
// stored and looked up: the client public key when one is supplied, otherwise
// the explicit client identifier.
//
// The public key is authoritative because every existing awg_ip_allocations row
// and every current call site already resolves to it. Allocation stores the
// value this function returns and release looks the row up by the same value, so
// a row can never be stored under an identity that release does not search for.
func AllocationKey(clientID, clientPubKey string) string {
	if pubKey := strings.TrimSpace(clientPubKey); pubKey != "" {
		return pubKey
	}
	return strings.TrimSpace(clientID)
}

// validateAllocationIdentity refuses an explicit client identifier that names a
// different client than the supplied public key.
//
// AllocationKey would otherwise store the row under the public key and drop the
// explicit identifier, so a later release made through that identifier would
// match no row and leave the address reserved with no trace of why. The conflict
// is reported at the boundary that accepted the identifier (the client-add path)
// rather than silently resolved there.
func validateAllocationIdentity(clientID, clientPubKey string) error {
	explicitID := strings.TrimSpace(clientID)
	pubKey := strings.TrimSpace(clientPubKey)
	if explicitID == "" || pubKey == "" || explicitID == pubKey {
		return nil
	}
	return fmt.Errorf(
		"AWG client identity conflict: explicit client_id %q does not match client public key %q; allocations are keyed by the public key",
		explicitID, pubKey,
	)
}

// resolveEffectiveClientID derives the identity that both allocation and release
// use for this client, through the same AllocationKey rule that stores the row.
// An explicit client_id that names a different client than the public key is
// refused here, before any remote mutation or allocation.
//
// It lives beside AllocationKey so that the storage identity, the refusal and
// the identity handed to allocation and release are one decision in one place.
func resolveEffectiveClientID(clientParams map[string]any, clientPubKey string) (string, error) {
	explicitID := ""
	if cid, ok := clientParams["client_id"].(string); ok {
		explicitID = cid
	}
	if err := validateAllocationIdentity(explicitID, clientPubKey); err != nil {
		return "", err
	}
	return AllocationKey(explicitID, clientPubKey), nil
}
