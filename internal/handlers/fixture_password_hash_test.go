package handlers

// Precomputed cost-12 bcrypt hashes for test credentials (issue #803).
//
// These scenarios only need an existing authenticated identity, not the work of
// generating a hash: each production HashPassword call cost seconds under
// -race. The hashes were produced by security.HashPassword with its unchanged
// cost 12; internal/security keeps exercising generation and the genuine Python
// compatibility vectors. A missing entry fails the test rather than hashing
// silently, so a new password cannot quietly reintroduce the cost.

import (
	"strings"
	"testing"
)

var fixturePasswordHashes = map[string]string{
	"AdminPass123!":   "$2a$12$/R3nJohLqWEXDWSrd8gviu78P2PbXonS9Rxh7SVWf9.mQrM64IsWC",
	"UserPass123!":    "$2a$12$n30C3zMNP9ljPPqaU98J7eZS3v/r/ulb7hkW.TmX0HVUIk7zueiXq",
	"TestPass123!":    "$2a$12$OkUeNwZhgJrB5ZAeIUIbL.6fdm5gArl9Kfjrf.VQnIEwHHJaIFrQC",
	"CurrentPass123!": "$2a$12$vD/WGyy0uYounL0WIFBaneBKrhJQRc0Ahd02hcP7QfoimknNR.0my",
	"Pass123!Safe":    "$2a$12$6aiAiRIQ.6fQyrOe6wA9R.Z8L/67vweWhS.MOR0dUJOV81RBcl3da",
	"TargetPass123!":  "$2a$12$DuZ1AffJLDTH8vmZhJ1L/.35O8zYfl9cvoUyW2u.RKRicGZS9h8Za",
	"ShareSecret123!": "$2a$12$8Sg24Wz0eFezFLko.I.tzOCBRvAmAxeoEvMSdGXiZB7s1IAGfL9Ui",
}

func fixturePasswordHash(t *testing.T, password string) string {
	t.Helper()
	hash, ok := fixturePasswordHashes[password]
	if !ok {
		t.Fatalf("no precomputed cost-12 fixture hash for %q", password)
	}
	return hash
}

// TestFixturePasswordHashesRemainCost12 keeps the optimization inside its
// boundary: a fixture may skip generation, but it may not lower the bcrypt
// parameter. The login tests verify these hashes against the real password
// path; this check only guards the prefix, so it adds no hashing cost.
func TestFixturePasswordHashesRemainCost12(t *testing.T) {
	for password, hash := range fixturePasswordHashes {
		if !strings.HasPrefix(hash, "$2a$12$") {
			t.Errorf("fixture hash for %q has prefix %q, want a cost-12 bcrypt hash", password, hash[:min(len(hash), 7)])
		}
	}
}
