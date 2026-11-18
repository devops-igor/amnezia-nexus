package vpn

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// TestRestartRefusesStoredOperatorExcludedDomainOnFetchFailure covers the vpn
// half of #892: the activation path must pass the syncer's guard (built-in plus
// operator exclusions) into the baseline decision. A stored generation written
// before the exclusion is not valid rules for the current settings.
func TestRestartRefusesStoredOperatorExcludedDomainOnFetchFailure(t *testing.T) {
	server := newPolicyListServer(t)

	settings := policyListSettings(t)
	settings.ExcludedDomains = []string{"custom.example"}
	cfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	fetch, store := fixtureFetcherAndStore(t, server, cfg)
	ctx := context.Background()

	matcher := policy.NewMatcher()
	syncer, err := policy.NewSyncer(matcher, fetch, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	gen := &policy.Generation{
		SchemaVersion: policy.SchemaVersion,
		GenerationID:  "gen-before-operator-exclusion",
		Version:       2,
		ConfigHash:    syncer.ConfigHash(),
		Domains: map[string]uint32{
			"custom.example":  2,
			"allowed.example": 2,
		},
	}
	if err := store.Commit(ctx, gen); err != nil {
		t.Fatalf("seed excluded generation: %v", err)
	}

	// The upstream is gone, so the stored generation is the only candidate.
	server.Close()

	activationErr := ensureInitialSnapshot(ctx, syncer, store, matcher)
	if activationErr == nil {
		t.Fatal("activation published a stored generation containing an operator-excluded domain")
	}
	if !errors.Is(activationErr, ErrPolicyActivationNoRules) {
		t.Fatalf("activation error = %v, want ErrPolicyActivationNoRules", activationErr)
	}
	if !strings.Contains(activationErr.Error(), "never-proxy") {
		t.Fatalf("refusal does not name the never-proxy cause: %v", activationErr)
	}
	if matcher.Current() != nil {
		t.Fatal("the excluded stored generation reached the live matcher")
	}
}
