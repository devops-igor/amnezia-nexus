package vpn

// Activation over a cache an earlier build wrote.
//
// FileStore.Load refused a valid predecessor last-known-good generation, so
// activation failed before PrimeBaseline could recognize it as belonging to a
// different configuration and rebuild from the operator's local rules. The
// installation then stayed on all-proxy behaviour after an upgrade even though the
// operator had saved usable IPv4 exceptions.
//
// The fixture is the predecessor build's own bytes (produced by its own Commit, in
// the policy package's testdata), installed in a real directory and read by the real
// FileStore through the real activation entry point. The fresh-store case and the
// corrupt-cache case are the controls: one proves the fix did not make activation
// depend on a cache existing at all, the other that the corruption guard survives.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// predecessorCacheFixture is the durable policy file an earlier release wrote.
const predecessorCacheFixture = "../policy/testdata/policy_lkg_predecessor.json"

// installCache copies one cache file into a fresh directory and returns a store
// over it.
func installCache(t *testing.T, source string) (policy.Store, string) {
	t.Helper()
	body, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read the cache fixture %s: %v", source, err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policy_lkg.json"), body, 0600); err != nil {
		t.Fatalf("install the cache: %v", err)
	}
	return policy.NewFileStore(dir), dir
}

// activateWithStore runs the production activation entry point against one store.
func activateWithStore(t *testing.T, store policy.Store, entries ...string) (error, bool) {
	t.Helper()
	svc := serviceForActivation(t)
	t.Cleanup(func() { svc.StopPolicyRouting() })
	t.Cleanup(SetWANDeviceFactoryForTest(func(string) (forwarder.PacketDevice, error) {
		return noopWANDevice{}, nil
	}))
	err := svc.StartPolicyRouting(context.Background(), localOnlySettings(entries), store)
	return err, svc.PBREnabled()
}

// TestActivationOverPredecessorCacheSucceeds is the F957-01 regression: a valid
// predecessor cache plus a usable local list must activate.
func TestActivationOverPredecessorCacheSucceeds(t *testing.T) {
	store, dir := installCache(t, predecessorCacheFixture)

	err, enabled := activateWithStore(t, store, "198.51.100.0/24")
	if err != nil {
		t.Fatalf("a valid predecessor cache must not prevent activation: %v", err)
	}
	if !enabled {
		t.Fatal("PBR is off after activating over a valid predecessor cache")
	}

	// The durable cache must have been rewritten in the current form, so the next
	// start does not go through the predecessor path again.
	body, err := os.ReadFile(filepath.Join(dir, "policy_lkg.json"))
	if err != nil {
		t.Fatalf("read the rewritten cache: %v", err)
	}
	if strings.Contains(string(body), `"domains"`) {
		t.Fatalf("the cache still carries the retired domain half after activation:\n%s", body)
	}
}

// TestActivationOverCorruptCacheStillRefused is the F957-01 negative control. The
// corruption guard is what stops a damaged file from being published as policy, and
// recognizing one predecessor representation must not blunt it.
func TestActivationOverCorruptCacheStillRefused(t *testing.T) {
	body, err := os.ReadFile(predecessorCacheFixture)
	if err != nil {
		t.Fatalf("read the cache fixture: %v", err)
	}
	damaged := strings.Replace(string(body), `"198.51.100.0/24"`, `"203.0.113.0/24"`, 1)
	if damaged == string(body) {
		t.Fatal("the mutation did not change the fixture; the control would prove nothing")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policy_lkg.json"), []byte(damaged), 0600); err != nil {
		t.Fatalf("install the damaged cache: %v", err)
	}

	activationErr, enabled := activateWithStore(t, policy.NewFileStore(dir), "198.51.100.0/24")
	if activationErr == nil {
		t.Fatal("activation succeeded over a genuinely corrupt cache; the fail-closed guard must still refuse it")
	}
	if !strings.Contains(activationErr.Error(), "content hash mismatch") {
		t.Fatalf("refusal = %v, want the content hash mismatch reason so the operator can see what is wrong", activationErr)
	}
	if enabled {
		t.Fatal("PBR is enabled after activation over a corrupt cache")
	}
}

// TestActivationWithFreshStoreStillWorks is the other control: the fix must not
// make a cache exist where a genuine first start has none.
func TestActivationWithFreshStoreStillWorks(t *testing.T) {
	store := policy.NewFileStore(t.TempDir())
	if _, err := store.Load(context.Background()); !os.IsNotExist(err) {
		t.Fatalf("fresh store Load = %v, want os.ErrNotExist", err)
	}
	err, enabled := activateWithStore(t, store, "198.51.100.0/24")
	if err != nil {
		t.Fatalf("a fresh store with a usable local list must activate: %v", err)
	}
	if !enabled {
		t.Fatal("PBR is off after a fresh-store activation")
	}
}
