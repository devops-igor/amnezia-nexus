package awg

import (
	"context"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestAllocationKey pins the single identity rule: the public key is
// authoritative when supplied, the explicit client identifier is the fallback,
// and a pair that names two different clients is refused rather than resolved.
func TestAllocationKey(t *testing.T) {
	t.Run("consistent identities share one key", func(t *testing.T) {
		cases := []struct {
			name      string
			clientID  string
			clientPub string
			wantKey   string
		}{
			{name: "matching pair resolves to the public key", clientID: "pub-key", clientPub: "pub-key", wantKey: "pub-key"},
			{name: "explicit identifier alone is used", clientID: "portal-user-1", wantKey: "portal-user-1"},
			{name: "public key alone is used", clientPub: "pub-key", wantKey: "pub-key"},
			{name: "values are trimmed", clientID: "  portal-user-1  ", wantKey: "portal-user-1"},
			{name: "neither supplied", wantKey: ""},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if err := ValidateAllocationIdentity(tc.clientID, tc.clientPub); err != nil {
					t.Fatalf("consistent identities were refused: %v", err)
				}
				if key := AllocationKey(tc.clientID, tc.clientPub); key != tc.wantKey {
					t.Fatalf("AllocationKey(%q, %q) = %q, want %q", tc.clientID, tc.clientPub, key, tc.wantKey)
				}
			})
		}
	})

	t.Run("conflicting identities are refused", func(t *testing.T) {
		cases := []struct{ clientID, clientPub string }{
			{clientID: "portal-user-1", clientPub: "pub-key"},
			{clientID: "  portal-user-1  ", clientPub: " pub-key "},
		}
		for _, tc := range cases {
			err := ValidateAllocationIdentity(tc.clientID, tc.clientPub)
			if err == nil {
				t.Fatalf("conflicting identities %q/%q were accepted", tc.clientID, tc.clientPub)
			}
			if !strings.Contains(err.Error(), strings.TrimSpace(tc.clientID)) || !strings.Contains(err.Error(), strings.TrimSpace(tc.clientPub)) {
				t.Fatalf("refusal does not name both identities: %v", err)
			}
		}
		// The key that would have been stored is the public key, which is exactly
		// why the conflict must be refused: the explicit identifier disappears.
		if key := AllocationKey("portal-user-1", "pub-key"); key != "pub-key" {
			t.Fatalf("AllocationKey for a conflicting pair = %q, want the public key", key)
		}
	})
}

// TestAddClientRefusesConflictingExplicitClientID covers the mixed-identity path
// end to end: when a caller supplies both an explicit client_id and a public key
// that name different clients, AddClient must refuse with an error naming the
// conflict before it allocates an address or writes a peer. Silently storing the
// row under the public key would leave any later release through the explicit
// identifier matching nothing.
func TestAddClientRefusesConflictingExplicitClientID(t *testing.T) {
	ctx := context.Background()
	sshClient := newMockAWGSSHClient()
	mgr := NewAWGManager(&mockAWGSSHProvider{client: sshClient})
	server := &models.Server{ID: 1, Host: "192.0.2.10"}

	allocator := &mockFaultyIPAllocator{}
	mgr.SetIPAllocator(allocator)

	_, pubKey := testProberKeypair(t)

	res, err := mgr.AddClient(ctx, server, map[string]any{
		"name":       "Conflicting identity",
		"client_id":  "portal-user-1",
		"public_key": pubKey,
	})

	if err == nil {
		t.Fatalf("AddClient accepted a conflicting explicit client_id and returned %v", res)
	}
	if !strings.Contains(err.Error(), "portal-user-1") || !strings.Contains(err.Error(), pubKey) {
		t.Fatalf("refusal does not name the conflict: %v", err)
	}
	if got := allocator.allocCount.Load(); got != 0 {
		t.Fatalf("refused client add still allocated %d address(es)", got)
	}
	if conf := sshClient.files[legacyConfigPath]; strings.Contains(string(conf), pubKey) {
		t.Fatalf("refused client add wrote the peer to the server config: %q", string(conf))
	}

	// Control: the same caller-supplied public key without a conflicting
	// explicit identifier is accepted and does allocate, so the refusal is about
	// the conflict and not about the key.
	res, err = mgr.AddClient(ctx, server, map[string]any{
		"name":       "Conflicting identity",
		"public_key": pubKey,
	})
	if err != nil {
		t.Fatalf("AddClient refused a consistent identity: %v", err)
	}
	if res["client_id"] != pubKey {
		t.Fatalf("accepted client_id = %v, want the public key %q", res["client_id"], pubKey)
	}
	if got := allocator.allocCount.Load(); got != 1 {
		t.Fatalf("accepted client add allocated %d address(es), want 1", got)
	}
}
