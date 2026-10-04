package awg

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"golang.org/x/crypto/curve25519"
)

// The regressions in this file pin the reconciliation contract for a server
// key rotation performed through the configuration editor.
//
// The provisioning-time artifact
// /opt/amnezia/awg/wireguard_server_public_key.key used to be the FIRST source
// consulted by GetServerPublicKey and was never refreshed after provisioning.
// A rotated [Interface] PrivateKey therefore left every newly generated client
// config pinned to the pre-rotation server identity.

// identityTestKeypair returns a deterministic base64 (private, public)
// Curve25519 keypair derived from seed, so a test can hold two distinct
// identities without depending on randomness.
func identityTestKeypair(t *testing.T, seed byte) (string, string) {
	t.Helper()
	privBytes := make([]byte, 32)
	for i := range privBytes {
		privBytes[i] = seed + byte(i)
	}
	pubBytes, err := curve25519.X25519(privBytes, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("X25519 failed: %v", err)
	}
	return base64.StdEncoding.EncodeToString(privBytes), base64.StdEncoding.EncodeToString(pubBytes)
}

// identityFixture is an AWG container whose identity artifacts hold
// artifactPub while the configuration holds privB64.
//
// interfaceUp models the tunnel: when true, `awg show awg0 public-key`
// succeeds and answers with the key derived from the configuration on disk,
// which is what syncconf leaves behind after applying a rotation. When false
// the container is stopped: the live probe fails and only the artifacts and the
// configuration remain readable.
type identityFixture struct {
	*mockAWGSSHClient
	interfaceUp bool
}

func newIdentityFixture(privB64, artifactPub string, interfaceUp bool) *identityFixture {
	c := newMockAWGSSHClient()
	c.files[serverPublicKeyArtifactPath] = []byte(artifactPub)
	c.files[serverPrivateKeyArtifactPath] = []byte(privB64)
	c.files["/opt/amnezia/awg/awg0.conf"] = []byte(identityServerConfig(privB64))
	f := &identityFixture{mockAWGSSHClient: c, interfaceUp: interfaceUp}
	c.sudoCmdHandler = f.handle
	return f
}

func (f *identityFixture) handle(cmd string) (string, string, int, error) {
	// The switch order models bash `||` semantics faithfully: a chained command
	// takes the FIRST probe that succeeds, so the artifact probe is matched
	// before the live-interface probe. The fixed live probe is a separate
	// command that mentions neither the artifact nor `cat`, so it reaches its
	// own case below.
	switch {
	// The reconciliation script writes both key artifacts with printf. Undo the
	// ssh.EscapeShellArg quoting of the script argument so the printf
	// statements can be read back.
	case strings.Contains(cmd, "bash -c") && strings.Contains(cmd, serverPublicKeyArtifactPath):
		script := strings.ReplaceAll(cmd, `'\''`, "'")
		for _, stmt := range strings.Split(script, "printf") {
			// Each statement reads printf '%s' '<key>' > <path>.
			parts := strings.Split(stmt, "'")
			if len(parts) < 5 {
				continue
			}
			value := parts[3]
			switch {
			case strings.Contains(stmt, serverPrivateKeyArtifactPath):
				f.files[serverPrivateKeyArtifactPath] = []byte(value)
			case strings.Contains(stmt, serverPublicKeyArtifactPath):
				f.files[serverPublicKeyArtifactPath] = []byte(value)
			}
		}
		return "OK", "", 0, nil
	case strings.Contains(cmd, serverPublicKeyArtifactPath) && strings.Contains(cmd, "cat "):
		return string(f.files[serverPublicKeyArtifactPath]), "", 0, nil
	case strings.Contains(cmd, "show awg0 public-key"):
		if !f.interfaceUp {
			return "", "Cannot find device \"awg0\"", 1, errors.New("exit status 1")
		}
		if pub, err := derivePublicKeyFromPrivate(interfacePrivateKey(string(f.files["/opt/amnezia/awg/awg0.conf"]))); err == nil {
			return pub, "", 0, nil
		}
		return "", "", 1, errors.New("exit status 1")
	case strings.Contains(cmd, serverPrivateKeyArtifactPath) && strings.Contains(cmd, "cat "):
		return string(f.files[serverPrivateKeyArtifactPath]), "", 0, nil
	case strings.Contains(cmd, serverPSKArtifactPath):
		return string(f.files[serverPSKArtifactPath]), "", 0, nil
	case strings.Contains(cmd, "cat ") && strings.Contains(cmd, "awg0.conf"):
		return string(f.files["/opt/amnezia/awg/awg0.conf"]), "", 0, nil
	case strings.Contains(cmd, "cat ") && strings.Contains(cmd, "clientsTable"):
		return string(f.files["/opt/amnezia/awg/clientsTable"]), "", 0, nil
	}
	return f.defaultRunSudo(cmd)
}

func identityServerConfig(privB64 string) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.8.1.1/24
ListenPort = 55424
MTU = 1280
Jc = 4
Jmin = 30
Jmax = 80
S1 = 40
S2 = 60
H1 = 12345
H2 = 67890

[Peer]
PublicKey = pubkey1
AllowedIPs = 10.8.1.2/32
`, privB64)
}

func identityServer() *models.Server {
	return &models.Server{ID: 1, Host: "1.2.3.4", SSHPort: 22}
}

// TestRotatedServerKeyPropagatesToDownloadedClientConfig is the reviewer's
// scenario end to end, and regression 2 (save-then-download): rotate the server
// PrivateKey through WriteConfiguration, then download a client config. The
// downloaded config must authenticate against the ROTATED identity.
func TestRotatedServerKeyPropagatesToDownloadedClientConfig(t *testing.T) {
	ctx := context.Background()
	oldPriv, oldPub := identityTestKeypair(t, 1)
	newPriv, newPub := identityTestKeypair(t, 2)
	if oldPub == newPub {
		t.Fatal("test keypairs must differ")
	}

	// Seed the container exactly as provisioning left it: the artifacts carry
	// the pre-rotation identity.
	f := newIdentityFixture(oldPriv, oldPub, true)
	mgr := NewAWGManager(&mockAWGSSHProvider{client: f.mockAWGSSHClient})
	server := identityServer()

	// The identity as seen before the rotation.
	before, err := mgr.GetServerPublicKey(ctx, server)
	if err != nil {
		t.Fatalf("GetServerPublicKey before rotation: %v", err)
	}
	if before != oldPub {
		t.Fatalf("pre-rotation identity = %q, want %q", before, oldPub)
	}

	if err := mgr.WriteConfiguration(ctx, server, identityServerConfig(newPriv)); err != nil {
		t.Fatalf("WriteConfiguration(rotate) failed: %v", err)
	}

	after, err := mgr.GetServerPublicKey(ctx, server)
	if err != nil {
		t.Fatalf("GetServerPublicKey after rotation: %v", err)
	}
	if after != newPub {
		t.Errorf("post-rotation identity = %q, want the rotated %q (stale value %q)", after, newPub, oldPub)
	}

	// Save-then-download: a client config fetched AFTER the rotation must
	// carry the rotated server public key, not the pre-rotation one.
	clientCfg, err := mgr.GetClientConfig(ctx, server, "pubkey1")
	if err != nil {
		t.Fatalf("GetClientConfig after rotation: %v", err)
	}
	if !strings.Contains(clientCfg, "PublicKey = "+newPub) {
		t.Errorf("client config downloaded after the rotation does not carry the rotated server identity %s\nconfig:\n%s", newPub, clientCfg)
	}
	if strings.Contains(clientCfg, "PublicKey = "+oldPub) {
		t.Errorf("client config downloaded after the rotation still carries the STALE server identity %s\nconfig:\n%s", oldPub, clientCfg)
	}
}

// TestIdentityArtifactsReconciledAfterRotation pins the write side: the
// provisioning artifacts are refreshed from the newly written configuration, so
// a stopped-container read is correct even though the interface cannot answer.
func TestIdentityArtifactsReconciledAfterRotation(t *testing.T) {
	ctx := context.Background()
	oldPriv, oldPub := identityTestKeypair(t, 1)
	newPriv, newPub := identityTestKeypair(t, 2)

	f := newIdentityFixture(oldPriv, oldPub, true)
	mgr := NewAWGManager(&mockAWGSSHProvider{client: f.mockAWGSSHClient})
	server := identityServer()

	if err := mgr.WriteConfiguration(ctx, server, identityServerConfig(newPriv)); err != nil {
		t.Fatalf("WriteConfiguration(rotate) failed: %v", err)
	}

	if got := strings.TrimSpace(string(f.files[serverPublicKeyArtifactPath])); got != newPub {
		t.Errorf("public key artifact = %q, want the reconciled %q (was %q)", got, newPub, oldPub)
	}
	if got := strings.TrimSpace(string(f.files[serverPrivateKeyArtifactPath])); got != newPriv {
		t.Errorf("private key artifact = %q, want the reconciled %q", got, newPriv)
	}
}

// TestGetServerPublicKeyRecoversFromArtifactsWhenContainerStopped is regression
// 3: the artifact path must still succeed for a stopped container, and after a
// rotation it must return the NEW identity.
func TestGetServerPublicKeyRecoversFromArtifactsWhenContainerStopped(t *testing.T) {
	ctx := context.Background()
	oldPriv, oldPub := identityTestKeypair(t, 1)
	newPriv, newPub := identityTestKeypair(t, 2)

	// Rotate against a running container.
	running := newIdentityFixture(oldPriv, oldPub, true)
	mgr := NewAWGManager(&mockAWGSSHProvider{client: running.mockAWGSSHClient})
	if err := mgr.WriteConfiguration(ctx, identityServer(), identityServerConfig(newPriv)); err != nil {
		t.Fatalf("WriteConfiguration(rotate) failed: %v", err)
	}

	// Now the same container is stopped: the live probe fails and recovery has
	// to come from disk.
	stopped := &identityFixture{mockAWGSSHClient: running.mockAWGSSHClient, interfaceUp: false}
	stopped.sudoCmdHandler = stopped.handle
	stoppedMgr := NewAWGManager(&mockAWGSSHProvider{client: stopped.mockAWGSSHClient})

	got, err := stoppedMgr.GetServerPublicKey(ctx, identityServer())
	if err != nil {
		t.Fatalf("GetServerPublicKey on a stopped container failed: %v", err)
	}
	if got != newPub {
		t.Errorf("stopped-container recovery returned %q, want the post-reconciliation identity %q", got, newPub)
	}
}

// TestGetServerPublicKeyDerivesWhenInterfaceDownAndArtifactStale covers the
// read-side ordering directly: even with a stale artifact still on disk, a
// readable configuration outranks it.
func TestGetServerPublicKeyDerivesWhenInterfaceDownAndArtifactStale(t *testing.T) {
	ctx := context.Background()
	oldPriv, oldPub := identityTestKeypair(t, 1)
	newPriv, newPub := identityTestKeypair(t, 2)

	// Stopped container whose artifact was NEVER reconciled: only the read-side
	// ordering can produce the right answer here.
	f := newIdentityFixture(oldPriv, oldPub, false)
	f.files["/opt/amnezia/awg/awg0.conf"] = []byte(identityServerConfig(newPriv))
	mgr := NewAWGManager(&mockAWGSSHProvider{client: f.mockAWGSSHClient})

	got, err := mgr.GetServerPublicKey(ctx, identityServer())
	if err != nil {
		t.Fatalf("GetServerPublicKey failed: %v", err)
	}
	if got != newPub {
		t.Errorf("GetServerPublicKey = %q, want the configured identity %q; the stale artifact %q must not win", got, newPub, oldPub)
	}
}

// TestLiveInterfaceWinsOverConfiguredIdentity pins the other half of the
// priority order: when the interface is up, the live key is authoritative and
// is NOT overridden by the value derived from disk.
func TestLiveInterfaceWinsOverConfiguredIdentity(t *testing.T) {
	ctx := context.Background()
	priv, derivedPub := identityTestKeypair(t, 1)
	_, otherPub := identityTestKeypair(t, 2)

	f := newIdentityFixture(priv, otherPub, true)
	// The running interface reports a different key than the configuration
	// derives (e.g. the operator changed keys outside the editor).
	f.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "show awg0 public-key") {
			return otherPub, "", 0, nil
		}
		return f.handle(cmd)
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: f.mockAWGSSHClient})
	got, err := mgr.GetServerPublicKey(ctx, identityServer())
	if err != nil {
		t.Fatalf("GetServerPublicKey failed: %v", err)
	}
	if got != otherPub {
		t.Errorf("GetServerPublicKey = %q, want the LIVE interface key %q (configured identity was %q)", got, otherPub, derivedPub)
	}
}

// TestNonKeyLiveProbeOutputIsRejected guards the live-probe validation: a
// wrapper that answers with a non-key banner must not be taken as the server
// identity.
func TestNonKeyLiveProbeOutputIsRejected(t *testing.T) {
	ctx := context.Background()
	priv, derivedPub := identityTestKeypair(t, 1)
	_, artifactPub := identityTestKeypair(t, 2)

	f := newIdentityFixture(priv, artifactPub, true)
	f.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "show awg0 public-key") {
			return "OK", "", 0, nil
		}
		return f.handle(cmd)
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: f.mockAWGSSHClient})
	got, err := mgr.GetServerPublicKey(ctx, identityServer())
	if err != nil {
		t.Fatalf("GetServerPublicKey failed: %v", err)
	}
	if got != derivedPub {
		t.Errorf("GetServerPublicKey = %q, want the configured identity %q; a non-key live banner must be rejected", got, derivedPub)
	}
}

// TestNoOpWriteDoesNotCorruptIdentityState is regression 5: re-saving the SAME
// configuration must leave the identity artifacts untouched.
func TestNoOpWriteDoesNotCorruptIdentityState(t *testing.T) {
	ctx := context.Background()
	priv, pub := identityTestKeypair(t, 1)

	f := newIdentityFixture(priv, pub, true)
	mgr := NewAWGManager(&mockAWGSSHProvider{client: f.mockAWGSSHClient})
	server := identityServer()

	// Seed the artifacts with the pre-reconciliation provisioning values so a
	// stray rewrite would be visible.
	f.files[serverPublicKeyArtifactPath] = []byte("seededPublicKey123456789012345678901234=")
	f.files[serverPrivateKeyArtifactPath] = []byte("seededPrivateKey123456789012345678901234=")

	config := identityServerConfig(priv)
	for i := range 3 {
		if err := mgr.WriteConfiguration(ctx, server, config); err != nil {
			t.Fatalf("WriteConfiguration (no-op %d) failed: %v", i, err)
		}
	}

	if got := strings.TrimSpace(string(f.files[serverPublicKeyArtifactPath])); got != "seededPublicKey123456789012345678901234=" {
		t.Errorf("no-op write rewrote the public key artifact: %q", got)
	}
	if got := strings.TrimSpace(string(f.files[serverPrivateKeyArtifactPath])); got != "seededPrivateKey123456789012345678901234=" {
		t.Errorf("no-op write rewrote the private key artifact: %q", got)
	}

	// The resolved identity is still the configured one.
	got, err := mgr.GetServerPublicKey(ctx, server)
	if err != nil {
		t.Fatalf("GetServerPublicKey after no-op writes: %v", err)
	}
	if got != pub {
		t.Errorf("identity after no-op writes = %q, want %q", got, pub)
	}
}

// TestProvisioningStillWritesIdentityArtifacts is regression 4: provisioning
// must keep writing all three artifacts (the keygen script is shared with the
// reconciliation path).
func TestProvisioningStillWritesIdentityArtifacts(t *testing.T) {
	ctx := context.Background()
	c := newMockAWGSSHClient()
	var keygen string
	c.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "bash -c") && strings.Contains(cmd, serverPrivateKeyArtifactPath) {
			keygen = cmd
			return "OK", "", 0, nil
		}
		return c.defaultRunSudo(cmd)
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: c})
	if err := initializeServerKeysAndConfig(ctx, c, "55424", &AWGParams{}); err != nil {
		t.Fatalf("initializeServerKeysAndConfig failed: %v", err)
	}

	if keygen == "" {
		t.Fatal("provisioning did not run the keygen script")
	}
	for _, path := range []string{serverPrivateKeyArtifactPath, serverPublicKeyArtifactPath, serverPSKArtifactPath} {
		if !strings.Contains(keygen, path) {
			t.Errorf("provisioning keygen script no longer writes %s: %s", path, keygen)
		}
	}

	// The configuration provisioning installed carries the private key whose
	// public key the artifact records, so a stopped-container read is correct
	// straight after provisioning.
	conf := string(c.files["/opt/amnezia/awg/awg0.conf"])
	derived, err := derivePublicKeyFromPrivate(interfacePrivateKey(conf))
	if err != nil {
		t.Fatalf("provisioned config private key does not derive: %v", err)
	}
	mgrIdentity, err := mgr.GetServerPublicKey(ctx, identityServer())
	if err != nil {
		t.Fatalf("GetServerPublicKey after provisioning: %v", err)
	}
	if mgrIdentity != derived {
		t.Errorf("identity after provisioning = %q, want the derived %q", mgrIdentity, derived)
	}
}

// TestInterfacePrivateKeyIgnoresPeerSections pins the helper that the read and
// write sides both depend on: only [Interface] PrivateKey is the server
// identity.
func TestInterfacePrivateKeyIgnoresPeerSections(t *testing.T) {
	cases := []struct {
		name string
		conf string
		want string
	}{
		{"interface key", "[Interface]\nPrivateKey = AAA=\n", "AAA="},
		{"case insensitive name", "[interface]\nprivatekey = BBB=\n", "BBB="},
		{"trailing comment stripped", "[Interface]\nPrivateKey = CCC= # rotated\n", "CCC="},
		{"peer key ignored", "[Interface]\nAddress = 10.8.1.1/24\n\n[Peer]\nPrivateKey = DDD=\n", ""},
		{"absent", "[Interface]\nAddress = 10.8.1.1/24\n", ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := interfacePrivateKey(tc.conf); got != tc.want {
				t.Errorf("interfacePrivateKey = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestReconcileServerIdentityEscapesShellArguments pins the shell-safety
// invariant: every interpolated value reaches the remote shell through
// ssh.EscapeShellArg, and a key that is not a well-formed base64 key is
// refused outright.
func TestReconcileServerIdentityEscapesShellArguments(t *testing.T) {
	ctx := context.Background()
	priv, pub := identityTestKeypair(t, 1)

	c := newMockAWGSSHClient()
	var wrote string
	c.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "bash -c") && strings.Contains(cmd, serverPublicKeyArtifactPath) {
			wrote = cmd
			return "OK", "", 0, nil
		}
		return c.defaultRunSudo(cmd)
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: c})
	original := identityServerConfig("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	rotated := identityServerConfig(priv)
	if err := mgr.reconcileServerIdentity(ctx, c, identityServer(), original, rotated); err != nil {
		t.Fatalf("reconcileServerIdentity failed: %v", err)
	}
	if wrote == "" {
		t.Fatal("reconcileServerIdentity did not run an artifact write")
	}
	if !strings.Contains(wrote, priv) || !strings.Contains(wrote, pub) {
		t.Errorf("artifact write does not carry both reconciled keys: %s", wrote)
	}
	// The container name is escaped, so it appears inside single quotes.
	if !strings.Contains(wrote, "'amnezia-awg2'") && !strings.Contains(wrote, "'amnezia-awg'") {
		t.Errorf("container name is not escaped in the artifact write: %s", wrote)
	}

	// A private key that is not a valid 32-byte base64 key must never be
	// interpolated into a shell script.
	wrote = ""
	hostile := "[Interface]\nPrivateKey = $(touch /tmp/pwned); rm -rf /\nAddress = 10.8.1.1/24\n"
	if err := mgr.reconcileServerIdentity(ctx, c, identityServer(), original, hostile); err != nil {
		t.Fatalf("reconcileServerIdentity(hostile) returned an unexpected error: %v", err)
	}
	if wrote != "" {
		t.Errorf("a non-key private key was interpolated into a shell command: %s", wrote)
	}
}

// TestDerivePublicKeyFromPrivate covers the derivation helper the read and write
// sides share.
func TestDerivePublicKeyFromPrivate(t *testing.T) {
	priv, pub := identityTestKeypair(t, 1)

	got, err := derivePublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("derivePublicKeyFromPrivate failed: %v", err)
	}
	if got != pub {
		t.Errorf("derived = %q, want %q", got, pub)
	}

	if _, err := derivePublicKeyFromPrivate("not-base64!!"); err == nil {
		t.Error("expected an error for a non-base64 private key")
	}
	if _, err := derivePublicKeyFromPrivate("c2hvcnQ="); err == nil {
		t.Error("expected an error for a short private key")
	}
}

// TestOpsReview_ResolvedContainerIdentity pins the mixed-container regression:
// Selected current container has readable configuration A but no available live interface.
// Retained legacy container has a different valid live identity B.
// Old global-live-first behavior probed live identity across all containers and returned B,
// while GetClientConfig used config/port A, creating an unusable A/B identity mixture.
// The resolved identity and reconstructed client config must both use selected container A.
func TestOpsReview_ResolvedContainerIdentity(t *testing.T) {
	ctx := context.Background()
	priv, want := identityTestKeypair(t, 1)
	_, other := identityTestKeypair(t, 2)
	f := newIdentityFixture(priv, want, false)
	f.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "show awg0 public-key") {
			if strings.Contains(cmd, "'amnezia-awg2'") {
				return "", "interface down", 1, errors.New("interface down")
			}
			if strings.Contains(cmd, "'amnezia-awg'") {
				return other, "", 0, nil
			}
		}
		return f.handle(cmd)
	}
	m := NewAWGManager(&mockAWGSSHProvider{client: f.mockAWGSSHClient})
	got, err := m.GetServerPublicKey(ctx, identityServer())
	if err != nil {
		t.Fatalf("GetServerPublicKey failed: %v", err)
	}
	t.Logf("returned legacy-container identity=%t; selected-container configured identity=%t", got == other, got == want)
	if got != want {
		t.Errorf("GetServerPublicKey = %q, want selected container identity %q (legacy live key was %q)", got, want, other)
	}

	clientCfg, err := m.GetClientConfig(ctx, identityServer(), "pubkey1")
	if err != nil {
		t.Fatalf("GetClientConfig failed: %v", err)
	}
	if !strings.Contains(clientCfg, "PublicKey = "+want) {
		t.Errorf("GetClientConfig does not carry selected container identity %s\nconfig:\n%s", want, clientCfg)
	}
	if strings.Contains(clientCfg, "PublicKey = "+other) {
		t.Errorf("GetClientConfig carries legacy container identity %s\nconfig:\n%s", other, clientCfg)
	}
	if !strings.Contains(clientCfg, "Endpoint = 1.2.3.4:55424") {
		t.Errorf("GetClientConfig does not carry expected endpoint 1.2.3.4:55424\nconfig:\n%s", clientCfg)
	}
}

// TestResolvedContainerIdentity_FallbackToLegacyCoherent tests that when the selected
// container is missing/absent, fallback changes containers coherently: configuration,
// port, parameters, and public key all come from the legacy container as one unit.
func TestResolvedContainerIdentity_FallbackToLegacyCoherent(t *testing.T) {
	ctx := context.Background()
	_, currentPub := identityTestKeypair(t, 1)
	legacyPriv, legacyPub := identityTestKeypair(t, 2)

	legacyConf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.8.2.1/24
ListenPort = 51820
MTU = 1360
Jc = 3
Jmin = 40
Jmax = 70
S1 = 15
S2 = 25
H1 = 11111
H2 = 22222

[Peer]
PublicKey = pubkey1
AllowedIPs = 10.8.2.2/32
`, legacyPriv)

	c := newMockAWGSSHClient()
	c.files["/opt/amnezia/awg/clientsTable"] = []byte(`[
  {
    "clientId": "pubkey1",
    "userData": {
      "clientName": "TestClient1",
      "clientPrivateKey": "privkey1",
      "clientIp": "10.8.2.2",
      "enabled": true
    }
  }
]`)

	c.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		// Strict rejection for amnezia-awg2: it does not exist
		if strings.Contains(cmd, "'amnezia-awg2'") {
			return "", "Error: No such container: amnezia-awg2", 1, errors.New("container not found")
		}
		if strings.Contains(cmd, "'amnezia-awg'") {
			switch {
			case strings.Contains(cmd, "show awg0 public-key"):
				// Legacy container live interface is up
				return legacyPub, "", 0, nil
			case strings.Contains(cmd, "cat ") && strings.Contains(cmd, "awg0.conf"):
				return legacyConf, "", 0, nil
			case strings.Contains(cmd, "cat ") && strings.Contains(cmd, "clientsTable"):
				return string(c.files["/opt/amnezia/awg/clientsTable"]), "", 0, nil
			}
		}
		return c.defaultRunSudo(cmd)
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: c})
	server := identityServer()

	gotKey, err := mgr.GetServerPublicKey(ctx, server)
	if err != nil {
		t.Fatalf("GetServerPublicKey failed: %v", err)
	}
	if gotKey != legacyPub {
		t.Errorf("GetServerPublicKey = %q, want legacy container identity %q", gotKey, legacyPub)
	}

	clientCfg, err := mgr.GetClientConfig(ctx, server, "pubkey1")
	if err != nil {
		t.Fatalf("GetClientConfig failed: %v", err)
	}
	if !strings.Contains(clientCfg, "PublicKey = "+legacyPub) {
		t.Errorf("GetClientConfig does not contain legacy public key %s\nconfig:\n%s", legacyPub, clientCfg)
	}
	if strings.Contains(clientCfg, "PublicKey = "+currentPub) {
		t.Errorf("GetClientConfig unexpectedly contains current container public key %s\nconfig:\n%s", currentPub, clientCfg)
	}
	// Verify port and MTU match the legacy container configuration coherently
	if !strings.Contains(clientCfg, "Endpoint = 1.2.3.4:51820") {
		t.Errorf("GetClientConfig does not match legacy container port 51820\nconfig:\n%s", clientCfg)
	}
	if !strings.Contains(clientCfg, "MTU = 1360") {
		t.Errorf("GetClientConfig does not match legacy container MTU 1360\nconfig:\n%s", clientCfg)
	}
}

// TestResolvedContainerIdentity_DiscoveredCustomContainer verifies that discovered custom
// container names are supported without hardcoding, and candidateContainerNames prioritizes them.
func TestResolvedContainerIdentity_DiscoveredCustomContainer(t *testing.T) {
	ctx := context.Background()
	customPriv, customPub := identityTestKeypair(t, 3)
	customConf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.8.3.1/24
ListenPort = 55555
MTU = 1280

[Peer]
PublicKey = pubkey1
AllowedIPs = 10.8.3.2/32
`, customPriv)

	c := newMockAWGSSHClient()
	c.files["/opt/amnezia/awg/clientsTable"] = []byte(`[
  {
    "clientId": "pubkey1",
    "userData": {
      "clientName": "TestClient1",
      "clientPrivateKey": "privkey1",
      "clientIp": "10.8.3.2",
      "enabled": true
    }
  }
]`)

	c.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker ps") && strings.Contains(cmd, "amnezia-awg") {
			return "amnezia-awg-custom", "", 0, nil
		}
		if strings.Contains(cmd, "'amnezia-awg-custom'") {
			switch {
			case strings.Contains(cmd, "show awg0 public-key"):
				return customPub, "", 0, nil
			case strings.Contains(cmd, "cat ") && strings.Contains(cmd, "awg0.conf"):
				return customConf, "", 0, nil
			case strings.Contains(cmd, "cat ") && strings.Contains(cmd, "clientsTable"):
				return string(c.files["/opt/amnezia/awg/clientsTable"]), "", 0, nil
			}
		}
		return c.defaultRunSudo(cmd)
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: c})
	server := identityServer()

	candidates := mgr.candidateContainerNames(ctx, c)
	if len(candidates) == 0 || candidates[0] != "amnezia-awg-custom" {
		t.Fatalf("candidateContainerNames = %v, want amnezia-awg-custom at index 0", candidates)
	}

	gotKey, err := mgr.GetServerPublicKey(ctx, server)
	if err != nil {
		t.Fatalf("GetServerPublicKey failed: %v", err)
	}
	if gotKey != customPub {
		t.Errorf("GetServerPublicKey = %q, want custom container identity %q", gotKey, customPub)
	}

	clientCfg, err := mgr.GetClientConfig(ctx, server, "pubkey1")
	if err != nil {
		t.Fatalf("GetClientConfig failed: %v", err)
	}
	if !strings.Contains(clientCfg, "PublicKey = "+customPub) {
		t.Errorf("GetClientConfig does not contain custom public key %s\nconfig:\n%s", customPub, clientCfg)
	}
	if !strings.Contains(clientCfg, "Endpoint = 1.2.3.4:55555") {
		t.Errorf("GetClientConfig does not match custom container endpoint 1.2.3.4:55555\nconfig:\n%s", clientCfg)
	}
}

// TestResolvedContainerIdentity_MalformedConfigRecoversFromArtifact verifies that when the
// selected container's live interface is down and its configuration file is malformed (no PrivateKey),
// it safely recovers from the provisioning artifact within the container.
func TestResolvedContainerIdentity_MalformedConfigRecoversFromArtifact(t *testing.T) {
	ctx := context.Background()
	_, artifactPub := identityTestKeypair(t, 4)

	malformedConf := `[Interface]
Address = 10.8.1.1/24
ListenPort = 55424
MTU = 1280
`

	c := newMockAWGSSHClient()
	c.files[serverPublicKeyArtifactPath] = []byte(artifactPub)
	c.files["/opt/amnezia/awg/awg0.conf"] = []byte(malformedConf)

	c.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		switch {
		case strings.Contains(cmd, "show awg0 public-key"):
			return "", "interface down", 1, errors.New("interface down")
		case strings.Contains(cmd, "cat ") && strings.Contains(cmd, "awg0.conf"):
			return malformedConf, "", 0, nil
		case strings.Contains(cmd, "cat ") && strings.Contains(cmd, serverPublicKeyArtifactPath):
			return artifactPub, "", 0, nil
		}
		return c.defaultRunSudo(cmd)
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: c})
	gotKey, err := mgr.GetServerPublicKey(ctx, identityServer())
	if err != nil {
		t.Fatalf("GetServerPublicKey failed: %v", err)
	}
	if gotKey != artifactPub {
		t.Errorf("GetServerPublicKey = %q, want artifact recovery identity %q", gotKey, artifactPub)
	}
}

// TestResolvedContainerIdentity_AllContainersAbsentReturnsExplicitError verifies that when
// no containers exist on the remote host, an explicit error is returned.
func TestResolvedContainerIdentity_AllContainersAbsentReturnsExplicitError(t *testing.T) {
	ctx := context.Background()
	c := newMockAWGSSHClient()
	c.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "clientsTable") {
			return `[{"clientId": "pubkey1", "userData": {"clientPrivateKey": "privkey1"}}]`, "", 0, nil
		}
		return "", "Error: No such container", 1, errors.New("exit status 1")
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: c})
	server := identityServer()

	_, err := mgr.GetServerPublicKey(ctx, server)
	if err == nil {
		t.Fatal("expected GetServerPublicKey to return error when all containers are absent")
	}
	if !strings.Contains(err.Error(), "failed to get AmneziaWG server public key") {
		t.Errorf("unexpected error message: %v", err)
	}

	_, err = mgr.GetClientConfig(ctx, server, "pubkey1")
	if err == nil {
		t.Fatal("expected GetClientConfig to return error when all containers are absent")
	}
	if !strings.Contains(err.Error(), "failed to get server config from containers") {
		t.Errorf("unexpected error message: %v", err)
	}
}
