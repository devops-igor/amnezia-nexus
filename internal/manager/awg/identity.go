package awg

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"golang.org/x/crypto/curve25519"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// In-container identity artifacts written once during provisioning
// (initializeServerKeysAndConfig) and refreshed by reconcileServerIdentity.
const (
	serverPrivateKeyArtifactPath = "/opt/amnezia/awg/wireguard_server_private_key.key"
	serverPublicKeyArtifactPath  = "/opt/amnezia/awg/wireguard_server_public_key.key"
	serverPSKArtifactPath        = "/opt/amnezia/awg/wireguard_psk.key"
)

// serverIDOf is a nil-safe accessor for logging.
func serverIDOf(server *models.Server) int64 {
	if server == nil {
		return 0
	}
	return server.ID
}

// awgKeyPattern matches a base64-encoded 32-byte key. Keys are interpolated
// into in-container shell scripts during identity reconciliation, so the value
// is required to match this pattern before it is used: the character class
// admits no shell metacharacter, which makes the interpolation inert on top of
// the surrounding ssh.EscapeShellArg.
var awgKeyPattern = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)

// isWireGuardKey reports whether s is a base64-encoded WireGuard key as
// `wg show <iface> public-key` prints it. Commands in this file chain several
// probes with `||`, and a host whose shell answers a probe with an unrelated
// non-empty string (a wrapper banner, "OK" from a permissive mock) must not be
// mistaken for a key: a value that does not decode is skipped so the next,
// more authoritative source is consulted.
func isWireGuardKey(s string) bool {
	if s == "" {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

// derivePublicKeyFromPrivate returns the base64 X25519 public key for a
// base64-encoded 32-byte private key.
func derivePublicKeyFromPrivate(privKeyBase64 string) (string, error) {
	privBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privKeyBase64))
	if err != nil {
		return "", fmt.Errorf("private key is not valid base64: %w", err)
	}
	if len(privBytes) != 32 {
		return "", fmt.Errorf("private key is %d bytes, want 32", len(privBytes))
	}
	pubBytes, err := curve25519.X25519(privBytes, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("failed to derive public key from private key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pubBytes), nil
}

// interfacePrivateKey returns the [Interface] PrivateKey from a server
// configuration, or "" when the section or the key is absent. Only the
// [Interface] section is scanned so a peer line can never be mistaken for the
// server's own identity.
func interfacePrivateKey(configText string) string {
	inInterface := false
	for _, line := range strings.Split(configText, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") || trimmed == "" {
			continue
		}
		if strings.EqualFold(trimmed, "[Interface]") {
			inInterface = true
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			inInterface = false
			continue
		}
		if !inInterface {
			continue
		}
		name, value, found := strings.Cut(trimmed, "=")
		if found && strings.EqualFold(strings.TrimSpace(name), "privatekey") {
			return strings.TrimSpace(stripComment(strings.TrimSpace(value)))
		}
	}
	return ""
}

// candidateContainerNames returns the container names to probe, most specific
// first: the resolved name, then the remaining known AWG container names.
func (m *AWGManager) candidateContainerNames(ctx context.Context, client ssh.SSHClient) []string {
	resolved := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(resolved) {
		resolved = m.containerName()
	}
	if !IsValidContainerName(resolved) {
		resolved = "amnezia-awg2"
	}
	names := []string{resolved}
	for _, name := range AWGContainerNames {
		if name != resolved && IsValidContainerName(name) {
			names = append(names, name)
		}
	}
	return names
}

// getServerPublicKeyInContainer resolves the public key within a specific container,
// applying the within-container precedence:
//  1. The live interface (`awg`/`wg show awg0 public-key`). While the interface
//     is up this is what peers actually authenticate against, so it stays
//     authoritative within the selected container — a running-but-different value is
//     never overridden by a value read off disk.
//  2. The key derived from the [Interface] PrivateKey of the on-disk
//     configuration. If confText is not provided, it is read from the container.
//  3. The wireguard_server_public_key.key artifact written during provisioning:
//     last-resort recovery source for a stopped container whose configuration
//     cannot be read or did not derive a key.
func (m *AWGManager) getServerPublicKeyInContainer(ctx context.Context, client ssh.SSHClient, server *models.Server, containerName string, confText string) (string, error) {
	if !IsValidContainerName(containerName) {
		return "", fmt.Errorf("invalid container name %q", containerName)
	}

	// 1. Live interface within this container. Authoritative whenever it answers with a valid key.
	cmd := fmt.Sprintf("docker exec -i %s %s show awg0 public-key 2>/dev/null || docker exec -i %s wg show awg0 public-key 2>/dev/null",
		ssh.EscapeShellArg(containerName), ssh.EscapeShellArg(m.wgBinary()), ssh.EscapeShellArg(containerName))
	out, _, code, err := client.RunSudoCommand(ctx, cmd)
	if err == nil && code == 0 {
		if live := strings.TrimSpace(out); isWireGuardKey(live) {
			return live, nil
		}
		slog.Debug("live AmneziaWG public key probe returned a non-key value; falling back to the configured identity",
			"container", containerName, "server_id", serverIDOf(server))
	}

	// 2. Derive from the configured [Interface] PrivateKey within this container.
	conf := confText
	var confErr error
	if conf == "" {
		conf, confErr = m.getServerConfig(ctx, client, containerName)
	}
	if confErr == nil && conf != "" {
		if derived, err := derivePublicKeyFromPrivate(interfacePrivateKey(conf)); err == nil && derived != "" {
			return derived, nil
		}
	}

	// 3. Provisioning artifact within this container: recovery only, for a stopped
	// container whose configuration could not be read or derived.
	artifactCmd := fmt.Sprintf("docker exec -i %s cat %s 2>/dev/null", ssh.EscapeShellArg(containerName), ssh.EscapeShellArg(serverPublicKeyArtifactPath))
	artifactOut, _, artifactCode, artifactErr := client.RunSudoCommand(ctx, artifactCmd)
	if artifactErr == nil && artifactCode == 0 {
		artifact := strings.TrimSpace(artifactOut)
		if artifact != "" {
			if confErr == nil && conf != "" {
				slog.Warn("falling back to the provisioning AmneziaWG public key artifact; the configured private key did not derive and the artifact may predate the current configuration",
					"container", containerName, "server_id", serverIDOf(server))
			}
			return artifact, nil
		}
	}

	return "", fmt.Errorf("failed to get AmneziaWG server public key from container %q", containerName)
}

// GetServerPublicKey returns the public key for AmneziaWG server.
//
// Candidate containers are inspected in priority order (starting with the
// selected/resolved container). Within each candidate container, sources
// are consulted in within-container precedence:
//  1. The live interface (`awg`/`wg show awg0 public-key`). While the interface
//     is up this is what peers actually authenticate against, so it stays
//     authoritative within the selected container — a running-but-different value is
//     never overridden by a value read off disk.
//  2. The key derived from the [Interface] PrivateKey of the on-disk
//     configuration. This is the identity the operator last saved, it costs one
//     X25519 operation, and it is available whenever the configuration is
//     readable even if the interface is down.
//  3. The wireguard_server_public_key.key artifact written during provisioning:
//     recovery only, for a stopped container whose configuration could not be read.
//
// An unrelated legacy container's live interface cannot outrank a readable
// configuration in the selected container. If fallback changes containers,
// configuration, port, parameters, and identity move as one coherent unit.
func (m *AWGManager) GetServerPublicKey(ctx context.Context, server *models.Server) (string, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return "", err
	}
	names := m.candidateContainerNames(ctx, client)

	for _, name := range names {
		if !IsValidContainerName(name) {
			continue
		}
		if key, err := m.getServerPublicKeyInContainer(ctx, client, server, name, ""); err == nil && key != "" {
			return key, nil
		}
	}

	return "", errors.New("failed to get AmneziaWG server public key")
}
