package awg

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// ReadConfiguration reads the installed AWG container, the same configuration
// used by provisioning and peer changes. A missing config is an error.
func (m *AWGManager) ReadConfiguration(ctx context.Context, server *models.Server) (string, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return "", err
	}
	lock := m.getServerLock(server.ID)
	lock.Lock()
	defer lock.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getServerConfig(ctx, client)
}

// ErrConfigurationPostApply marks a failure in the caller-supplied reconciliation
// step after the remote AWG configuration was successfully applied.
var ErrConfigurationPostApply = errors.New("AWG configuration post-apply reconciliation failed")

// WriteConfiguration serializes with peer operations and applies both disk and
// runtime changes. If runtime application fails after the disk write, restore
// the preceding configuration under the same lock with a bounded cleanup context.
//
// An edit that changes the server's [Interface] PrivateKey rotates the server's
// identity. Because the user-facing contract is to reconcile rather than reject
// such an edit, every derived artifact that carries the identity is refreshed
// from the newly written configuration before the write is reported successful,
// so a subsequent read - including one against a stopped container, where only
// the artifacts are available - describes the new identity.
func (m *AWGManager) WriteConfiguration(ctx context.Context, server *models.Server, content string) error {
	return m.writeConfigurationTransaction(ctx, server, content, nil)
}

// WriteConfigurationWithPostApply keeps the AWG server lock and remote lock held
// while postApply reconciles state outside the manager (for example the server
// database and active VPN backend). If postApply fails, the previous remote
// configuration is restored before the transaction releases either lock.
func (m *AWGManager) WriteConfigurationWithPostApply(
	ctx context.Context,
	server *models.Server,
	content string,
	postApply func(context.Context) error,
) error {
	if postApply == nil {
		return m.WriteConfiguration(ctx, server, content)
	}
	return m.writeConfigurationTransaction(ctx, server, content, postApply)
}

func (m *AWGManager) writeConfigurationTransaction(
	ctx context.Context,
	server *models.Server,
	content string,
	postApply func(context.Context) error,
) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}
	lock := m.getServerLock(server.ID)
	lock.Lock()
	defer lock.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.acquireRemoteServerLock(ctx, client, server.ID)
	if err != nil {
		return err
	}
	defer unlock()

	original, err := m.getServerConfig(ctx, client)
	if err != nil {
		return err
	}
	written, err := m.saveServerConfigTracked(ctx, client, content)
	if err != nil {
		if written {
			return m.restoreConfigurationAfterFailure(ctx, client, server, content, original, err)
		}
		return err
	}
	if !written {
		return errors.New("AWG configuration write completed without persisting content")
	}

	// The disk and runtime write succeeded. Reconcile the derived identity
	// artifacts before any caller-owned state is committed.
	if err := m.reconcileServerIdentity(ctx, client, server, original, content); err != nil {
		return m.restoreConfigurationAfterFailure(ctx, client, server, content, original, err)
	}

	if postApply == nil {
		return nil
	}
	if err := postApply(ctx); err != nil {
		return m.restoreConfigurationAfterFailure(
			ctx,
			client,
			server,
			content,
			original,
			errors.Join(ErrConfigurationPostApply, err),
		)
	}
	return nil
}

func (m *AWGManager) restoreConfigurationAfterFailure(
	ctx context.Context,
	client ssh.SSHClient,
	server *models.Server,
	attempted string,
	original string,
	cause error,
) error {
	restoreCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()

	written, restoreErr := m.saveServerConfigTracked(restoreCtx, client, original)
	if restoreErr != nil {
		return errors.Join(cause, fmt.Errorf("failed to restore previous AWG configuration: %w", restoreErr))
	}
	if !written {
		return errors.Join(cause, errors.New("failed to restore previous AWG configuration: write was not persisted"))
	}
	if identityErr := m.reconcileServerIdentity(restoreCtx, client, server, attempted, original); identityErr != nil {
		return errors.Join(cause, fmt.Errorf("failed to restore previous AWG identity artifacts: %w", identityErr))
	}
	return cause
}

// reconcileServerIdentity refreshes the derived identity artifacts so they match
// the configuration that was just written.
//
// The public-key artifact is written exactly once at provisioning time
// (initializeServerKeysAndConfig), so an identity-changing edit used to leave it
// describing the pre-rotation server forever. Reconciliation derives the public
// key from the written configuration's [Interface] PrivateKey and rewrites both
// the private- and public-key artifacts.
//
// It is a no-op when the write did not change the PrivateKey, so re-saving the
// same configuration cannot corrupt identity state. A failure to refresh the
// artifacts does not fail the write — the configuration and the live interface
// already carry the new identity, and the read path derives from the
// configuration — but it is logged, because a stopped-container read would then
// fall back to a stale artifact.
func (m *AWGManager) reconcileServerIdentity(ctx context.Context, client ssh.SSHClient, server *models.Server, original, written string) error {
	previousKey := interfacePrivateKey(original)
	newKey := interfacePrivateKey(written)
	if newKey == "" || newKey == previousKey {
		return nil
	}
	newPub, err := derivePublicKeyFromPrivate(newKey)
	if err != nil {
		// The written configuration carries a private key that is not a valid
		// 32-byte base64 value. Leave the artifacts alone rather than writing a
		// public key that does not correspond to anything; the read path will
		// report the same problem.
		slog.Warn("AWG configuration changed the server private key but the new key is not a usable Curve25519 private key; identity artifacts were not refreshed",
			"server_id", serverIDOf(server), "error", err)
		return nil
	}
	// Defense in depth for the two values interpolated below: neither may
	// contain a shell metacharacter even if a future caller builds them
	// differently.
	if !awgKeyPattern.MatchString(newKey) || !awgKeyPattern.MatchString(newPub) {
		return errors.New("refusing to write AWG identity artifacts: key does not match the expected base64 form")
	}

	cName := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(cName) {
		cName = m.containerName()
	}
	if !IsValidContainerName(cName) {
		return errors.New("invalid container name")
	}

	script := fmt.Sprintf("mkdir -p /opt/amnezia/awg\nprintf '%%s' '%s' > %s\nprintf '%%s' '%s' > %s\n",
		newKey, serverPrivateKeyArtifactPath, newPub, serverPublicKeyArtifactPath)
	if _, errOut, code, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker exec -i %s bash -c %s",
		ssh.EscapeShellArg(cName), ssh.EscapeShellArg(script))); err != nil || code != 0 {
		slog.Warn("AWG server identity changed but the derived identity artifacts could not be refreshed; a read against a stopped container will fall back to the previous identity",
			"server_id", serverIDOf(server), "container", cName, "exit_code", code, "stderr", strings.TrimSpace(errOut), "error", err)
		return nil
	}
	slog.Info("refreshed AWG server identity artifacts after a configuration write",
		"server_id", serverIDOf(server), "container", cName)
	return nil
}

// ExtractServerPublicKey returns the Base64-encoded public key derived from
// the [Interface] PrivateKey in an AWG configuration string.
func ExtractServerPublicKey(content string) (string, error) {
	key := interfacePrivateKey(content)
	if key == "" {
		return "", errors.New("no [Interface] PrivateKey found in configuration")
	}
	return derivePublicKeyFromPrivate(key)
}
