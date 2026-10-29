package xray

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// ErrInvalidConfiguration marks an Xray configuration that cannot be parsed.
var ErrInvalidConfiguration = errors.New("invalid xray configuration")

// WriteConfiguration validates and applies an Xray configuration, restoring the
// previous file and restarting the container again if the first restart fails.
func (m *XrayManager) WriteConfiguration(ctx context.Context, server *models.Server, content string) error {
	if _, err := ParseXrayConfig([]byte(content)); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidConfiguration, err)
	}

	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}
	unlock, err := m.lockServer(ctx, client, server.ID)
	if err != nil {
		return err
	}
	defer unlock()

	previous, err := client.DownloadSudoFile(ctx, XrayConfigPath)
	if err != nil {
		return fmt.Errorf("download previous xray config: %w", err)
	}
	restart := func(ctx context.Context) error {
		cmd := fmt.Sprintf("docker restart %s", ssh.EscapeShellArg(XrayContainerName))
		_, errOut, code, err := client.RunSudoCommand(ctx, cmd)
		if err != nil {
			return fmt.Errorf("restart xray container: %w", err)
		}
		if code != 0 {
			return fmt.Errorf("restart xray container exited with code %d: %s", code, strings.TrimSpace(errOut))
		}

		inspectCmd := fmt.Sprintf(
			"docker inspect -f '{{.State.Running}} {{.State.Restarting}} {{.State.Pid}}' %s",
			ssh.EscapeShellArg(XrayContainerName),
		)
		out, errOut, code, err := client.RunSudoCommand(ctx, inspectCmd)
		if err != nil {
			return fmt.Errorf("inspect xray container after restart: %w", err)
		}
		if code != 0 {
			return fmt.Errorf("inspect xray container exited with code %d: %s", code, strings.TrimSpace(errOut))
		}
		state := strings.TrimSpace(out)
		fields := strings.Fields(state)
		if len(fields) != 3 {
			return fmt.Errorf("unexpected xray container state after restart %q", state)
		}
		pid, err := strconv.Atoi(fields[2])
		if err != nil {
			return fmt.Errorf("parse xray container pid after restart: %w", err)
		}
		healthy := fields[0] == "true" && fields[1] == "false" && pid > 0
		if !healthy {
			return fmt.Errorf("xray container is not healthy after restart (state %q)", state)
		}
		return nil
	}
	rollback := func(applyErr error) error {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if restoreErr := client.UploadSudoFile(rollbackCtx, XrayConfigPath, previous, 0600); restoreErr != nil {
			return errors.Join(applyErr, fmt.Errorf("restore previous xray config: %w", restoreErr))
		}
		if recoveryErr := restart(rollbackCtx); recoveryErr != nil {
			return errors.Join(applyErr, fmt.Errorf("restart xray container with previous config: %w", recoveryErr))
		}
		return applyErr
	}

	// An upload error can occur after the remote move committed, so always compensate.
	if err := client.UploadSudoFile(ctx, XrayConfigPath, []byte(content), 0600); err != nil {
		return rollback(fmt.Errorf("upload xray config: %w", err))
	}
	if err := restart(ctx); err != nil {
		return rollback(err)
	}
	return nil
}
