package naive

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// ErrInvalidConfiguration marks a Caddyfile that cannot be parsed.
var ErrInvalidConfiguration = errors.New("invalid naive configuration")

// WriteConfiguration validates and applies a Caddyfile, restoring the previous
// file and reloading Caddy again if the first reload fails.
func (m *NaiveManager) WriteConfiguration(ctx context.Context, server *models.Server, content string) error {
	if _, _, _, err := ParseCaddyfile(content); err != nil {
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

	previous, err := client.DownloadSudoFile(ctx, NaiveCaddyfilePath)
	if err != nil {
		return fmt.Errorf("download previous Caddyfile: %w", err)
	}
	if err := client.UploadSudoFile(ctx, NaiveCaddyfilePath, []byte(content), 0600); err != nil {
		return fmt.Errorf("upload Caddyfile: %w", err)
	}

	reload := func(ctx context.Context) error {
		cmd := fmt.Sprintf("docker exec %s caddy reload --config /etc/caddy/Caddyfile", ssh.EscapeShellArg(NaiveContainerName))
		_, errOut, code, err := client.RunSudoCommand(ctx, cmd)
		if err != nil {
			return fmt.Errorf("reload caddy container: %w", err)
		}
		if code != 0 {
			return fmt.Errorf("reload caddy container exited with code %d: %s", code, strings.TrimSpace(errOut))
		}
		return nil
	}

	if err := reload(ctx); err != nil {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if restoreErr := client.UploadSudoFile(rollbackCtx, NaiveCaddyfilePath, previous, 0600); restoreErr != nil {
			return errors.Join(err, fmt.Errorf("restore previous Caddyfile: %w", restoreErr))
		}
		if recoveryErr := reload(rollbackCtx); recoveryErr != nil {
			return errors.Join(err, fmt.Errorf("reload caddy with previous Caddyfile: %w", recoveryErr))
		}
		return err
	}
	return nil
}
