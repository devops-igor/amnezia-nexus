package naive

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func parseNaiveInstallOptions(params map[string]any, defaultHost string) (int, string) {
	port := 443
	if p, ok := params["port"]; ok && fmt.Sprint(p) != "" {
		if pInt, err := strconv.Atoi(fmt.Sprint(p)); err == nil && pInt > 0 {
			port = pInt
		}
	}

	domain := defaultHost
	if no, ok := params["naive_options"]; ok && no != nil {
		switch opt := no.(type) {
		case *models.NaiveInstallOptions:
			if opt.Port != "" {
				if pInt, err := strconv.Atoi(opt.Port); err == nil && pInt > 0 {
					port = pInt
				}
			}
			if opt.Domain != "" {
				domain = opt.Domain
			}
		case models.NaiveInstallOptions:
			if opt.Port != "" {
				if pInt, err := strconv.Atoi(opt.Port); err == nil && pInt > 0 {
					port = pInt
				}
			}
			if opt.Domain != "" {
				domain = opt.Domain
			}
		case map[string]any:
			if p, ok := opt["port"].(string); ok && p != "" {
				if pInt, err := strconv.Atoi(p); err == nil && pInt > 0 {
					port = pInt
				}
			}
			if d, ok := opt["domain"].(string); ok && d != "" {
				domain = d
			}
		}
	}
	return port, domain
}

// Install configures Caddy forward_proxy, deploys the decoy website, and launches amnezia-caddy.
func (m *NaiveManager) Install(ctx context.Context, server *models.Server, params map[string]any) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}

	unlock, err := m.lockServer(ctx, client, server.ID)
	if err != nil {
		return err
	}
	defer unlock()

	// 1. Check Docker is installed
	out, _, code, _ := client.RunCommand(ctx, "docker --version")
	if code != 0 || !strings.Contains(strings.ToLower(out), "docker") {
		return errors.New("docker is not installed on the remote server")
	}

	// 2. Parse installation options
	port, domain := parseNaiveInstallOptions(params, server.Host)

	// 3. Create directory structure
	mkdirCmd := fmt.Sprintf("mkdir -p %s", ssh.EscapeShellArg(NaiveHTMLDir))
	if _, errOut, code, err := client.RunSudoCommand(ctx, mkdirCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to create naive directories (code %d): %s: %w", code, errOut, err)
	}

	// 4. Deploy static decoy website
	decoyHTML := DefaultDecoyHTML()
	if err := client.UploadSudoFile(ctx, fmt.Sprintf("%s/index.html", NaiveHTMLDir), []byte(decoyHTML), 0644); err != nil {
		return fmt.Errorf("upload decoy index.html: %w", err)
	}

	// 5. Write local DNS resolver configuration
	resolvConf := "nameserver 127.0.0.1\noptions no-aaaa\n"
	_ = client.UploadSudoFile(ctx, NaiveResolvConf, []byte(resolvConf), 0644)

	// 6. Render and upload initial Caddyfile
	caddyfileContent := RenderCaddyfile(port, domain, []NaiveClient{})
	if err := client.UploadSudoFile(ctx, NaiveCaddyfilePath, []byte(caddyfileContent), 0644); err != nil {
		return fmt.Errorf("upload Caddyfile: %w", err)
	}

	// 7. Ensure persistent data volume for Let's Encrypt certificates
	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker volume create %s 2>/dev/null || true", ssh.EscapeShellArg(NaiveDataVolume)))

	// 8. Cleanup any stale caddy container
	stopCmd := fmt.Sprintf("docker stop %s 2>/dev/null || true; docker rm -fv %s 2>/dev/null || true",
		ssh.EscapeShellArg(NaiveContainerName), ssh.EscapeShellArg(NaiveContainerName))
	_, _, _, _ = client.RunSudoCommand(ctx, stopCmd)

	// Best-effort image pull
	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker pull %s 2>/dev/null || true", ssh.EscapeShellArg(NaiveBaseImage)))

	// 9. Launch amnezia-caddy container
	runCmd := fmt.Sprintf(`docker run -d \
--name %s \
--restart unless-stopped \
--network host \
-v %s:/etc/caddy/Caddyfile:ro \
-v %s:/srv:ro \
-v %s:/data \
-v %s:/etc/resolv.conf:ro \
%s`,
		ssh.EscapeShellArg(NaiveContainerName),
		ssh.EscapeShellArg(NaiveCaddyfilePath),
		ssh.EscapeShellArg(NaiveHTMLDir),
		ssh.EscapeShellArg(NaiveDataVolume),
		ssh.EscapeShellArg(NaiveResolvConf),
		ssh.EscapeShellArg(NaiveBaseImage),
	)

	if _, errOut, code, err := client.RunSudoCommand(ctx, runCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to run naive caddy container (code %d): %s: %w", code, errOut, err)
	}

	// 10. Verify container is alive
	checkCmd := fmt.Sprintf("docker ps --filter name=^%s$ --format '{{.Names}}'", ssh.EscapeShellArg(NaiveContainerName))
	out, _, code, err = client.RunCommand(ctx, checkCmd)
	if err != nil || code != 0 || !strings.Contains(out, NaiveContainerName) {
		return fmt.Errorf("caddy container failed to start: %s", out)
	}

	// Update server.Protocols in-memory
	if server.Protocols == nil {
		server.Protocols = make(map[string]any)
	}
	server.Protocols[models.ProtocolNaive] = map[string]any{
		"installed": true,
		"port":      port,
		"domain":    domain,
	}

	return nil
}

// Uninstall stops and removes the amnezia-caddy container and configuration.
func (m *NaiveManager) Uninstall(ctx context.Context, server *models.Server) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}

	unlock, err := m.lockServer(ctx, client, server.ID)
	if err != nil {
		return err
	}
	defer unlock()

	cleanupCmd := fmt.Sprintf(
		"docker stop %s 2>/dev/null || true; docker rm -fv %s 2>/dev/null || true; rm -rf %s",
		ssh.EscapeShellArg(NaiveContainerName),
		ssh.EscapeShellArg(NaiveContainerName),
		ssh.EscapeShellArg(NaiveConfigDir),
	)
	_, _, _, _ = client.RunSudoCommand(ctx, cleanupCmd)

	if server.Protocols != nil {
		delete(server.Protocols, models.ProtocolNaive)
	}
	return nil
}
