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

func (m *NaiveManager) resolveExistingClients(ctx context.Context, client ssh.SSHClient) ([]NaiveClient, error) {
	exists, err := client.FileExists(ctx, NaiveCaddyfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to check existence of Caddyfile %s: %w", NaiveCaddyfilePath, err)
	}
	if !exists {
		return []NaiveClient{}, nil
	}

	catCmd := fmt.Sprintf("cat %s 2>/dev/null", ssh.EscapeShellArg(NaiveCaddyfilePath))
	catOut, catErrOut, catCode, catErr := client.RunSudoCommand(ctx, catCmd)
	var existingCaddyBytes []byte
	if catErr == nil && catCode == 0 && strings.TrimSpace(catOut) != "" && strings.TrimSpace(catOut) != "OK" {
		existingCaddyBytes = []byte(catOut)
	} else {
		data, dlErr := client.DownloadFile(ctx, NaiveCaddyfilePath)
		if dlErr != nil {
			return nil, fmt.Errorf("failed to read existing Caddyfile %s (cat code %d: %s, download err: %w)", NaiveCaddyfilePath, catCode, strings.TrimSpace(catErrOut), dlErr)
		}
		existingCaddyBytes = data
	}

	trimmed := strings.TrimSpace(string(existingCaddyBytes))
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("existing Caddyfile %s is empty or truncated", NaiveCaddyfilePath)
	}

	_, _, clients, parseErr := ParseCaddyfile(trimmed)
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse existing Caddyfile %s: %w", NaiveCaddyfilePath, parseErr)
	}

	if clients == nil {
		clients = []NaiveClient{}
	}
	return clients, nil
}

func (m *NaiveManager) buildAndLaunchContainer(ctx context.Context, client ssh.SSHClient) error {
	dockerfile := RenderCaddyDockerfile()
	if err := client.UploadSudoFile(ctx, fmt.Sprintf("%s/Dockerfile", NaiveConfigDir), []byte(dockerfile), 0644); err != nil {
		return fmt.Errorf("failed to upload Caddy Dockerfile: %w", err)
	}

	buildCmd := fmt.Sprintf("docker build -t %s %s", ssh.EscapeShellArg(NaiveBaseImage), ssh.EscapeShellArg(NaiveConfigDir))
	if _, errOut, code, err := client.RunSudoCommand(ctx, buildCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to build caddy image (code %d): %s: %w", code, errOut, err)
	}

	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker volume create %s 2>/dev/null || true", ssh.EscapeShellArg(NaiveDataVolume)))

	stopCmd := fmt.Sprintf("docker stop %s 2>/dev/null || true; docker rm -fv %s 2>/dev/null || true",
		ssh.EscapeShellArg(NaiveContainerName), ssh.EscapeShellArg(NaiveContainerName))
	_, _, _, _ = client.RunSudoCommand(ctx, stopCmd)

	runCmd := fmt.Sprintf(`docker run -d \
--name %s \
--restart unless-stopped \
--network host \
--log-driver none \
--tmpfs /tmp:rw,noexec,nosuid,size=16m \
--tmpfs /run:rw,noexec,nosuid,size=16m \
-v %s:/etc/caddy:ro \
-v %s:/srv:ro \
-v %s:/data \
%s`,
		ssh.EscapeShellArg(NaiveContainerName),
		ssh.EscapeShellArg(NaiveConfigDir),
		ssh.EscapeShellArg(NaiveHTMLDir),
		ssh.EscapeShellArg(NaiveDataVolume),
		ssh.EscapeShellArg(NaiveBaseImage),
	)

	if _, errOut, code, err := client.RunSudoCommand(ctx, runCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to run naive caddy container (code %d): %s: %w", code, errOut, err)
	}

	checkCmd := fmt.Sprintf("docker inspect -f '{{.State.Running}} {{.State.Restarting}}' %s", ssh.EscapeShellArg(NaiveContainerName))
	out, errOut, code, err := client.RunSudoCommand(ctx, checkCmd)
	if err != nil || code != 0 {
		return fmt.Errorf("caddy container failed to inspect (code %d): %s: %w", code, errOut, err)
	}
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) < 2 || fields[0] != "true" || fields[1] != "false" {
		return fmt.Errorf("caddy container is not running (state: %s)", strings.TrimSpace(out))
	}
	return nil
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
	mkdirCmd := fmt.Sprintf("mkdir -p %s && chmod 0700 %s", ssh.EscapeShellArg(NaiveHTMLDir), ssh.EscapeShellArg(NaiveConfigDir))
	if _, errOut, code, err := client.RunSudoCommand(ctx, mkdirCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to create naive directories (code %d): %s: %w", code, errOut, err)
	}

	// 4. Deploy static decoy website
	decoyHTML := DefaultDecoyHTML()
	if err := client.UploadSudoFile(ctx, fmt.Sprintf("%s/index.html", NaiveHTMLDir), []byte(decoyHTML), 0644); err != nil {
		return fmt.Errorf("upload decoy index.html: %w", err)
	}

	// 5. Render and upload initial or preserved Caddyfile
	existingClients, err := m.resolveExistingClients(ctx, client)
	if err != nil {
		return fmt.Errorf("resolve existing clients: %w", err)
	}
	caddyfileContent := RenderCaddyfile(port, domain, existingClients)
	if err := client.UploadSudoFile(ctx, NaiveCaddyfilePath, []byte(caddyfileContent), 0600); err != nil {
		return fmt.Errorf("upload Caddyfile: %w", err)
	}

	// 6. Build and launch amnezia-caddy container
	if err := m.buildAndLaunchContainer(ctx, client); err != nil {
		return err
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

	// 1. Inspect whether container is absent
	inspectCmd := fmt.Sprintf("docker inspect %s", ssh.EscapeShellArg(NaiveContainerName))
	out, errOut, code, err := client.RunSudoCommand(ctx, inspectCmd)
	if err != nil {
		return fmt.Errorf("failed to inspect naive container: %w", err)
	}

	containerAbsent := false
	if code != 0 {
		combined := strings.ToLower(out + " " + errOut)
		if strings.Contains(combined, "no such") {
			containerAbsent = true
		} else {
			return fmt.Errorf("failed to inspect naive container (code %d): %s", code, strings.TrimSpace(errOut))
		}
	} else if strings.TrimSpace(out) == "false false" {
		containerAbsent = true
	}

	// 2. If present, stop and remove container without || true
	if !containerAbsent {
		rmCmd := fmt.Sprintf("docker stop %s && docker rm -fv %s",
			ssh.EscapeShellArg(NaiveContainerName),
			ssh.EscapeShellArg(NaiveContainerName),
		)
		if _, errOut, code, err := client.RunSudoCommand(ctx, rmCmd); err != nil || code != 0 {
			return fmt.Errorf("failed to stop and remove naive container (code %d): %s: %w", code, strings.TrimSpace(errOut), err)
		}

		verifyOut, verifyErrOut, verifyCode, verifyErr := client.RunSudoCommand(ctx, inspectCmd)
		if verifyErr != nil {
			return fmt.Errorf("failed to verify naive container removal: %w", verifyErr)
		}
		if verifyCode == 0 && strings.TrimSpace(verifyOut) != "false false" {
			return fmt.Errorf("naive container %s still present after removal", NaiveContainerName)
		}
		if verifyCode != 0 && !strings.Contains(strings.ToLower(verifyOut+" "+verifyErrOut), "no such") {
			return fmt.Errorf("unexpected inspect status for %s (code %d): %s", NaiveContainerName, verifyCode, strings.TrimSpace(verifyErrOut))
		}
	}

	// 3. Remove configuration directory only after container removal is confirmed
	rmDirCmd := fmt.Sprintf("rm -rf %s", ssh.EscapeShellArg(NaiveConfigDir))
	if _, errOut, code, err := client.RunSudoCommand(ctx, rmDirCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to remove naive config directory (code %d): %s: %w", code, strings.TrimSpace(errOut), err)
	}

	if server.Protocols != nil {
		delete(server.Protocols, models.ProtocolNaive)
	}
	return nil
}
