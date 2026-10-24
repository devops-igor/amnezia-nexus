package awg

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/cps"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func ensureDockerInstalled(ctx context.Context, client ssh.SSHClient) error {
	out, _, code, _ := client.RunCommand(ctx, "docker --version")
	if code == 0 && strings.Contains(strings.ToLower(out), "docker") {
		return nil
	}
	dockerScript := `
if which apt-get > /dev/null 2>&1; then pm=$(which apt-get); silent_inst="-yq install"; check_pkgs="-yq update"; docker_pkg="docker.io"; dist="debian";
elif which dnf > /dev/null 2>&1; then pm=$(which dnf); silent_inst="-yq install"; check_pkgs="-yq check-update"; docker_pkg="docker"; dist="fedora";
elif which yum > /dev/null 2>&1; then pm=$(which yum); silent_inst="-y -q install"; check_pkgs="-y -q check-update"; docker_pkg="docker"; dist="centos";
else echo "Packet manager not found"; exit 1; fi;
if [ "$dist" = "debian" ]; then export DEBIAN_FRONTEND=noninteractive; fi;
if ! command -v docker > /dev/null 2>&1; then $pm $check_pkgs && $pm $silent_inst $docker_pkg && systemctl enable --now docker; fi;
systemctl start docker; docker --version
`
	if _, errOut, dCode, err := client.RunSudoScript(ctx, dockerScript); err != nil || dCode != 0 {
		return fmt.Errorf("failed to install Docker (code %d): %s, %w", dCode, errOut, err)
	}
	return nil
}

func prepareHostAndContainers(ctx context.Context, client ssh.SSHClient) error {
	prepScript := `
mkdir -p /opt/amnezia/amnezia-awg2 /opt/amnezia/awg
if ! docker network ls | grep -q amnezia-dns-net; then
  docker network create --driver bridge --subnet=172.29.172.0/24 --opt com.docker.network.bridge.name=amn0 amnezia-dns-net || true
fi
`
	if _, _, _, err := client.RunSudoScript(ctx, prepScript); err != nil {
		return fmt.Errorf("failed to prepare host: %w", err)
	}

	for _, name := range AWGContainerNames {
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker stop %s 2>/dev/null || true", ssh.EscapeShellArg(name)))
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker rm -fv %s 2>/dev/null || true", ssh.EscapeShellArg(name)))
	}
	return nil
}

// awgBaseImage pins the AmneziaWG userspace base image used to build AWG
// backends. devopsigor/amneziawg:v3.1.20260828-1 is a versioned multiarch
// (amd64+arm64) tag from the amneziawg-docker repo, built from the
// AmneziaWG v3.1.20260828 source (devopsigor publishing). Multiarch is
// required because backends install on both amd64 and arm64 hosts — the
// upstream amneziavpn/amneziawg-go image publishes amd64 only, which broke
// ARM64 installs (Issue #225). The versioned tag is chosen over :latest
// because this image becomes a privileged VPN container on remote hosts:
// a mutable floating tag is a supply-chain and reproducibility hazard, so
// installs must pin a pinned, versioned release. The explicit pull
// before build ensures the tag exists on the host instead of failing
// mid-build with a stale local cache.
const awgBaseImage = "devopsigor/amneziawg:v3.1.20260828-1"

func (m *AWGManager) buildAndRunAWGContainer(ctx context.Context, client ssh.SSHClient, port string) error {
	cName := m.containerName()
	if !IsValidContainerName(cName) {
		cName = "amnezia-awg2"
	}
	// Preflight: fail fast when the UDP port is already bound (host socket or
	// existing docker port binding) instead of discovering it at `docker run`
	// time after a slow pull+build cycle (Issue #225). Best-effort: a port
	// could still bind between check and run — `docker run` remains the final
	// authority.
	if err := checkUDPPortAvailable(ctx, client, port); err != nil {
		return err
	}
	dockerfile := fmt.Sprintf(`FROM %s
LABEL maintainer="AmneziaVPN"
RUN apk add --no-cache bash curl dumb-init iptables && apk --update upgrade --no-cache
RUN mkdir -p /opt/amnezia
RUN echo "#!/bin/bash" > /opt/amnezia/start.sh && echo "tail -f /dev/null" >> /opt/amnezia/start.sh && chmod a+x /opt/amnezia/start.sh
ENTRYPOINT [ "dumb-init", "/opt/amnezia/start.sh" ]
`, awgBaseImage)
	if err := client.UploadSudoFile(ctx, fmt.Sprintf("/opt/amnezia/%s/Dockerfile", cName), []byte(dockerfile), 0644); err != nil {
		return fmt.Errorf("failed to upload Dockerfile: %w", err)
	}

	if _, errOut, pCode, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker pull %s", ssh.EscapeShellArg(awgBaseImage))); err != nil || pCode != 0 {
		return fmt.Errorf("failed to pull AWG base image %s (code %d): %s, %w", awgBaseImage, pCode, errOut, err)
	}

	if _, errOut, bCode, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker build --no-cache -t %s /opt/amnezia/%s", ssh.EscapeShellArg(cName), ssh.EscapeShellArg(cName))); err != nil || bCode != 0 {
		return fmt.Errorf("failed to build %s image (code %d): %s, %w", cName, bCode, errOut, err)
	}

	runCmd := fmt.Sprintf(`docker run -d \
--restart always \
--privileged \
--cap-add=NET_ADMIN \
--cap-add=SYS_MODULE \
-p %s:%s/udp \
-v /lib/modules:/lib/modules \
--sysctl="net.ipv4.conf.all.src_valid_mark=1" \
--name %s \
%s`, ssh.EscapeShellArg(port), ssh.EscapeShellArg(port), ssh.EscapeShellArg(cName), ssh.EscapeShellArg(cName))

	if _, errOut, rCode, err := client.RunSudoCommand(ctx, runCmd); err != nil || rCode != 0 {
		return fmt.Errorf("failed to run container (code %d): %s, %w", rCode, errOut, err)
	}

	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker network connect amnezia-dns-net %s 2>/dev/null || true", ssh.EscapeShellArg(cName)))
	return nil
}

func buildAndRunAWGContainer(ctx context.Context, client ssh.SSHClient, port string) error {
	return (&AWGManager{}).buildAndRunAWGContainer(ctx, client, port)
}

// legacyTcCleanupCommands returns the exact remote commands that clear tc
// data-plane state installed by the pre-74b34d9 speed-limit code inside the
// AWG container: the root qdisc on awg0 (plus its per-client HTB classes and
// filters), the root qdisc on ifb0, and finally the ifb0 redirect device.
// Every command carries `|| true` inside the container shell — the sweep is
// strictly best-effort inside the container, while docker exec failures propagate.
func legacyTcCleanupCommands(containerName string) []string {
	cn := ssh.EscapeShellArg(containerName)
	return []string{
		fmt.Sprintf("docker exec -i %s sh -c 'tc qdisc del dev awg0 root 2>/dev/null || true'", cn),
		fmt.Sprintf("docker exec -i %s sh -c 'tc qdisc del dev ifb0 root 2>/dev/null || true'", cn),
		fmt.Sprintf("docker exec -i %s sh -c 'ip link del ifb0 2>/dev/null || true'", cn),
	}
}

// CleanupLegacyTcRules removes leftover tc speed-limit state (HTB qdiscs,
// filters, the ifb0 redirect device) from an existing AWG container. The
// speed-limit removal (74b34d9) deleted the control plane without clearing
// remote data-plane state, so deployments installed by the old code kept
// enforcing invisible limits with no UI/API left to clear them (PR #231
// re-review, Fix 2). Idempotent by construction: every command is a delete
// guarded by `|| true`, so re-running on a clean container is a no-op.
// Returns an error if any cleanup command failed so the caller can retry
// later (the status-path guard only marks a server cleaned on success).
func (m *AWGManager) CleanupLegacyTcRules(ctx context.Context, client ssh.SSHClient, containerName string) error {
	if !IsValidContainerName(containerName) {
		slog.Warn("legacy tc cleanup: skipping invalid container name", "container", containerName)
		return fmt.Errorf("invalid container name %q", containerName)
	}
	var firstErr error
	for _, cmd := range legacyTcCleanupCommands(containerName) {
		if _, errOut, code, err := client.RunSudoCommand(ctx, cmd); err != nil || code != 0 {
			slog.Warn("legacy tc cleanup: command failed (will retry on next status poll)",
				"command", cmd, "exit_code", code, "stderr", errOut, "error", err)
			if firstErr == nil {
				if err != nil {
					firstErr = fmt.Errorf("%s failed (exit %d): %s, %w", cmd, code, errOut, err)
				} else {
					firstErr = fmt.Errorf("%s failed (exit %d): %s", cmd, code, errOut)
				}
			}
		}
	}
	return firstErr
}

// checkUDPPortAvailable verifies that the requested UDP port is not already
// bound on the remote host before the AWG install pulls or builds anything.
// It checks two sources: host listening UDP sockets (`ss -lun`) and existing
// docker port bindings (`docker ps --format '{{.Ports}}'`), because a port
// published by another container does not appear in host `ss` output when the
// panel itself runs inside a container (Issue #225, Server 1). A failed
// probe command is not fatal — the install proceeds and any real conflict
// still surfaces from `docker run` as before.
func checkUDPPortAvailable(ctx context.Context, client ssh.SSHClient, port string) error {
	const conflictErr = "UDP port %s is already in use on the server — choose a different port for the AWG backend"

	ssOut, _, _, err := client.RunSudoCommand(ctx, "ss -lun 2>/dev/null || true")
	if err != nil {
		slog.Warn("preflight: failed to list listening UDP sockets", "error", err)
	} else if udpPortBound(ssOut, port) {
		return fmt.Errorf(conflictErr, port)
	}

	portsOut, _, _, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker ps --filter publish=%s/udp --format '{{.Ports}}' 2>/dev/null || true", ssh.EscapeShellArg(port)))
	if err != nil {
		slog.Warn("preflight: failed to list docker port bindings", "error", err)
	} else if strings.TrimSpace(portsOut) != "" {
		// Non-empty output: some container already publishes this host
		// port (the publish filter matches the HOST side, regardless of
		// the container-side port, and covers ranges).
		return fmt.Errorf(conflictErr, port)
	}

	return nil
}

// udpPortBound reports whether ss(8) output shows a UDP socket whose local
// port equals port. Matching is token-based: strings.Fields yields the local
// endpoint as a single `addr:port` token (e.g. `0.0.0.0:51820` or `[::]:53`),
// and the suffix `:<port>` is matched against the whole token to avoid prefix
// false positives such as `:5182` matching a bound `:51820`.
func udpPortBound(ssOut, port string) bool {
	for _, line := range strings.Split(ssOut, "\n") {
		for _, field := range strings.Fields(line) {
			if strings.HasSuffix(field, ":"+port) {
				return true
			}
		}
	}
	return false
}

func (m *AWGManager) initializeServerKeysAndConfig(ctx context.Context, client ssh.SSHClient, port string, awgParams *AWGParams) error {
	cName := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(cName) {
		cName = m.containerName()
	}
	if !IsValidContainerName(cName) {
		cName = "amnezia-awg2"
	}

	serverPrivKey, serverPubKey, err := GenerateWGKeypair()
	if err != nil {
		return fmt.Errorf("failed to generate server keypair: %w", err)
	}
	serverPSK, err := GeneratePSK()
	if err != nil {
		return fmt.Errorf("failed to generate server psk: %w", err)
	}

	keygenScript := fmt.Sprintf(`
mkdir -p /opt/amnezia/awg
echo "%s" > %s
echo "%s" > %s
echo "%s" > %s
`, serverPrivKey, serverPrivateKeyArtifactPath, serverPubKey, serverPublicKeyArtifactPath, serverPSK, serverPSKArtifactPath)
	if _, errOut, code, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker exec -i %s bash -c %s", ssh.EscapeShellArg(cName), ssh.EscapeShellArg(keygenScript))); err != nil || code != 0 {
		// Provisioning keeps its historical best-effort behavior here: the
		// identity artifacts are recoverable (the config still carries the
		// private key, and GetServerPublicKey derives from it), so a failed
		// artifact write must not abort an otherwise valid install.
		slog.Warn("failed to write AmneziaWG server identity artifacts during provisioning",
			"container", cName, "exit_code", code, "stderr", strings.TrimSpace(errOut), "error", err)
	}

	serverConfig := RenderServerConfig(serverPrivKey, AWGDefaults["subnet_ip"], AWGDefaults["subnet_cidr"], port, awgParams.MTU, awgParams, nil)
	if err := client.UploadSudoFile(ctx, "/tmp/_amnz_awg0.conf", []byte(serverConfig), 0600); err != nil {
		return err
	}
	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker cp '/tmp/_amnz_awg0.conf' %s:'/opt/amnezia/awg/awg0.conf'", ssh.EscapeShellArg(cName)))
	_, _, _, _ = client.RunSudoCommand(ctx, "rm -f /tmp/_amnz_awg0.conf")

	startScript := `#!/bin/bash
ip -4 rule del not fwmark 51820 table 51820 2>/dev/null || true
ip -4 rule del table main suppress_prefixlength 0 2>/dev/null || true
ip -4 route flush table 51820 2>/dev/null || true
awg-quick down /opt/amnezia/awg/awg0.conf 2>/dev/null || true
if [ -f /opt/amnezia/awg/awg0.conf ]; then awg-quick up /opt/amnezia/awg/awg0.conf; fi
ip -4 rule del not fwmark 51820 table 51820 2>/dev/null || true
ip -4 rule del table main suppress_prefixlength 0 2>/dev/null || true
ip -4 route flush table 51820 2>/dev/null || true
ip route replace 10.100.0.0/16 dev awg0 2>/dev/null || ip route add 10.100.0.0/16 dev awg0 2>/dev/null || true
sysctl -w net.ipv4.conf.all.rp_filter=2 2>/dev/null || true
sysctl -w net.ipv4.conf.awg0.rp_filter=2 2>/dev/null || true
iptables -A INPUT -i awg0 -j ACCEPT
iptables -A FORWARD -i awg0 -j ACCEPT
iptables -A OUTPUT -o awg0 -j ACCEPT
iptables -A FORWARD -i awg0 -o eth0 -j ACCEPT
iptables -C FORWARD -s 10.100.0.0/16 -j ACCEPT 2>/dev/null || iptables -A FORWARD -s 10.100.0.0/16 -j ACCEPT
iptables -C FORWARD -d 10.100.0.0/16 -j ACCEPT 2>/dev/null || iptables -A FORWARD -d 10.100.0.0/16 -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t nat -C POSTROUTING -s 10.100.0.0/16 -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -I POSTROUTING 1 -s 10.100.0.0/16 -o eth0 -j MASQUERADE
iptables -t nat -C POSTROUTING -s 10.100.0.0/16 -o eth1 -j MASQUERADE 2>/dev/null || iptables -t nat -I POSTROUTING 1 -s 10.100.0.0/16 -o eth1 -j MASQUERADE 2>/dev/null || true
iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -C POSTROUTING -s 10.100.0.0/16 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.100.0.0/16 -j MASQUERADE
tail -f /dev/null
`

	if err := client.UploadSudoFile(ctx, "/tmp/_amnz_start.sh", []byte(startScript), 0755); err != nil {
		return err
	}
	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker cp '/tmp/_amnz_start.sh' %s:'/opt/amnezia/start.sh'", ssh.EscapeShellArg(cName)))
	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker exec %s chmod +x /opt/amnezia/start.sh", ssh.EscapeShellArg(cName)))
	_, _, _, _ = client.RunSudoCommand(ctx, "rm -f /tmp/_amnz_start.sh")
	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker restart %s", ssh.EscapeShellArg(cName)))

	firewallScript := `
sysctl -w net.ipv4.ip_forward=1
iptables -C INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null || iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
`
	_, _, _, _ = client.RunSudoScript(ctx, firewallScript)
	return nil
}

func initializeServerKeysAndConfig(ctx context.Context, client ssh.SSHClient, port string, awgParams *AWGParams) error {
	return (&AWGManager{}).initializeServerKeysAndConfig(ctx, client, port, awgParams)
}

// Install deploys Docker (if missing), builds the AWG container, configures parameters, and starts the service.
func (m *AWGManager) Install(ctx context.Context, server *models.Server, params map[string]any) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	port := AWGDefaults["port"]
	if p, ok := params["port"]; ok && fmt.Sprint(p) != "" {
		port = fmt.Sprint(p)
	}

	profile := "standard"
	if p, ok := params["awg_profile"]; ok && fmt.Sprint(p) != "" {
		profile = fmt.Sprint(p)
	}

	// AWG 3.1 header protection defaults to ON: new installs get 3.x semantics
	// unless explicitly disabled (compat mode for 2.0 backends).
	hpOn := true
	if v, ok := parseBoolParam(params["awg_header_protection"]); ok {
		hpOn = v
	}
	awgParams, err := GenerateAWGParams(profile, hpOn)
	if err != nil {
		return fmt.Errorf("failed to generate AWG params: %w", err)
	}
	awgParams.Port = port

	cpsProto := "sip"
	if params != nil {
		if cp, ok := params["awg_cps_protocol"]; ok && fmt.Sprint(cp) != "" {
			cpsProto = strings.ToLower(strings.TrimSpace(fmt.Sprint(cp)))
		}
	}
	d, err := cps.SelectMimicryDomain(ctx, client, cpsProto)
	if err != nil || d == "" {
		d = cps.FallbackDomains[cpsProto]
	}
	if cpsPackets, err := cps.GenerateCPSPackets(profile, d, cpsProto); err == nil {
		awgParams.I1 = cpsPackets["i1"]
		awgParams.I2 = cpsPackets["i2"]
		awgParams.I3 = cpsPackets["i3"]
		awgParams.I4 = cpsPackets["i4"]
		awgParams.I5 = cpsPackets["i5"]
	}
	if m.installHook != nil {
		m.installHook(awgParams)
	}

	if err := ensureDockerInstalled(ctx, client); err != nil {
		return err
	}
	if err := prepareHostAndContainers(ctx, client); err != nil {
		return err
	}
	if err := m.buildAndRunAWGContainer(ctx, client, port); err != nil {
		return err
	}
	return m.initializeServerKeysAndConfig(ctx, client, port, awgParams)
}

// Uninstall stops and removes all AWG containers and clean up directories.
func (m *AWGManager) Uninstall(ctx context.Context, server *models.Server) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.invalidateContainerCache(server)

	for _, name := range AWGContainerNames {
		if !IsValidContainerName(name) {
			continue
		}
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker stop %s 2>/dev/null || true", ssh.EscapeShellArg(name)))
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker rm -fv %s 2>/dev/null || true", ssh.EscapeShellArg(name)))
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker rmi %s 2>/dev/null || true", ssh.EscapeShellArg(name)))
	}
	_, _, _, _ = client.RunSudoCommand(ctx, "rm -rf /opt/amnezia/amnezia-awg /opt/amnezia/amnezia-awg2 /opt/amnezia/awg")
	return nil
}

func runDockerCmdWithRetry(ctx context.Context, client ssh.SSHClient, cmd string) (string, int, error) {
	const maxRetries = 2
	var (
		out  string
		code int
		err  error
	)
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return "", code, ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		}
		out, _, code, err = client.RunSudoCommand(ctx, cmd)
		if err == nil && code == 0 {
			return out, code, nil
		}
	}
	return out, code, err
}

func (m *AWGManager) discoverContainerName(ctx context.Context, client ssh.SSHClient) (string, bool) {
	if client == nil {
		return "", false
	}
	if cached, ok := m.getCachedContainerForClient(client); ok && IsValidContainerName(cached) {
		return cached, true
	}

	for _, name := range AWGContainerNames {
		if !IsValidContainerName(name) {
			continue
		}
		out, code, err := runDockerCmdWithRetry(ctx, client, fmt.Sprintf("docker ps --filter name=^%s$ --format '{{.Names}}'", ssh.EscapeShellArg(name)))
		if err == nil && code == 0 {
			for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed == name {
					m.setCachedContainerForClient(client, name)
					return name, true
				}
			}
		}
	}
	// Fallback to any running container with name starting with amnezia-awg
	out, code, err := runDockerCmdWithRetry(ctx, client, "docker ps --filter name=amnezia-awg --format '{{.Names}}'")
	if err == nil && code == 0 {
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "amnezia-awg") && IsValidContainerName(trimmed) {
				m.setCachedContainerForClient(client, trimmed)
				return trimmed, true
			}
		}
	}
	return "", false
}

func (m *AWGManager) resolveContainerName(ctx context.Context, client ssh.SSHClient) string {
	if client != nil {
		if found, ok := m.discoverContainerName(ctx, client); ok {
			return found
		}
	}
	safeDefault := m.containerName()
	if !IsValidContainerName(safeDefault) {
		safeDefault = "amnezia-awg2"
	}
	return safeDefault
}

// ResolveContainerName returns the discovered or default container name for the given client.
func (m *AWGManager) ResolveContainerName(ctx context.Context, client ssh.SSHClient) string {
	return m.resolveContainerName(ctx, client)
}

// ensureBackendRoutingAndNAT installs the return route for the portal client subnet,
// interface-scoped and subnet-scoped NAT masquerade rules, FORWARD rules, and loose
// reverse path filtering inside the backend's AWG container. Portal data-plane traffic
// arrives on awg0 with source IPs from the portal IPAM subnet (e.g. 10.100.0.0/16);
// without the return route, reply traffic is routed out eth0 default gateway and Martian
// packet filtering on awg0 drops incoming traffic.
func (m *AWGManager) ensureBackendRoutingAndNAT(ctx context.Context, client ssh.SSHClient, subnet string) error {
	cName := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(cName) {
		return fmt.Errorf("cannot ensure backend routing and NAT: invalid container name %q", cName)
	}

	subnet = strings.TrimSpace(subnet)
	if subnet == "" {
		subnet = "10.100.0.0/16"
	}
	if _, _, err := net.ParseCIDR(subnet); err != nil {
		return fmt.Errorf("invalid subnet CIDR %q: %w", subnet, err)
	}

	rules := []string{
		"ip -4 rule del not fwmark 51820 table 51820 2>/dev/null || true",
		"ip -4 rule del table main suppress_prefixlength 0 2>/dev/null || true",
		"ip -4 route flush table 51820 2>/dev/null || true",
		fmt.Sprintf("ip route replace %s dev awg0 2>/dev/null || ip route add %s dev awg0 2>/dev/null || true", subnet, subnet),
		fmt.Sprintf("iptables -t nat -C POSTROUTING -s %s -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -I POSTROUTING 1 -s %s -o eth0 -j MASQUERADE", subnet, subnet),
		fmt.Sprintf("iptables -t nat -C POSTROUTING -s %s -o eth1 -j MASQUERADE 2>/dev/null || iptables -t nat -I POSTROUTING 1 -s %s -o eth1 -j MASQUERADE 2>/dev/null || true", subnet, subnet),
		fmt.Sprintf("iptables -t nat -C POSTROUTING -s %s -j MASQUERADE 2>/dev/null || iptables -t nat -I POSTROUTING 1 -s %s -j MASQUERADE", subnet, subnet),
		"iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
		"iptables -t nat -C POSTROUTING -o eth1 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE 2>/dev/null || true",
		fmt.Sprintf("iptables -C FORWARD -s %s -j ACCEPT 2>/dev/null || iptables -A FORWARD -s %s -j ACCEPT", subnet, subnet),
		fmt.Sprintf("iptables -C FORWARD -d %s -j ACCEPT 2>/dev/null || iptables -A FORWARD -d %s -j ACCEPT", subnet, subnet),
		"iptables -C FORWARD -i awg0 -o eth0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i awg0 -o eth0 -j ACCEPT",
		"iptables -C FORWARD -i awg0 -o eth1 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i awg0 -o eth1 -j ACCEPT 2>/dev/null || true",
		"iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
		"(sysctl -w net.ipv4.conf.all.rp_filter=2 2>/dev/null || true) && (sysctl -w net.ipv4.conf.awg0.rp_filter=2 2>/dev/null || true)",
	}

	var groupedRules []string
	for _, rule := range rules {
		groupedRules = append(groupedRules, fmt.Sprintf("( %s )", rule))
	}
	compoundCmd := fmt.Sprintf("docker exec %s bash -c %s", ssh.EscapeShellArg(cName), ssh.EscapeShellArg(strings.Join(groupedRules, " && ")))
	out, errOut, code, err := client.RunSudoCommand(ctx, compoundCmd)
	if err != nil {
		// #nosec G706 -- Internal log for container routing/NAT rule application failure
		log.Printf("[awg/nat] failed to apply backend routing/NAT rule in container %s: %v", cName, err)
		return fmt.Errorf("failed to apply backend routing/NAT rule in container %s: %w", cName, err)
	}
	if code != 0 {
		errMsg := strings.TrimSpace(errOut)
		if errMsg == "" {
			errMsg = strings.TrimSpace(out)
		}
		// #nosec G706 -- Internal log for container routing/NAT rule application failure
		log.Printf("[awg/nat] failed to apply backend routing/NAT rule in container %s (code %d): %s", cName, code, errMsg)
		return fmt.Errorf("failed to apply backend routing/NAT rule in container %s (code %d): %s", cName, code, errMsg)
	}

	// Host-level defense-in-depth:
	bridgeDev := "amn0"
	if out, _, code, err := client.RunSudoCommand(ctx, "ip link show amn0 2>/dev/null || ip link show docker0 2>/dev/null || true"); err == nil && code == 0 {
		if strings.Contains(out, "docker0") && !strings.Contains(out, "amn0") {
			bridgeDev = "docker0"
		}
	}
	hostRule := fmt.Sprintf("iptables -t nat -C POSTROUTING -s %s ! -o %s -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s %s ! -o %s -j MASQUERADE 2>/dev/null || true", ssh.EscapeShellArg(subnet), ssh.EscapeShellArg(bridgeDev), ssh.EscapeShellArg(subnet), ssh.EscapeShellArg(bridgeDev))
	_, errOut, code, err = client.RunSudoCommand(ctx, hostRule)
	if err != nil {
		return fmt.Errorf("failed to apply host-level NAT defense rule: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("failed to apply host-level NAT defense rule (code %d): %s", code, errOut)
	}

	hostMangleRule := "iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true"
	_, _, _, _ = client.RunSudoCommand(ctx, hostMangleRule)

	return nil
}

// EnsureBackendRoutingAndNAT resolves the server's SSH client and applies return routes,
// NAT masquerade, and reverse path filtering for the portal subnet inside the container.
func (m *AWGManager) EnsureBackendRoutingAndNAT(ctx context.Context, server *models.Server, subnet string) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return fmt.Errorf("failed to get SSH client for server %d: %w", server.ID, err)
	}
	return m.ensureBackendRoutingAndNAT(ctx, client, subnet)
}

// ensureBackendNATRule is a backward-compatible wrapper calling ensureBackendRoutingAndNAT with default subnet.
func (m *AWGManager) ensureBackendNATRule(ctx context.Context, client ssh.SSHClient) error {
	return m.ensureBackendRoutingAndNAT(ctx, client, "")
}
