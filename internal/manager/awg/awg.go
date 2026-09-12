package awg

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg/cps"
	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg/tc"
	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/ssh"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
	"golang.org/x/crypto/curve25519"
)

var (
	AWGContainerNames  = []string{"amnezia-awg2", "amnezia-awg", "amnezia-awg-legacy"}
	containerNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
)

const defaultContainerCacheTTL = 5 * time.Minute

// IsValidContainerName validates a container name against strict regex:
// must start with an alphanumeric character, followed by alphanumeric, dot, underscore, or hyphen.
func IsValidContainerName(name string) bool {
	return containerNameRegex.MatchString(name)
}

type containerCacheEntry struct {
	name      string
	expiresAt time.Time
}

// SSHProvider abstracts obtaining an SSHClient for a server.
type SSHProvider interface {
	Get(ctx context.Context, server *models.Server) (ssh.SSHClient, error)
}

// AWGManager implements manager.ProtocolManager for AmneziaWG.
//
//nolint:revive
type AWGManager struct {
	sshPool        SSHProvider
	mu             sync.Mutex
	cacheMu        sync.RWMutex
	containerCache map[string]containerCacheEntry
}

// NewAWGManager creates a new AWGManager instance.
func NewAWGManager(pool SSHProvider) *AWGManager {
	return &AWGManager{
		sshPool:        pool,
		containerCache: make(map[string]containerCacheEntry),
	}
}

func (m *AWGManager) getCachedContainer(key string) (string, bool) {
	if key == "" {
		return "", false
	}
	m.cacheMu.RLock()
	defer m.cacheMu.RUnlock()
	if m.containerCache == nil {
		return "", false
	}
	entry, ok := m.containerCache[key]
	if !ok {
		return "", false
	}
	if time.Now().After(entry.expiresAt) {
		return "", false
	}
	if !IsValidContainerName(entry.name) {
		return "", false
	}
	return entry.name, true
}

func (m *AWGManager) setCachedContainer(key string, name string) {
	if key == "" || !IsValidContainerName(name) {
		return
	}
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	if m.containerCache == nil {
		m.containerCache = make(map[string]containerCacheEntry)
	}
	m.containerCache[key] = containerCacheEntry{
		name:      name,
		expiresAt: time.Now().Add(defaultContainerCacheTTL),
	}
}

func (m *AWGManager) getCachedContainerForClient(client ssh.SSHClient) (string, bool) {
	if client == nil {
		return "", false
	}
	if id := client.GetServerID(); id != nil && *id != 0 {
		if val, ok := m.getCachedContainer(fmt.Sprintf("id:%d", *id)); ok {
			return val, true
		}
	}
	if host := client.GetHost(); host != "" {
		if val, ok := m.getCachedContainer(fmt.Sprintf("host:%s:%d", host, client.GetPort())); ok {
			return val, true
		}
		if val, ok := m.getCachedContainer(fmt.Sprintf("host:%s", host)); ok {
			return val, true
		}
	}
	return "", false
}

func (m *AWGManager) setCachedContainerForClient(client ssh.SSHClient, name string) {
	if client == nil || !IsValidContainerName(name) {
		return
	}
	if id := client.GetServerID(); id != nil && *id != 0 {
		m.setCachedContainer(fmt.Sprintf("id:%d", *id), name)
	}
	if host := client.GetHost(); host != "" {
		m.setCachedContainer(fmt.Sprintf("host:%s:%d", host, client.GetPort()), name)
		m.setCachedContainer(fmt.Sprintf("host:%s", host), name)
	}
}

func (m *AWGManager) setCachedContainerForServer(server *models.Server, name string) {
	if server == nil || !IsValidContainerName(name) {
		return
	}
	if server.ID != 0 {
		m.setCachedContainer(fmt.Sprintf("id:%d", server.ID), name)
	}
	if server.Host != "" {
		port := server.SSHPort
		if port == 0 {
			port = 22
		}
		m.setCachedContainer(fmt.Sprintf("host:%s:%d", server.Host, port), name)
		m.setCachedContainer(fmt.Sprintf("host:%s", server.Host), name)
	}
}

func (m *AWGManager) invalidateContainerCache(server *models.Server) {
	if server == nil {
		return
	}
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	if m.containerCache == nil {
		return
	}
	if server.ID != 0 {
		delete(m.containerCache, fmt.Sprintf("id:%d", server.ID))
	}
	if server.Host != "" {
		port := server.SSHPort
		if port == 0 {
			port = 22
		}
		delete(m.containerCache, fmt.Sprintf("host:%s:%d", server.Host, port))
		delete(m.containerCache, fmt.Sprintf("host:%s", server.Host))
	}
}

func (m *AWGManager) Protocol() string {
	return "awg"
}

func (m *AWGManager) getSSHClient(ctx context.Context, server *models.Server) (ssh.SSHClient, error) {
	if server == nil {
		return nil, errors.New("server cannot be nil")
	}
	if m.sshPool == nil {
		return nil, errors.New("ssh pool is not configured")
	}
	return m.sshPool.Get(ctx, server)
}

func (m *AWGManager) containerName() string {
	return "amnezia-awg2"
}

func (m *AWGManager) configPath() string {
	return "/opt/amnezia/awg/awg0.conf"
}

func (m *AWGManager) clientsTablePath() string {
	return "/opt/amnezia/awg/clientsTable"
}

func (m *AWGManager) interfaceName() string {
	return "awg0"
}

func (m *AWGManager) wgBinary() string {
	return "awg"
}

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
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker stop %s 2>/dev/null || true", name))
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker rm -fv %s 2>/dev/null || true", name))
	}
	return nil
}

// awgBaseImage pins the AmneziaWG-Go userspace base image to the 3.1 release.
// Pinning (instead of :latest) guarantees freshly built backends speak the
// 3.x protocol; the explicit pull before build ensures the tag exists on the
// host instead of failing mid-build with a stale local cache.
const awgBaseImage = "amneziavpn/amneziawg-go:3.1.20260828"

func (m *AWGManager) buildAndRunAWGContainer(ctx context.Context, client ssh.SSHClient, port string) error {
	cName := m.containerName()
	if !IsValidContainerName(cName) {
		cName = "amnezia-awg2"
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

	if _, errOut, pCode, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker pull %s", awgBaseImage)); err != nil || pCode != 0 {
		return fmt.Errorf("failed to pull AWG base image %s (code %d): %s, %w", awgBaseImage, pCode, errOut, err)
	}

	if _, errOut, bCode, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker build --no-cache -t %s /opt/amnezia/%s", cName, cName)); err != nil || bCode != 0 {
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
%s`, port, port, cName, cName)

	if _, errOut, rCode, err := client.RunSudoCommand(ctx, runCmd); err != nil || rCode != 0 {
		return fmt.Errorf("failed to run container (code %d): %s, %w", rCode, errOut, err)
	}

	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker network connect amnezia-dns-net %s 2>/dev/null || true", cName))
	return nil
}

func buildAndRunAWGContainer(ctx context.Context, client ssh.SSHClient, port string) error {
	return (&AWGManager{}).buildAndRunAWGContainer(ctx, client, port)
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
echo "%s" > /opt/amnezia/awg/wireguard_server_private_key.key
echo "%s" > /opt/amnezia/awg/wireguard_server_public_key.key
echo "%s" > /opt/amnezia/awg/wireguard_psk.key
`, serverPrivKey, serverPubKey, serverPSK)
	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker exec -i %s bash -c '%s'", cName, keygenScript))

	serverConfig := RenderServerConfig(serverPrivKey, AWGDefaults["subnet_ip"], AWGDefaults["subnet_cidr"], port, awgParams.MTU, awgParams, nil)
	if err := client.UploadSudoFile(ctx, "/tmp/_amnz_awg0.conf", []byte(serverConfig), 0600); err != nil {
		return err
	}
	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker cp /tmp/_amnz_awg0.conf %s:/opt/amnezia/awg/awg0.conf", cName))
	_, _, _, _ = client.RunSudoCommand(ctx, "rm -f /tmp/_amnz_awg0.conf")

	startScript := `#!/bin/bash
awg-quick down /opt/amnezia/awg/awg0.conf 2>/dev/null || true
if [ -f /opt/amnezia/awg/awg0.conf ]; then awg-quick up /opt/amnezia/awg/awg0.conf; fi
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
iptables -t nat -C POSTROUTING -s 10.100.0.0/16 -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -I POSTROUTING 1 -s 10.100.0.0/16 -o eth0 -j MASQUERADE
iptables -t nat -C POSTROUTING -s 10.100.0.0/16 -o eth1 -j MASQUERADE 2>/dev/null || iptables -t nat -I POSTROUTING 1 -s 10.100.0.0/16 -o eth1 -j MASQUERADE 2>/dev/null || true
iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -C POSTROUTING -s 10.100.0.0/16 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.100.0.0/16 -j MASQUERADE
tail -f /dev/null
`

	if err := client.UploadSudoFile(ctx, "/tmp/_amnz_start.sh", []byte(startScript), 0755); err != nil {
		return err
	}
	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker cp /tmp/_amnz_start.sh %s:/opt/amnezia/start.sh", cName))
	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker exec %s chmod +x /opt/amnezia/start.sh", cName))
	_, _, _, _ = client.RunSudoCommand(ctx, "rm -f /tmp/_amnz_start.sh")
	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker restart %s", cName))

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

	if (profile == "standard" || profile == "pro") && params != nil {
		cpsProto := "quic"
		if cp, ok := params["awg_cps_protocol"]; ok && fmt.Sprint(cp) != "" {
			cpsProto = fmt.Sprint(cp)
		}
		if d, err := cps.SelectMimicryDomain(ctx, client, cpsProto); err == nil && d != "" {
			if cpsPackets, err := cps.GenerateCPSPackets(profile, d); err == nil {
				awgParams.I1 = cpsPackets["i1"]
				awgParams.I2 = cpsPackets["i2"]
				awgParams.I3 = cpsPackets["i3"]
				awgParams.I4 = cpsPackets["i4"]
				awgParams.I5 = cpsPackets["i5"]
			}
		}
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
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker stop %s 2>/dev/null || true", name))
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker rm -fv %s 2>/dev/null || true", name))
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker rmi %s 2>/dev/null || true", name))
	}
	_, _, _, _ = client.RunSudoCommand(ctx, "rm -rf /opt/amnezia/amnezia-awg /opt/amnezia/amnezia-awg2 /opt/amnezia/awg")
	return nil
}

func (m *AWGManager) resolveContainerName(ctx context.Context, client ssh.SSHClient) string {
	if cached, ok := m.getCachedContainerForClient(client); ok {
		return cached
	}

	for _, name := range AWGContainerNames {
		if !IsValidContainerName(name) {
			continue
		}
		out, _, code, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker ps --filter name=^%s$ --format '{{.Names}}'", name))
		if err == nil && code == 0 {
			for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed == name {
					m.setCachedContainerForClient(client, name)
					return name
				}
			}
		}
	}
	// Fallback to any running container with name starting with amnezia-awg
	out, _, code, err := client.RunSudoCommand(ctx, "docker ps --filter name=amnezia-awg --format '{{.Names}}'")
	if err == nil && code == 0 {
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "amnezia-awg") && IsValidContainerName(trimmed) {
				m.setCachedContainerForClient(client, trimmed)
				return trimmed
			}
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
		"sysctl -w net.ipv4.conf.all.rp_filter=2 2>/dev/null; sysctl -w net.ipv4.conf.awg0.rp_filter=2 2>/dev/null || true",
	}

	for _, rule := range rules {
		cmd := fmt.Sprintf("docker exec %s bash -c '%s'", cName, rule)
		_, errOut, code, err := client.RunSudoCommand(ctx, cmd)
		if err != nil {
			return fmt.Errorf("failed to apply backend routing/NAT rule in container %s: %w", cName, err)
		}
		if code != 0 {
			return fmt.Errorf("failed to apply backend routing/NAT rule in container %s (code %d): %s", cName, code, errOut)
		}
	}

	// Host-level defense-in-depth:
	bridgeDev := "amn0"
	if out, _, code, err := client.RunSudoCommand(ctx, "ip link show amn0 2>/dev/null || ip link show docker0 2>/dev/null || true"); err == nil && code == 0 {
		if strings.Contains(out, "docker0") && !strings.Contains(out, "amn0") {
			bridgeDev = "docker0"
		}
	}
	hostRule := fmt.Sprintf("iptables -t nat -C POSTROUTING -s %s ! -o %s -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s %s ! -o %s -j MASQUERADE 2>/dev/null || true", subnet, bridgeDev, subnet, bridgeDev)
	_, errOut, code, err := client.RunSudoCommand(ctx, hostRule)
	if err != nil {
		return fmt.Errorf("failed to apply host-level NAT defense rule: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("failed to apply host-level NAT defense rule (code %d): %s", code, errOut)
	}

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

func (m *AWGManager) getServerConfig(ctx context.Context, client ssh.SSHClient, containerNames ...string) (string, error) {
	names := containerNames
	if len(names) == 0 || (len(names) == 1 && names[0] == "") {
		resolved := m.resolveContainerName(ctx, client)
		if !IsValidContainerName(resolved) {
			resolved = m.containerName()
		}
		names = []string{resolved}
		for _, name := range AWGContainerNames {
			if name != resolved && IsValidContainerName(name) {
				names = append(names, name)
			}
		}
	}
	for _, name := range names {
		if !IsValidContainerName(name) {
			continue
		}
		cmd := fmt.Sprintf("docker exec -i %s cat %s 2>/dev/null || docker exec -i %s cat /etc/amnezia/amneziawg/awg0.conf 2>/dev/null", name, m.configPath(), name)
		out, _, code, err := client.RunSudoCommand(ctx, cmd)
		if err == nil && code == 0 && strings.TrimSpace(out) != "" {
			return out, nil
		}
	}
	return "", fmt.Errorf("failed to get server config from containers: %v", names)
}

func (m *AWGManager) resolveContainerConfigPath(ctx context.Context, client ssh.SSHClient, containerName string) string {
	candidates := []string{m.configPath(), "/etc/amnezia/amneziawg/awg0.conf"}
	for _, p := range candidates {
		cmd := fmt.Sprintf("docker exec -i %s test -f %s", containerName, p)
		_, _, code, err := client.RunSudoCommand(ctx, cmd)
		if err == nil && code == 0 {
			return p
		}
	}
	cmd := fmt.Sprintf("docker exec -i %s test -d /etc/amnezia/amneziawg", containerName)
	if _, _, code, err := client.RunSudoCommand(ctx, cmd); err == nil && code == 0 {
		return "/etc/amnezia/amneziawg/awg0.conf"
	}
	return m.configPath()
}

func (m *AWGManager) saveServerConfig(ctx context.Context, client ssh.SSHClient, content string) error {
	cName := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(cName) {
		cName = m.containerName()
	}
	if !IsValidContainerName(cName) {
		return errors.New("invalid container name")
	}
	tmpPath := "/tmp/_amnz_edit_config.conf"
	if err := client.UploadSudoFile(ctx, tmpPath, []byte(content), 0600); err != nil {
		return err
	}
	defer func() {
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("rm -f %s", tmpPath))
	}()

	cfgPath := m.resolveContainerConfigPath(ctx, client, cName)
	cpCmd := fmt.Sprintf("docker cp %s %s:%s", tmpPath, cName, cfgPath)
	if _, errOut, code, err := client.RunSudoCommand(ctx, cpCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to copy config into container (code %d): %s, %w", code, errOut, err)
	}

	syncCmd := fmt.Sprintf("docker exec -i %s bash -c '%s syncconf %s <(%s-quick strip %s)'",
		cName, m.wgBinary(), m.interfaceName(), m.wgBinary(), cfgPath)
	out, errOut, code, err := client.RunSudoCommand(ctx, syncCmd)
	if err != nil || code != 0 {
		errMsg := strings.TrimSpace(errOut)
		if errMsg == "" {
			errMsg = strings.TrimSpace(out)
		}
		if err != nil {
			return fmt.Errorf("failed to sync AmneziaWG config in container %s (exit code %d): %s: %w", cName, code, errMsg, err)
		}
		return fmt.Errorf("failed to sync AmneziaWG config in container %s (exit code %d): %s", cName, code, errMsg)
	}
	return nil
}

func (m *AWGManager) getClientsTable(ctx context.Context, client ssh.SSHClient) ([]AWGClient, error) {
	cName := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(cName) {
		cName = m.containerName()
	}
	if !IsValidContainerName(cName) {
		return []AWGClient{}, errors.New("invalid container name")
	}
	out, _, code, _ := client.RunSudoCommand(ctx, fmt.Sprintf("docker exec -i %s cat %s 2>/dev/null", cName, m.clientsTablePath()))
	if code != 0 || strings.TrimSpace(out) == "" {
		return []AWGClient{}, nil
	}
	return ParseClientsTable(out)
}

func (m *AWGManager) saveClientsTable(ctx context.Context, client ssh.SSHClient, clients []AWGClient) error {
	cName := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(cName) {
		cName = m.containerName()
	}
	if !IsValidContainerName(cName) {
		return errors.New("invalid container name")
	}
	jsonData, err := SerializeClientsTable(clients)
	if err != nil {
		return err
	}

	tmpPath := "/tmp/_amnz_clients.json"
	if err := client.UploadSudoFile(ctx, tmpPath, []byte(jsonData), 0600); err != nil {
		return err
	}
	defer func() {
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("rm -f %s", tmpPath))
	}()

	cpCmd := fmt.Sprintf("docker cp %s %s:%s", tmpPath, cName, m.clientsTablePath())
	if _, errOut, code, err := client.RunSudoCommand(ctx, cpCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to copy clientsTable into container (code %d): %s, %w", code, errOut, err)
	}
	return nil
}

// GetClients returns all registered clients from clientsTable enriched with live transfer data.
func (m *AWGManager) GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return nil, err
	}

	clients, err := m.getClientsTable(ctx, client)
	if err != nil {
		return nil, err
	}

	// Live transfer stats via awg show all
	cName := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(cName) {
		cName = m.containerName()
	}
	showOut, _, _, _ := client.RunSudoCommand(ctx, fmt.Sprintf("docker exec -i %s %s show all 2>/dev/null", cName, m.wgBinary()))
	showStats := parseWGShow(showOut)

	var result []map[string]any
	knownIDs := make(map[string]bool)

	for _, c := range clients {
		knownIDs[c.ClientID] = true
		ud := c.UserData

		if stat, ok := showStats[c.ClientID]; ok {
			ud.LatestHandshake = stat.LatestHandshake
			ud.DataReceived = stat.DataReceived
			ud.DataSent = stat.DataSent
			ud.DataReceivedBytes = stat.DataReceivedBytes
			ud.DataSentBytes = stat.DataSentBytes
			if stat.AllowedIPs != "" {
				ud.AllowedIPs = stat.AllowedIPs
			}
		}

		udMap := map[string]any{
			"clientName":        ud.ClientName,
			"creationDate":      ud.CreationDate,
			"clientPrivateKey":  ud.ClientPrivateKey,
			"clientIp":          ud.ClientIP,
			"psk":               ud.PSK,
			"enabled":           ud.Enabled,
			"awg_mimicry":       ud.AWGMimicry,
			"speed_limit_down":  ud.SpeedLimitDown,
			"speed_limit_up":    ud.SpeedLimitUp,
			"latestHandshake":   ud.LatestHandshake,
			"dataReceived":      ud.DataReceived,
			"dataSent":          ud.DataSent,
			"dataReceivedBytes": ud.DataReceivedBytes,
			"dataSentBytes":     ud.DataSentBytes,
			"allowedIps":        ud.AllowedIPs,
			"externalClient":    ud.ExternalClient,
			"rotated_at":        ud.RotatedAt,
		}

		result = append(result, map[string]any{
			"clientId": c.ClientID,
			"userData": udMap,
		})
	}

	// Pick up external peers in awg0.conf not in clientsTable
	if confText, err := m.getServerConfig(ctx, client); err == nil {
		_, peers, _ := ParseServerConfig(confText)
		for _, p := range peers {
			if !knownIDs[p.PublicKey] {
				stat := showStats[p.PublicKey]
				result = append(result, map[string]any{
					"clientId": p.PublicKey,
					"userData": map[string]any{
						"clientName":        fmt.Sprintf("External (%s)", p.AllowedIPs),
						"clientPrivateKey":  "",
						"externalClient":    true,
						"allowedIps":        p.AllowedIPs,
						"latestHandshake":   stat.LatestHandshake,
						"dataReceived":      stat.DataReceived,
						"dataSent":          stat.DataSent,
						"dataReceivedBytes": stat.DataReceivedBytes,
						"dataSentBytes":     stat.DataSentBytes,
					},
				})
			}
		}
	}

	return result, nil
}

type wgShowPeerStat struct {
	LatestHandshake   string
	DataReceived      string
	DataSent          string
	DataReceivedBytes int64
	DataSentBytes     int64
	AllowedIPs        string
}

func parseWGShow(out string) map[string]wgShowPeerStat {
	stats := make(map[string]wgShowPeerStat)
	var currentPeer string
	var currentStat wgShowPeerStat

	lines := strings.Split(out, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "peer:") {
			if currentPeer != "" {
				stats[currentPeer] = currentStat
			}
			currentPeer = strings.TrimSpace(strings.TrimPrefix(trimmed, "peer:"))
			currentStat = wgShowPeerStat{}
		} else if currentPeer != "" && strings.Contains(trimmed, ":") {
			parts := strings.SplitN(trimmed, ":", 2)
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			switch k {
			case "latest handshake":
				currentStat.LatestHandshake = v
			case "transfer":
				tfParts := strings.Split(v, ",")
				if len(tfParts) == 2 {
					rx := strings.TrimSpace(strings.TrimSuffix(tfParts[0], "received"))
					tx := strings.TrimSpace(strings.TrimSuffix(tfParts[1], "sent"))
					currentStat.DataReceived = rx
					currentStat.DataSent = tx
					currentStat.DataReceivedBytes = parseSizeHuman(rx)
					currentStat.DataSentBytes = parseSizeHuman(tx)
				}
			case "allowed ips":
				currentStat.AllowedIPs = v
			}
		}
	}
	if currentPeer != "" {
		stats[currentPeer] = currentStat
	}
	return stats
}

func parseSizeHuman(s string) int64 {
	parts := strings.Fields(s)
	if len(parts) != 2 {
		return 0
	}
	val, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return 0
	}
	mult := int64(1)
	switch strings.ToLower(parts[1]) {
	case "kib", "kb":
		mult = 1024
	case "mib", "mb":
		mult = 1024 * 1024
	case "gib", "gb":
		mult = 1024 * 1024 * 1024
	case "tib", "tb":
		mult = 1024 * 1024 * 1024 * 1024
	}
	return int64(val * float64(mult))
}

func resolveClientName(clientParams map[string]any) string {
	if n, ok := clientParams["name"]; ok && fmt.Sprint(n) != "" {
		return fmt.Sprint(n)
	}
	if n, ok := clientParams["clientName"]; ok && fmt.Sprint(n) != "" {
		return fmt.Sprint(n)
	}
	return "client"
}

func parseSpeedLimits(clientParams map[string]any) (*int, *int) {
	var speedDown, speedUp *int
	if v, ok := clientParams["awg_speed_limit_down"]; ok && v != nil {
		if val, err := strconv.Atoi(fmt.Sprint(v)); err == nil && val > 0 {
			speedDown = &val
		}
	}
	if v, ok := clientParams["awg_speed_limit_up"]; ok && v != nil {
		if val, err := strconv.Atoi(fmt.Sprint(v)); err == nil && val > 0 {
			speedUp = &val
		}
	}
	return speedDown, speedUp
}

// probePeerPubKey extracts a valid caller-supplied WireGuard public key from
// clientParams (checked keys: "public_key", then "client_public_key").
// A valid key is base64 that decodes to exactly 32 bytes. Returns "" when
// absent or invalid, in which case AddClient generates a keypair as usual.
func probePeerPubKey(clientParams map[string]any) string {
	for _, k := range []string{"public_key", "client_public_key"} {
		v, ok := clientParams[k]
		if !ok || v == nil {
			continue
		}
		s, isStr := v.(string)
		if !isStr || s == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(decoded) != 32 {
			continue
		}
		return s
	}
	return ""
}

// upsertPeerInConfig replaces the [Peer] section whose PublicKey matches
// peerSection's PublicKey, or appends the section when no such peer exists.
// [Peer] blocks whose PublicKey is listed in removePubKeys are dropped (stale
// identity that was re-keyed under the same client name). Duplicate blocks for
// the same PublicKey are collapsed. Non-peer content is preserved as-is.
func upsertPeerInConfig(confText, peerSection string, removePubKeys ...string) (string, error) {
	peerLines := strings.Split(strings.TrimSpace(peerSection), "\n")
	newPub := ""
	for _, line := range peerLines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "PublicKey = ") {
			newPub = strings.TrimSpace(strings.TrimPrefix(trimmed, "PublicKey = "))
			break
		}
	}
	if newPub == "" {
		return "", errors.New("peer section is missing a PublicKey line")
	}

	lines := strings.Split(strings.TrimRight(confText, "\n"), "\n")
	var out []string
	replaced := false
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "[Peer]" {
			out = append(out, lines[i])
			continue
		}
		// Collect the whole [Peer] block (up to the next section header).
		j := i + 1
		for j < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[j]), "[") {
			j++
		}
		block := lines[i:j]
		blockPub := ""
		for _, bl := range block {
			trimmed := strings.TrimSpace(bl)
			if strings.HasPrefix(trimmed, "PublicKey = ") {
				blockPub = strings.TrimSpace(strings.TrimPrefix(trimmed, "PublicKey = "))
				break
			}
		}
		stale := false
		for _, rk := range removePubKeys {
			if rk != "" && rk != newPub && rk == blockPub {
				stale = true
				break
			}
		}
		switch {
		case stale:
			// Drop the stale block entirely.
		case blockPub == newPub:
			if !replaced {
				out = append(out, peerLines...)
				replaced = true
			}
			// Duplicate legacy block for the same key: drop it.
		default:
			out = append(out, block...)
		}
		i = j - 1
	}
	if !replaced {
		// Blank separator line before the appended peer, mirroring the
		// formatting awg-quick conf files get from the portal.
		withSep := append([]string{""}, peerLines...)
		out = append(out, withSep...)
	}
	return strings.Join(out, "\n") + "\n", nil
}

// findExistingClient locates an existing clientsTable entry matching the peer
// identity: by client ID (public key) first, then by client name. Returns the
// entry index and its current client ID.
func findExistingClient(clients []AWGClient, clientPubKey, clientName string) (int, string) {
	for i := range clients {
		if clients[i].ClientID == clientPubKey || clients[i].UserData.ClientName == clientName {
			return i, clients[i].ClientID
		}
	}
	return -1, ""
}

// peerSectionFor renders the [Peer] section to append to the server config.
// Probe peers carry no PresharedKey line: the prober probes with psk="", so
// both sides must derive IKpsk2 keys with a zero PSK.
func peerSectionFor(isProbePeer bool, clientPubKey, psk, clientIP, allowedIPs string) string {
	if isProbePeer {
		if allowedIPs == "" {
			allowedIPs = clientIP + "/32"
		}
		return fmt.Sprintf("\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", clientPubKey, allowedIPs)
	}
	return fmt.Sprintf("\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n", clientPubKey, psk, clientIP)
}

// upsertClientEntry updates the clientsTable entry at existingIdx in place
// (keeping IP and identity fields), or appends a new entry when idx < 0.
func upsertClientEntry(clients []AWGClient, existingIdx int, clientPubKey, clientName, clientPrivKey, psk, clientIP, mimicry string, speedDown, speedUp *int, contentPadding bool) []AWGClient {
	if existingIdx >= 0 {
		clients[existingIdx].ClientID = clientPubKey
		clients[existingIdx].UserData.ClientName = clientName
		clients[existingIdx].UserData.ClientPrivateKey = clientPrivKey
		clients[existingIdx].UserData.PSK = psk
		clients[existingIdx].UserData.Enabled = true

		ud := &clients[existingIdx].UserData
		if ud.RekeyAfterTime == nil {
			ud.RekeyAfterTime = GenerateRekeyAfterTime()
		}
		if ud.RekeyTimeout == nil {
			ud.RekeyTimeout = GenerateRekeyTimeout()
		}
		if ud.RejectAfterTime == nil {
			ud.RejectAfterTime = GenerateRejectAfterTime()
		}
		if ud.KeepaliveTimeout == nil {
			ud.KeepaliveTimeout = GenerateKeepaliveTimeout()
		}
		if ud.MaxHandshakeAttempts == nil {
			ud.MaxHandshakeAttempts = GenerateMaxHandshakeAttempts()
		}
		if ud.PersistentKeepalive == nil {
			ud.PersistentKeepalive = GeneratePersistentKeepalive()
		}
		EnforceTimingOrdering(ud.RekeyTimeout, ud.RekeyAfterTime, ud.RejectAfterTime)

		if contentPadding && clients[existingIdx].UserData.ContentPaddingAddition == nil {
			val := "16-64"
			clients[existingIdx].UserData.ContentPaddingAddition = &val
		}

		return clients
	}

	rat, rt, rej, kt, mha, pk := GenerateClientTimingParams()
	var cpAdd *string
	if contentPadding {
		val := "16-64"
		cpAdd = &val
	}

	return append(clients, AWGClient{
		ClientID: clientPubKey,
		UserData: AWGClientUserData{
			ClientName:             clientName,
			ClientPrivateKey:       clientPrivKey,
			ClientIP:               clientIP,
			PSK:                    psk,
			Enabled:                true,
			AWGMimicry:             mimicry,
			SpeedLimitDown:         speedDown,
			SpeedLimitUp:           speedUp,
			RekeyAfterTime:         rat,
			RekeyTimeout:           rt,
			RejectAfterTime:        rej,
			KeepaliveTimeout:       kt,
			MaxHandshakeAttempts:   mha,
			PersistentKeepalive:    pk,
			ContentPaddingAddition: cpAdd,
		},
	})
}

// applyClientSpeedLimit applies TC speed limits when any limit is set.
func applyClientSpeedLimit(ctx context.Context, client ssh.SSHClient, containerName, interfaceName, clientIP string, speedDown, speedUp *int) {
	if speedDown == nil && speedUp == nil {
		return
	}
	dVal, uVal := 0, 0
	if speedDown != nil {
		dVal = *speedDown
	}
	if speedUp != nil {
		uVal = *speedUp
	}
	_ = tc.ApplySpeedLimit(ctx, client, containerName, interfaceName, clientIP, dVal, uVal)
}

// AddClient provisions a new client/peer in the AWG configuration.
//
// If clientParams carries a valid caller-supplied public key ("public_key" or
// "client_public_key"), that key is registered as the peer identity and no
// keypair is generated (probe peers: the prober signs with the key the portal
// already holds, so no client private key is stored or returned). Probe peers
// are registered WITHOUT a PresharedKey because the prober derives Noise keys
// with an empty PSK; a registered PSK would break the IKpsk2 key derivation.
// Registration is idempotent: an existing clientsTable entry for the same
// identity (by client ID or client name) is updated in place, keeping its IP,
// instead of appending a duplicate [Peer], which amneziawg rejects.
func (m *AWGManager) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	clientName := resolveClientName(clientParams)

	// Name-based probe detection (R2): a legacy "Health Probe" entry may exist
	// with a server PSK from the old name-only registration path. Treat the
	// name as probe identity so the upsert drops the PresharedKey line and
	// forces psk="" — keeping the peer on the PSK-less identity both probers use.
	clientNameIsProbe := strings.EqualFold(strings.TrimSpace(clientName), "Health Probe")

	clientPubKey := probePeerPubKey(clientParams)
	isProbePeer := clientPubKey != "" || clientNameIsProbe
	clientPrivKey, clientPubKey, err := resolveClientKeys(clientParams)
	if err != nil {
		return nil, err
	}

	// Read server config
	confText, err := m.getServerConfig(ctx, client)
	if err != nil {
		return nil, err
	}

	usedIPs := GetUsedIPsFromConfig(confText)
	serverParams, _, _ := ParseServerConfig(confText)
	serverPubKey, err := m.GetServerPublicKey(ctx, server)
	if err != nil || serverPubKey == "" {
		if err != nil {
			return nil, fmt.Errorf("failed to get AmneziaWG server public key: %w", err)
		}
		return nil, errors.New("AmneziaWG server public key is empty")
	}

	// Idempotency: reuse the existing entry (and its IP) when this identity is
	// already registered instead of appending a duplicate peer.
	clients, _ := m.getClientsTable(ctx, client)
	existingIdx, existingPubKey := findExistingClient(clients, clientPubKey, clientName)

	clientIP, err := resolveClientIP(clients, existingIdx, usedIPs)
	if err != nil {
		return nil, err
	}

	// Normal clients get the server's PresharedKey (read fresh each call, as
	// before). Probe peers force psk="": the prober derives IKpsk2 keys with an
	// empty PSK, so the peer must be registered without one (R2).
	var psk string
	if !isProbePeer {
		psk, _ = m.GetServerPSK(ctx, server)
	}

	allowedIPs := ""
	if aip, ok := clientParams["allowed_ips"]; ok && aip != nil {
		allowedIPs = fmt.Sprint(aip)
	}
	peerSection := peerSectionFor(isProbePeer, clientPubKey, psk, clientIP, allowedIPs)
	var removePubKeys []string
	if existingPubKey != "" && existingPubKey != clientPubKey {
		removePubKeys = []string{existingPubKey}
	}
	newConfig, err := upsertPeerInConfig(confText, peerSection, removePubKeys...)
	if err != nil {
		return nil, err
	}
	if err := m.saveServerConfig(ctx, client, newConfig); err != nil {
		return nil, err
	}

	// Parse speed limits if provided
	speedDown, speedUp := parseSpeedLimits(clientParams)

	mimicry := "auto"
	if v, ok := clientParams["awg_mimicry"]; ok && fmt.Sprint(v) != "" {
		mimicry = fmt.Sprint(v)
	}

	cpOn, _ := parseBoolParam(clientParams["awg_content_padding"])

	// Save to clientsTable (update in place when the identity already exists)
	clients = upsertClientEntry(clients, existingIdx, clientPubKey, clientName, clientPrivKey, psk, clientIP, mimicry, speedDown, speedUp, cpOn)
	_ = m.saveClientsTable(ctx, client, clients)

	// Live remediation (issues #27, #36): ensure the return route, NAT masquerade,
	// and FORWARD rules exist so portal data-plane traffic (non-local source
	// subnets like 10.100.0.0/16) is forwarded and masqueraded. This covers
	// backends provisioned with the old subnet-scoped start.sh without
	// restarting or re-creating the container. Fail loudly: without the rules,
	// all load-balanced client traffic is dropped upstream.
	if err := m.ensureBackendNATRule(ctx, client); err != nil {
		return nil, fmt.Errorf("failed to ensure backend NAT rules: %w", err)
	}

	if isProbePeer {
		// Probe peers need no client config, connection kit, or TC limits:
		// nothing consumes a private key that does not exist.
		return map[string]any{
			"client_id":   clientPubKey,
			"client_name": clientName,
			"client_ip":   clientIP,
		}, nil
	}

	// Apply speed limit via TC
	applyClientSpeedLimit(ctx, client, m.resolveContainerName(ctx, client), m.interfaceName(), clientIP, speedDown, speedUp)

	// Render client config and connection kit
	clientConfig, connectionKit := m.buildClientConfig(ctx, client, server, serverParams, clientPrivKey, clientIP, serverPubKey, psk, mimicry, clientPubKey, clients)

	return map[string]any{
		"client_id":      clientPubKey,
		"client_name":    clientName,
		"client_ip":      clientIP,
		"config":         clientConfig,
		"connection_kit": connectionKit,
		"awg_mimicry":    mimicry,
	}, nil
}

func resolveClientKeys(clientParams map[string]any) (string, string, error) {
	clientPubKey := probePeerPubKey(clientParams)
	if clientPubKey != "" {
		return "", clientPubKey, nil
	}
	clientPrivKey, clientPubKey, err := GenerateWGKeypair()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate client keypair: %w", err)
	}
	return clientPrivKey, clientPubKey, nil
}

func resolveClientIP(clients []AWGClient, existingIdx int, usedIPs []string) (string, error) {
	if existingIdx >= 0 && clients[existingIdx].UserData.ClientIP != "" {
		return clients[existingIdx].UserData.ClientIP, nil
	}
	subnetAddr := AWGDefaults["subnet_address"]
	subnetCIDR, _ := strconv.Atoi(AWGDefaults["subnet_cidr"])
	gatewayIP := AWGDefaults["subnet_ip"]
	return GetNextIP(usedIPs, subnetAddr, subnetCIDR, gatewayIP)
}

func (m *AWGManager) buildClientConfig(ctx context.Context, client ssh.SSHClient, server *models.Server, serverParams map[string]string, clientPrivKey, clientIP, serverPubKey, psk, mimicry, clientPubKey string, clients []AWGClient) (string, map[string]string) {
	parsedParams := AWGParamsFromMap(convertStringMapToAny(serverParams))
	if mimicry != "" {
		if mp, err := cps.GenerateMimicryPackets(ctx, mimicry, "", client); err == nil {
			parsedParams.I1 = mp["i1"]
			parsedParams.I2 = mp["i2"]
			parsedParams.I3 = mp["i3"]
			parsedParams.I4 = mp["i4"]
			parsedParams.I5 = mp["i5"]
		}
	}

	port := serverParams["port"]
	if port == "" {
		port = AWGDefaults["port"]
	}
	endpoint := fmt.Sprintf("%s:%s", server.Host, port)
	var ud *AWGClientUserData
	for i := range clients {
		if clients[i].ClientID == clientPubKey {
			ud = &clients[i].UserData
			break
		}
	}
	clientConfig := RenderClientConfig(clientPrivKey, clientIP, serverPubKey, psk, endpoint, AWGDefaults["dns1"], AWGDefaults["dns2"], parsedParams.MTU, parsedParams, ud)
	connectionKit, _ := cps.GenerateConnectionKit(ctx, clientConfig, "", client)
	return clientConfig, connectionKit
}

func convertStringMapToAny(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// RemoveClient removes a client from the server WireGuard configuration and clientsTable.
func (m *AWGManager) RemoveClient(ctx context.Context, server *models.Server, clientID string) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. Remove TC speed limit for peer IP
	cName := m.resolveContainerName(ctx, client)
	clients, _ := m.getClientsTable(ctx, client)
	for _, c := range clients {
		if c.ClientID == clientID && c.UserData.ClientIP != "" {
			_ = tc.RemoveSpeedLimit(ctx, client, cName, m.interfaceName(), c.UserData.ClientIP)
			break
		}
	}

	// 2. Remove [Peer] section from config
	confText, err := m.getServerConfig(ctx, client)
	if err != nil {
		return err
	}

	sections := strings.Split(confText, "[")
	var newSections []string
	for _, sec := range sections {
		if strings.TrimSpace(sec) == "" {
			continue
		}
		if strings.Contains(sec, clientID) {
			continue
		}
		newSections = append(newSections, sec)
	}

	newConfig := "[" + strings.Join(newSections, "[")
	if err := m.saveServerConfig(ctx, client, newConfig); err != nil {
		return err
	}

	// 3. Update clientsTable
	var updatedClients []AWGClient
	for _, c := range clients {
		if c.ClientID != clientID {
			updatedClients = append(updatedClients, c)
		}
	}
	return m.saveClientsTable(ctx, client, updatedClients)
}

// GetClientConfig reconstructs the client config file for an existing client ID.
func (m *AWGManager) GetClientConfig(ctx context.Context, server *models.Server, clientID string) (string, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return "", err
	}

	clients, err := m.getClientsTable(ctx, client)
	if err != nil {
		return "", err
	}

	var targetClient *AWGClient
	for _, c := range clients {
		if c.ClientID == clientID {
			targetClient = &c
			break
		}
	}
	if targetClient == nil {
		return "", fmt.Errorf("client %s not found in clients table", clientID)
	}

	ud := targetClient.UserData
	if ud.ClientPrivateKey == "" {
		return "", errors.New("client private key not stored; config cannot be reconstructed")
	}

	confText, err := m.getServerConfig(ctx, client)
	if err != nil {
		return "", err
	}

	serverParams, _, _ := ParseServerConfig(confText)
	serverPubKey, err := m.GetServerPublicKey(ctx, server)
	if err != nil || serverPubKey == "" {
		if err != nil {
			return "", fmt.Errorf("failed to get AmneziaWG server public key: %w", err)
		}
		return "", errors.New("AmneziaWG server public key is empty")
	}

	psk := ud.PSK
	if psk == "" {
		psk, _ = m.GetServerPSK(ctx, server)
	}

	parsedParams := AWGParamsFromMap(convertStringMapToAny(serverParams))
	if ud.AWGMimicry != "" {
		if mp, err := cps.GenerateMimicryPackets(ctx, ud.AWGMimicry, "", client); err == nil {
			parsedParams.I1 = mp["i1"]
			parsedParams.I2 = mp["i2"]
			parsedParams.I3 = mp["i3"]
			parsedParams.I4 = mp["i4"]
			parsedParams.I5 = mp["i5"]
		}
	}

	port := serverParams["port"]
	if port == "" {
		port = AWGDefaults["port"]
	}
	endpoint := fmt.Sprintf("%s:%s", server.Host, port)

	return RenderClientConfig(ud.ClientPrivateKey, ud.ClientIP, serverPubKey, psk, endpoint, AWGDefaults["dns1"], AWGDefaults["dns2"], parsedParams.MTU, parsedParams, &ud), nil
}

// ToggleClient enables or disables a client by adding or removing the [Peer] from the server config.
func (m *AWGManager) ToggleClient(ctx context.Context, server *models.Server, clientID string, enable bool) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	clients, err := m.getClientsTable(ctx, client)
	if err != nil {
		return err
	}

	var target *AWGClient
	for i := range clients {
		if clients[i].ClientID == clientID {
			target = &clients[i]
			clients[i].UserData.Enabled = enable
			break
		}
	}
	if target == nil {
		return fmt.Errorf("client %s not found", clientID)
	}

	confText, err := m.getServerConfig(ctx, client)
	if err != nil {
		return err
	}

	var newConfig string
	if enable {
		psk := target.UserData.PSK
		peerSec := fmt.Sprintf("\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n", clientID, psk, target.UserData.ClientIP)
		newConfig = strings.TrimRight(confText, "\n") + "\n" + peerSec
	} else {
		sections := strings.Split(confText, "[")
		var newSections []string
		for _, sec := range sections {
			if strings.TrimSpace(sec) == "" || strings.Contains(sec, clientID) {
				continue
			}
			newSections = append(newSections, sec)
		}
		newConfig = "[" + strings.Join(newSections, "[")
	}

	if err := m.saveServerConfig(ctx, client, newConfig); err != nil {
		return err
	}
	return m.saveClientsTable(ctx, client, clients)
}

// findExistingContainer checks known container names for existence.
func (m *AWGManager) findExistingContainer(ctx context.Context, client ssh.SSHClient) (string, bool, error) {
	for _, name := range AWGContainerNames {
		if !IsValidContainerName(name) {
			continue
		}
		outAll, errOutAll, codeAll, errAll := client.RunSudoCommand(ctx, fmt.Sprintf("docker ps -a --filter name=^%s$ --format '{{.Names}}'", name))
		if errAll != nil || codeAll != 0 {
			return "", false, fmt.Errorf("docker ps -a failed checking %s (code %d): %s, %w", name, codeAll, errOutAll, errAll)
		}
		for _, line := range strings.Split(strings.TrimSpace(outAll), "\n") {
			if strings.TrimSpace(line) == name {
				return name, true, nil
			}
		}
	}
	return "", false, nil
}

// enrichRunningServerStatus populates configuration and credential details for a running container.
func (m *AWGManager) enrichRunningServerStatus(ctx context.Context, server *models.Server, client ssh.SSHClient, cName string, status map[string]any) {
	if conf, err := m.getServerConfig(ctx, client, cName); err == nil {
		params, peers, _ := ParseServerConfig(conf)
		status["port"] = params["port"]
		status["awg_params"] = params
		status["clients_count"] = len(peers)
		// Protocol generation is derived from the parsed backend config:
		// a non-empty HeaderProtectionKey means the backend speaks AWG 3.1.
		if params["header_protection_key"] != "" {
			status["protocol_generation"] = "3.1"
		} else {
			status["protocol_generation"] = "2.0"
		}
	}
	if !IsValidContainerName(cName) {
		cName = m.containerName()
	}
	// Best-effort AWG version lookup; empty string on any failure.
	if out, _, code, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker exec -i %s awg --version", cName)); err == nil && code == 0 {
		if line := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0]); line != "" {
			status["awg_version"] = line
		}
	}
	// If port is missing or 0, fallback extraction from docker port or docker inspect
	if p, ok := status["port"]; !ok || p == nil || fmt.Sprint(p) == "" || fmt.Sprint(p) == "0" {
		if port := m.extractContainerPort(ctx, client, cName); port > 0 {
			status["port"] = port
		}
	}
	if pubKey, err := m.GetServerPublicKey(ctx, server); err == nil && pubKey != "" {
		status["public_key"] = pubKey
	}
	if psk, err := m.GetServerPSK(ctx, server); err == nil && psk != "" {
		status["psk"] = psk
	}
}

// GetServerStatus returns whether the container is running and configuration details across all valid container names.
func (m *AWGManager) GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return nil, err
	}

	foundName, exists, err := m.findExistingContainer(ctx, client)
	if err != nil {
		return nil, err
	}

	var running bool
	if exists && foundName != "" && IsValidContainerName(foundName) {
		m.setCachedContainerForServer(server, foundName)
		m.setCachedContainerForClient(client, foundName)

		outRun, errOutRun, codeRun, errRun := client.RunSudoCommand(ctx, fmt.Sprintf("docker ps --filter name=^%s$ --format '{{.Status}}'", foundName))
		if errRun != nil || codeRun != 0 {
			return nil, fmt.Errorf("docker ps failed checking %s (code %d): %s, %w", foundName, codeRun, errOutRun, errRun)
		}
		running = strings.Contains(outRun, "Up")
	}

	status := map[string]any{
		"protocol":          "awg",
		"container_exists":  exists,
		"container_running": running,
	}

	if running {
		cName := foundName
		if cName == "" {
			cName = m.resolveContainerName(ctx, client)
		}
		if !IsValidContainerName(cName) {
			cName = m.containerName()
		}
		m.enrichRunningServerStatus(ctx, server, client, cName, status)
	}

	return status, nil
}

// extractContainerPort attempts to discover the host UDP listening port of the container
// via docker port and docker inspect.
func (m *AWGManager) extractContainerPort(ctx context.Context, client ssh.SSHClient, containerName string) int {
	if containerName == "" {
		containerName = m.resolveContainerName(ctx, client)
	}
	if !IsValidContainerName(containerName) {
		containerName = m.containerName()
	}
	if !IsValidContainerName(containerName) {
		return 0
	}
	out, _, code, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker port %s 2>/dev/null", containerName))
	if err == nil && code == 0 && strings.TrimSpace(out) != "" {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if idx := strings.LastIndex(line, ":"); idx != -1 {
				portStr := strings.TrimSpace(line[idx+1:])
				if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
					return p
				}
			}
		}
	}

	inspectCmd := fmt.Sprintf("docker inspect --format '{{range $p, $conf := .HostConfig.PortBindings}}{{(index $conf 0).HostPort}} {{end}}' %s 2>/dev/null", containerName)
	outInspect, _, codeInspect, errInspect := client.RunSudoCommand(ctx, inspectCmd)
	if errInspect == nil && codeInspect == 0 && strings.TrimSpace(outInspect) != "" {
		for _, part := range strings.Fields(outInspect) {
			if p, err := strconv.Atoi(part); err == nil && p > 0 {
				return p
			}
		}
	}
	return 0
}

// GetServerPublicKey returns the public key for AmneziaWG server.
func (m *AWGManager) GetServerPublicKey(ctx context.Context, server *models.Server) (string, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return "", err
	}

	resolved := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(resolved) {
		resolved = m.containerName()
	}
	names := []string{resolved}
	for _, name := range AWGContainerNames {
		if name != resolved && IsValidContainerName(name) {
			names = append(names, name)
		}
	}

	for _, name := range names {
		if !IsValidContainerName(name) {
			continue
		}
		cmd := fmt.Sprintf("docker exec -i %s cat /opt/amnezia/awg/wireguard_server_public_key.key 2>/dev/null || docker exec -i %s %s show awg0 public-key 2>/dev/null || docker exec -i %s wg show awg0 public-key 2>/dev/null", name, name, m.wgBinary(), name)
		out, _, code, err := client.RunSudoCommand(ctx, cmd)
		if err == nil && code == 0 && strings.TrimSpace(out) != "" {
			return strings.TrimSpace(out), nil
		}
	}

	// Also check if public key can be derived from PrivateKey in awg0.conf
	if conf, err := m.getServerConfig(ctx, client, names...); err == nil && conf != "" {
		for _, line := range strings.Split(conf, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(trimmed), "privatekey") {
				parts := strings.SplitN(trimmed, "=", 2)
				if len(parts) == 2 {
					privKeyBase64 := strings.TrimSpace(parts[1])
					if privBytes, err := base64.StdEncoding.DecodeString(privKeyBase64); err == nil && len(privBytes) == 32 {
						if pubBytes, err := curve25519.X25519(privBytes, curve25519.Basepoint); err == nil {
							return base64.StdEncoding.EncodeToString(pubBytes), nil
						}
					}
				}
			}
		}
	}

	return "", errors.New("failed to get AmneziaWG server public key")
}

// GetServerPSK returns the preshared key for AmneziaWG server.
func (m *AWGManager) GetServerPSK(ctx context.Context, server *models.Server) (string, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return "", err
	}

	resolved := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(resolved) {
		resolved = m.containerName()
	}
	names := []string{resolved}
	for _, name := range AWGContainerNames {
		if name != resolved && IsValidContainerName(name) {
			names = append(names, name)
		}
	}

	for _, name := range names {
		if !IsValidContainerName(name) {
			continue
		}
		cmd := fmt.Sprintf("docker exec -i %s cat /opt/amnezia/awg/wireguard_psk.key 2>/dev/null || docker exec -i %s cat /etc/amnezia/amneziawg/wireguard_psk.key 2>/dev/null", name, name)
		out, _, code, err := client.RunSudoCommand(ctx, cmd)
		if err == nil && code == 0 && strings.TrimSpace(out) != "" {
			return strings.TrimSpace(out), nil
		}
	}
	return "", nil
}

func parseParamString(params map[string]any, keys ...string) (string, bool) {
	for _, k := range keys {
		if v, ok := params[k]; ok && v != nil && fmt.Sprint(v) != "" {
			return fmt.Sprint(v), true
		}
	}
	return "", false
}

func parseBoolParam(val any) (bool, bool) {
	if val == nil {
		return false, false
	}
	switch v := val.(type) {
	case bool:
		return v, true
	case string:
		return strings.ToLower(v) == "true" || v == "1", true
	case int:
		return v != 0, true
	case int64:
		return v != 0, true
	case float64:
		return v != 0, true
	default:
		return false, false
	}
}

func parseSpeedLimit(params map[string]any, keys ...string) (*int, bool) {
	for _, k := range keys {
		if v, ok := params[k]; ok {
			if v == nil {
				return nil, true
			}
			if val, err := strconv.Atoi(fmt.Sprint(v)); err == nil && val > 0 {
				return &val, true
			}
			return nil, true
		}
	}
	return nil, false
}

// EditClient modifies client metadata, enabling/disabling, and bandwidth limits with TC sync.
func (m *AWGManager) EditClient(ctx context.Context, server *models.Server, clientID string, params map[string]any) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	clients, err := m.getClientsTable(ctx, client)
	if err != nil {
		return err
	}

	var target *AWGClient
	for i := range clients {
		if clients[i].ClientID == clientID {
			target = &clients[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("client %s not found in clients table", clientID)
	}

	if name, ok := parseParamString(params, "name", "clientName", "client_name"); ok {
		target.UserData.ClientName = name
	}
	if mimicry, ok := parseParamString(params, "awg_mimicry", "mimicry"); ok {
		target.UserData.AWGMimicry = mimicry
	}

	if newEnabled, ok := parseBoolParam(params["enabled"]); ok && newEnabled != target.UserData.Enabled {
		target.UserData.Enabled = newEnabled
		_ = m.updateServerConfigPeer(ctx, client, clientID, target.UserData.ClientIP, target.UserData.PSK, newEnabled)
	}

	down, downOk := parseSpeedLimit(params, "speed_limit_down", "awg_speed_limit_down", "speedDown")
	up, upOk := parseSpeedLimit(params, "speed_limit_up", "awg_speed_limit_up", "speedUp")
	if downOk || upOk {
		if downOk {
			target.UserData.SpeedLimitDown = down
		}
		if upOk {
			target.UserData.SpeedLimitUp = up
		}
		m.syncClientTC(ctx, client, target.UserData.ClientIP, target.UserData.SpeedLimitDown, target.UserData.SpeedLimitUp)
	}

	return m.saveClientsTable(ctx, client, clients)
}

func (m *AWGManager) updateServerConfigPeer(ctx context.Context, client ssh.SSHClient, clientID, clientIP, psk string, enable bool) error {
	confText, err := m.getServerConfig(ctx, client)
	if err != nil {
		return err
	}
	var newConfig string
	if enable {
		peerSec := fmt.Sprintf("\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n", clientID, psk, clientIP)
		newConfig = strings.TrimRight(confText, "\n") + "\n" + peerSec
	} else {
		sections := strings.Split(confText, "[")
		var newSections []string
		for _, sec := range sections {
			if strings.TrimSpace(sec) == "" || strings.Contains(sec, clientID) {
				continue
			}
			newSections = append(newSections, sec)
		}
		newConfig = "[" + strings.Join(newSections, "[")
	}
	return m.saveServerConfig(ctx, client, newConfig)
}

func (m *AWGManager) syncClientTC(ctx context.Context, client ssh.SSHClient, clientIP string, curDown, curUp *int) {
	cName := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(cName) {
		cName = m.containerName()
	}
	if (curDown != nil && *curDown > 0) || (curUp != nil && *curUp > 0) {
		dVal, uVal := 0, 0
		if curDown != nil {
			dVal = *curDown
		}
		if curUp != nil {
			uVal = *curUp
		}
		_ = tc.ApplySpeedLimit(ctx, client, cName, m.interfaceName(), clientIP, dVal, uVal)
	} else {
		_ = tc.RemoveSpeedLimit(ctx, client, cName, m.interfaceName(), clientIP)
	}
}

// RotateMimicry rotates a client's mimicry profile through the sequence:
// auto -> tls -> quic -> dns -> sip -> tls, regenerates I1-I5 packet headers, and updates clientsTable.
func (m *AWGManager) RotateMimicry(ctx context.Context, server *models.Server, clientID string) (string, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return "", err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	clients, err := m.getClientsTable(ctx, client)
	if err != nil {
		return "", err
	}

	var target *AWGClient
	for i := range clients {
		if clients[i].ClientID == clientID {
			target = &clients[i]
			break
		}
	}
	if target == nil {
		return "", fmt.Errorf("client %s not found in clients table", clientID)
	}

	curr := strings.ToLower(strings.TrimSpace(target.UserData.AWGMimicry))
	if curr == "" {
		curr = "auto"
	}

	var nextProfile string
	switch curr {
	case "auto":
		nextProfile = "tls"
	case "tls":
		nextProfile = "quic"
	case "quic":
		nextProfile = "dns"
	case "dns":
		nextProfile = "sip"
	case "sip":
		nextProfile = "tls"
	default:
		nextProfile = "tls"
	}

	// Regenerate I1-I5 signature packets
	if mp, err := cps.GenerateMimicryPackets(ctx, nextProfile, "", client); err == nil {
		target.UserData.I1 = mp["i1"]
		target.UserData.I2 = mp["i2"]
		target.UserData.I3 = mp["i3"]
		target.UserData.I4 = mp["i4"]
		target.UserData.I5 = mp["i5"]
	}

	target.UserData.AWGMimicry = nextProfile
	target.UserData.RotatedAt = time.Now().UTC().Format(time.RFC3339)

	if err := m.saveClientsTable(ctx, client, clients); err != nil {
		return "", fmt.Errorf("failed to save clients table after mimicry rotation: %w", err)
	}

	return nextProfile, nil
}
