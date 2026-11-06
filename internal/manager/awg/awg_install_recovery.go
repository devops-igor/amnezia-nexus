package awg

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func preserveAWGInstallation(params map[string]any) bool {
	for _, key := range []string{"preserve_containers", "reconcile", "preserve_identity"} {
		if enabled, _ := parseBoolParam(params[key]); enabled {
			return true
		}
	}
	return false
}

// recoverAWGInstallation runs before random parameter/key generation. The remote
// interface lock serializes it with peer/config changes, without holding m.mu
// during SSH I/O. Never infer "fresh" from an unsuccessful inspect or read.
func (m *AWGManager) recoverAWGInstallation(ctx context.Context, client ssh.SSHClient, server *models.Server) (bool, error) {
	out, _, code, err := client.RunSudoCommand(ctx, "docker ps -a --filter name=amnezia-awg --format '{{.Names}}'")
	if err != nil || code != 0 {
		return false, errors.New("cannot determine existing AWG installations")
	}
	names := strings.Fields(out)
	if len(names) == 0 {
		if _, exists := server.Protocols["awg"]; exists {
			return false, errors.New("existing AWG metadata but no container; refusing identity replacement")
		}
		// A missing container is fresh only with no durable identity evidence.
		// Host-side remnants can outlive an interrupted/deleted container.
		remnants, _, code, err := client.RunSudoCommand(ctx, "if [ -d /opt/amnezia ]; then find /opt/amnezia -type f \\( -name '*wg0.conf' -o -name 'wireguard_server_private_key.key' \\) -print; fi")
		if err != nil || code != 0 || strings.TrimSpace(remnants) != "" {
			return false, errors.New("cannot establish a fresh AWG installation; refusing identity replacement")
		}
		return false, nil
	}
	if len(names) != 1 || !IsValidContainerName(names[0]) || !strings.HasPrefix(names[0], "amnezia-awg") {
		return false, errors.New("ambiguous AWG container selection")
	}
	name := names[0]
	state, _, code, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker inspect -f '{{.State.Status}}' %s", ssh.EscapeShellArg(name)))
	if err != nil || code != 0 {
		return false, errors.New("cannot inspect existing AWG container")
	}
	switch strings.TrimSpace(state) {
	case "running", "exited", "created":
	default:
		return false, errors.New("existing AWG container is not in a recoverable state")
	}
	conf, err := m.readInstalledAWGConfig(ctx, client, name)
	if err != nil {
		return false, err
	}
	pub, params, err := installedAWGMetadata(conf)
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(state) != "running" {
		if _, _, code, err := client.RunSudoCommand(ctx, "docker start "+ssh.EscapeShellArg(name)); err != nil || code != 0 {
			return false, errors.New("failed to start existing AWG container")
		}
	}
	if err := m.verifyInstalledAWGRuntime(ctx, client, name, conf); err != nil {
		return false, err
	}
	// Replace only AWG metadata, so stale optional fields (e.g. a prior HP key)
	// cannot survive when the actual saved installation uses AWG 2.x semantics.
	delete(server.Protocols, "awg")
	populateAWGServerProtocols(server, pub, params.Port, params)
	m.setCachedContainerForClient(client, name)
	return true, nil
}

// docker cp works for stopped containers too. Read the tar stream on the host;
// pipefail prevents a failed copy from masquerading as a successful empty read.
// No secret-bearing temporary file or config upload is needed.
func (m *AWGManager) readInstalledAWGConfig(ctx context.Context, client ssh.SSHClient, name string) (string, error) {
	script := fmt.Sprintf("set -o pipefail; docker cp %s:%s - | tar -xOf -", ssh.EscapeShellArg(name), ssh.EscapeShellArg(m.configPath()))
	out, _, code, err := client.RunSudoCommand(ctx, "bash -c "+ssh.EscapeShellArg(script))
	if err != nil || code != 0 || strings.TrimSpace(out) == "" {
		return "", errors.New("cannot read saved AWG configuration; refusing to replace it")
	}
	return out, nil
}

// Parse into a zero-valued AWGParams, not AWGParamsFromMap's new-install
// defaults: absent S3/S4 or HP options must remain absent on legacy retries.
func installedAWGMetadata(conf string) (string, *AWGParams, error) {
	if _, err := installedAWGSections(conf); err != nil {
		return "", nil, err
	}
	pub, err := ExtractServerPublicKey(conf)
	if err != nil {
		return "", nil, errors.New("invalid saved AWG server identity")
	}
	values, _, _ := ParseServerConfig(conf)
	port, err := strconv.ParseUint(values["port"], 10, 16)
	if err != nil || port == 0 {
		return "", nil, errors.New("invalid saved AWG listen port")
	}
	valuesAny := make(map[string]any)
	for key, value := range (&AWGParams{}).ToMap() {
		valuesAny[key] = value
	}
	for key, value := range values {
		valuesAny[key] = value
	}
	return pub, AWGParamsFromMap(valuesAny), nil
}

// Preserve disk and live runtime independently; never sync/restart a running
// interface to "repair" divergence, since that could silently remove live peers.
func (m *AWGManager) verifyInstalledAWGRuntime(ctx context.Context, client ssh.SSHClient, name, saved string) error {
	cmd := fmt.Sprintf("docker exec %s awg showconf awg0", ssh.EscapeShellArg(name))
	live, _, code, err := client.RunSudoCommand(ctx, cmd)
	if err != nil || code != 0 {
		return errors.New("cannot verify existing AWG runtime")
	}
	diskSections, err := installedAWGSections(saved)
	if err != nil {
		return err
	}
	liveSections, err := installedAWGSections(live)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(diskSections, liveSections) {
		return errors.New("saved and live AWG state differ; refusing destructive retry")
	}
	return nil
}

// Compare stable wg/awg fields only: awg-quick-only directives aren't returned
// by showconf, while learned endpoints/keepalives must not require rewriting disk.
func installedAWGSections(conf string) (map[string]map[string]string, error) {
	result := make(map[string]map[string]string)
	section := ""
	fields := map[string]string{}
	for _, raw := range strings.Split(conf, "\n") {
		line := strings.TrimSpace(stripComment(raw))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if err := addInstalledAWGSection(result, section, fields); err != nil {
				return nil, err
			}
			section = strings.ToLower(line)
			if section != "[interface]" && section != "[peer]" {
				return nil, errors.New("unknown saved AWG section")
			}
			fields = make(map[string]string)
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if !ok || section == "" {
			return nil, errors.New("malformed saved AWG configuration")
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, errors.New("duplicate saved AWG directive")
		}
		fields[key] = strings.TrimSpace(val)
	}
	if err := addInstalledAWGSection(result, section, fields); err != nil {
		return nil, err
	}
	if result["[interface]"] == nil {
		return nil, errors.New("missing saved AWG interface")
	}
	return result, nil
}

func addInstalledAWGSection(result map[string]map[string]string, section string, fields map[string]string) error {
	if section == "" {
		return nil
	}
	id := "[interface]"
	keep := "privatekey listenport jc jmin jmax s1 s2 s3 s4 h1 h2 h3 h4 headerprotectionkey randomtrailers disablecookies"
	keyField := "privatekey"
	if section == "[peer]" {
		keyField = "publickey"
		id = fields[keyField]
		keep = "publickey presharedkey allowedips"
		if fields["allowedips"] == "" {
			return errors.New("missing saved AWG peer addresses")
		}
	}
	if !validInstalledAWGKey(fields[keyField]) {
		return errors.New("invalid saved AWG key")
	}
	if psk := fields["presharedkey"]; psk != "" && !validInstalledAWGKey(psk) {
		return errors.New("invalid saved AWG peer PSK")
	}
	if result[id] != nil {
		return errors.New("duplicate saved AWG section")
	}
	stable := make(map[string]string)
	for _, key := range strings.Fields(keep) {
		if val, ok := fields[key]; ok {
			stable[key] = val
		}
	}
	if section == "[interface]" {
		// Scalar clamping by the live implementation can change the private
		// key's encoding without changing its public identity.
		pub, err := derivePublicKeyFromPrivate(stable["privatekey"])
		if err != nil {
			return errors.New("invalid saved AWG identity")
		}
		stable["privatekey"] = pub
	}
	result[id] = stable
	return nil
}

func validInstalledAWGKey(key string) bool {
	decoded, err := base64.StdEncoding.Strict().DecodeString(key)
	return err == nil && len(decoded) == 32
}
