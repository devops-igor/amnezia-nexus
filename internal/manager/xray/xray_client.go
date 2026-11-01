package xray

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/google/uuid"
)

type muxContextKeyType struct{}

var muxContextKey = muxContextKeyType{}

// WithMuxContext returns a new context with the mux setting explicitly specified.
func WithMuxContext(ctx context.Context, mux bool) context.Context {
	return context.WithValue(ctx, muxContextKey, mux)
}

func resolveMuxSetting(ctx context.Context, server *models.Server) bool {
	if ctx != nil {
		if val, ok := ctx.Value(muxContextKey).(bool); ok {
			return val
		}
	}
	if server == nil || server.Protocols == nil {
		return false
	}
	for _, key := range []string{models.ProtocolVLESS, "vless"} {
		vMeta, ok := server.Protocols[key].(map[string]any)
		if !ok {
			continue
		}
		if m, ok := vMeta["mux"].(bool); ok && m {
			return true
		}
		if m, ok := vMeta["mux"].(string); ok && strings.EqualFold(m, "true") {
			return true
		}
		if vo, ok := vMeta["vless_options"].(map[string]any); ok {
			if m, ok := vo["mux"].(bool); ok && m {
				return true
			}
			if m, ok := vo["mux"].(string); ok && strings.EqualFold(m, "true") {
				return true
			}
		}
	}
	return false
}

// SelectClientShortID deterministically selects a short ID from a pool for a given client ID.
// Non-empty short IDs are preferred to ensure unique client fingerprinting.
func SelectClientShortID(shortIDs []string, clientID string) string {
	var nonEmpty []string
	for _, sid := range shortIDs {
		if sid != "" {
			nonEmpty = append(nonEmpty, sid)
		}
	}
	if len(nonEmpty) == 0 {
		if len(shortIDs) > 0 {
			return shortIDs[0]
		}
		return ""
	}

	h := sha256.Sum256([]byte(clientID))
	val := binary.BigEndian.Uint32(h[:4]) & 0x7fffffff
	idx := int(val) % len(nonEmpty)
	return nonEmpty[idx]
}

func resolveClientName(clientID string, clientParams map[string]any) string {
	name := fmt.Sprintf("client-%s", clientID[:8])
	if n, ok := clientParams["name"].(string); ok && strings.TrimSpace(n) != "" {
		return strings.TrimSpace(n)
	}
	if email, ok := clientParams["email"].(string); ok && strings.TrimSpace(email) != "" {
		return strings.TrimSpace(email)
	}
	return name
}

func resolveClientFlow(server *models.Server, clientParams map[string]any) string {
	flow := "xtls-rprx-vision"
	if server != nil && server.Protocols != nil {
		if pMap, ok := server.Protocols[models.ProtocolVLESS].(map[string]any); ok {
			if f, ok := pMap["flow"].(string); ok {
				flow = strings.TrimSpace(f)
			}
		}
	}
	if f, ok := clientParams["flow"].(string); ok {
		flow = strings.TrimSpace(f)
	}
	if flow == "none" {
		return ""
	}
	return flow
}

func resolveClientEngineProfile(server *models.Server, clientParams map[string]any) string {
	if clientParams != nil {
		for _, k := range []string{"engine_profile", "profile"} {
			if p, ok := clientParams[k].(string); ok && strings.TrimSpace(p) != "" {
				return strings.TrimSpace(p)
			}
		}
	}
	if server != nil && server.Protocols != nil {
		if pMap, ok := server.Protocols[models.ProtocolVLESS].(map[string]any); ok {
			for _, k := range []string{"engine_profile", "profile", "engine_version"} {
				if p, ok := pMap[k].(string); ok && strings.TrimSpace(p) != "" {
					return strings.TrimSpace(p)
				}
			}
		}
	}
	return ""
}

// AddClient adds a new VLESS+REALITY client credential, uploads updated config, and restarts the container.
func (m *XrayManager) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return nil, err
	}

	unlock, err := m.lockServer(ctx, client, server.ID)
	if err != nil {
		return nil, err
	}
	defer unlock()

	// 1. Download existing config.json
	cfgBytes, err := client.DownloadSudoFile(ctx, XrayConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to download xray config: %w", err)
	}

	cfg, err := ParseXrayConfig(cfgBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse xray config: %w", err)
	}

	if len(cfg.Inbounds) == 0 {
		return nil, errors.New("invalid xray config: no inbounds defined")
	}

	// 2. Generate client identity
	clientID := uuid.NewString()
	now := time.Now().UTC()
	m.recordClientCreation(clientID, now)
	name := resolveClientName(clientID, clientParams)
	flow := resolveClientFlow(server, clientParams)

	// 3. Append client to inbounds (Email must be unique clientID to prevent Xray crash on duplicate display names).
	// The raw JSON is edited so operator-added blocks (routing, dns, sniffing, ...) survive.
	updatedBytes, err := appendInboundClient(cfgBytes, func(i int) XrayClient {
		if i == 0 {
			return XrayClient{ID: clientID, Email: clientID, Flow: flow}
		}
		return XrayClient{ID: clientID, Email: clientID, Flow: "xtls-rprx-vision"}
	})
	if err != nil {
		return nil, fmt.Errorf("add client to xray config: %w", err)
	}

	// 4. Upload updated config
	if err := client.UploadSudoFile(ctx, XrayConfigPath, updatedBytes, 0600); err != nil {
		return nil, fmt.Errorf("upload updated xray config: %w", err)
	}

	// 5. Restart container to apply configuration
	restartCmd := fmt.Sprintf("docker restart %s", ssh.EscapeShellArg(XrayContainerName))
	if _, errOut, code, err := client.RunSudoCommand(ctx, restartCmd); err != nil || code != 0 {
		return nil, fmt.Errorf("failed to restart xray container (code %d): %s: %w", code, errOut, err)
	}

	// 6. Build vless:// client URI
	realitySettings := cfg.Inbounds[0].StreamSettings.RealitySettings
	serverName := DefaultDecoyDomain
	if len(realitySettings.ServerNames) > 0 {
		serverName = realitySettings.ServerNames[0]
	}
	shortID := SelectClientShortID(realitySettings.ShortIDs, clientID)

	pubKey, err := DerivePublicKey(realitySettings.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("derive reality public key: %w", err)
	}

	port := cfg.Inbounds[0].Port
	host := server.Host

	mux := resolveMuxSetting(ctx, server)
	if clientParams != nil {
		if m, ok := clientParams["mux"].(bool); ok {
			mux = m
		} else if m, ok := clientParams["mux"].(string); ok {
			mux = strings.EqualFold(m, "true")
		}
	}

	vlessURI, err := BuildVLESSURI(host, port, clientID, name, serverName, pubKey, shortID, flow, mux)
	if err != nil {
		return nil, fmt.Errorf("build vless URI: %w", err)
	}

	engineProfile := resolveClientEngineProfile(server, clientParams)

	return map[string]any{
		"client_id":      clientID,
		"clientId":       clientID,
		"uuid":           clientID,
		"name":           name,
		"config":         vlessURI,
		"public_key":     pubKey,
		"short_id":       shortID,
		"flow":           flow,
		"server_name":    serverName,
		"port":           port,
		"engine_profile": engineProfile,
		"mux":            mux,
		"creationDate":   now.Format(time.RFC3339),
		"created_at":     now.Format(time.RFC3339),
	}, nil
}

// RemoveClient deletes a client UUID from config.json and restarts the container.
func (m *XrayManager) RemoveClient(ctx context.Context, server *models.Server, clientID string) error {
	if clientID == "" {
		return errors.New("clientID cannot be empty")
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

	cfgBytes, err := client.DownloadSudoFile(ctx, XrayConfigPath)
	if err != nil {
		return fmt.Errorf("failed to download xray config: %w", err)
	}

	if _, err := ParseXrayConfig(cfgBytes); err != nil {
		return fmt.Errorf("failed to parse xray config: %w", err)
	}

	updatedBytes, err := removeInboundClient(cfgBytes, clientID)
	if err != nil {
		return fmt.Errorf("remove client from xray config: %w", err)
	}

	if err := client.UploadSudoFile(ctx, XrayConfigPath, updatedBytes, 0600); err != nil {
		return fmt.Errorf("upload updated xray config: %w", err)
	}

	restartCmd := fmt.Sprintf("docker restart %s", ssh.EscapeShellArg(XrayContainerName))
	if _, errOut, code, err := client.RunSudoCommand(ctx, restartCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to restart xray container (code %d): %s: %w", code, errOut, err)
	}

	return nil
}

// GetClients returns all clients configured in the xray inbounds.
func (m *XrayManager) GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return nil, err
	}

	cfgBytes, err := client.DownloadSudoFile(ctx, XrayConfigPath)
	if err != nil {
		return nil, fmt.Errorf("download xray config: %w", err)
	}

	cfg, err := ParseXrayConfig(cfgBytes)
	if err != nil {
		return nil, fmt.Errorf("parse xray config: %w", err)
	}
	if len(cfg.Inbounds) == 0 {
		return []map[string]any{}, nil
	}

	clients := make([]map[string]any, 0, len(cfg.Inbounds[0].Settings.Clients))
	for _, c := range cfg.Inbounds[0].Settings.Clients {
		client := map[string]any{
			"client_id": c.ID,
			"clientId":  c.ID,
			"uuid":      c.ID,
			"name":      c.Email,
			"flow":      c.Flow,
		}
		if createdAt, ok := m.recentClientCreation(c.ID); ok {
			client["creationDate"] = createdAt.Format(time.RFC3339)
		}
		clients = append(clients, client)
	}

	return clients, nil
}

// GetClientConfig reconstructs the vless:// connection URI for a given client ID.
func (m *XrayManager) GetClientConfig(ctx context.Context, server *models.Server, clientID string) (string, error) {
	if clientID == "" {
		return "", errors.New("clientID cannot be empty")
	}

	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return "", err
	}

	cfgBytes, err := client.DownloadSudoFile(ctx, XrayConfigPath)
	if err != nil {
		return "", fmt.Errorf("download xray config: %w", err)
	}

	cfg, err := ParseXrayConfig(cfgBytes)
	if err != nil || len(cfg.Inbounds) == 0 {
		return "", errors.New("xray config is invalid or has no inbounds")
	}

	var foundClient *XrayClient
	for _, c := range cfg.Inbounds[0].Settings.Clients {
		if c.ID == clientID {
			foundClient = &c
			break
		}
	}
	if foundClient == nil {
		return "", fmt.Errorf("client %q not found in xray configuration", clientID)
	}

	realitySettings := cfg.Inbounds[0].StreamSettings.RealitySettings
	serverName := DefaultDecoyDomain
	if len(realitySettings.ServerNames) > 0 {
		serverName = realitySettings.ServerNames[0]
	}
	shortID := SelectClientShortID(realitySettings.ShortIDs, foundClient.ID)

	pubKey, err := DerivePublicKey(realitySettings.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("derive reality public key: %w", err)
	}

	mux := resolveMuxSetting(ctx, server)

	return BuildVLESSURI(
		server.Host,
		cfg.Inbounds[0].Port,
		foundClient.ID,
		foundClient.Email,
		serverName,
		pubKey,
		shortID,
		foundClient.Flow,
		mux,
	)
}

// GetClientConfigWithParams reconstructs the vless:// connection URI supporting per-client parameters like mux.
func (m *XrayManager) GetClientConfigWithParams(ctx context.Context, server *models.Server, clientID string, clientParams map[string]any) (string, error) {
	if clientParams != nil {
		if m, ok := clientParams["mux"].(bool); ok {
			ctx = WithMuxContext(ctx, m)
		} else if m, ok := clientParams["mux"].(string); ok {
			ctx = WithMuxContext(ctx, strings.EqualFold(m, "true"))
		}
	}
	return m.GetClientConfig(ctx, server, clientID)
}
