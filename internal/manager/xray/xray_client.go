package xray

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/google/uuid"
)

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
	cfgBytes, err := client.DownloadFile(ctx, XrayConfigPath)
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
	name := fmt.Sprintf("client-%s", clientID[:8])
	if n, ok := clientParams["name"].(string); ok && strings.TrimSpace(n) != "" {
		name = strings.TrimSpace(n)
	} else if email, ok := clientParams["email"].(string); ok && strings.TrimSpace(email) != "" {
		name = strings.TrimSpace(email)
	}

	flow := "xtls-rprx-vision"
	if f, ok := clientParams["flow"].(string); ok {
		flow = f
	}

	// 3. Append client to inbounds
	newClient := XrayClient{
		ID:    clientID,
		Email: name,
		Flow:  flow,
	}
	cfg.Inbounds[0].Settings.Clients = append(cfg.Inbounds[0].Settings.Clients, newClient)

	if len(cfg.Inbounds) > 1 {
		cfg.Inbounds[1].Settings.Clients = append(cfg.Inbounds[1].Settings.Clients, XrayClient{
			ID:    clientID,
			Email: name,
			Flow:  "xtls-rprx-vision",
		})
	}

	// 4. Upload updated config
	updatedBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal updated xray config: %w", err)
	}

	if err := client.UploadSudoFile(ctx, XrayConfigPath, updatedBytes, 0644); err != nil {
		return nil, fmt.Errorf("upload updated xray config: %w", err)
	}

	// 5. Restart container to apply configuration
	restartCmd := fmt.Sprintf("docker restart %s", ssh.EscapeShellArg(XrayContainerName))
	if _, errOut, code, err := client.RunSudoCommand(ctx, restartCmd); err != nil || code != 0 {
		return nil, fmt.Errorf("failed to restart xray container (code %d): %s: %w", code, errOut, err)
	}

	// 6. Build vless:// client URI
	realitySettings := cfg.Inbounds[0].StreamSettings.RealitySettings
	serverName := "gateway.icloud.com"
	if len(realitySettings.ServerNames) > 0 {
		serverName = realitySettings.ServerNames[0]
	}
	shortID := ""
	if len(realitySettings.ShortIDs) > 0 {
		shortID = realitySettings.ShortIDs[0]
	}

	pubKey, err := DerivePublicKey(realitySettings.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("derive reality public key: %w", err)
	}

	port := cfg.Inbounds[0].Port
	host := server.Host

	vlessURI, err := BuildVLESSURI(host, port, clientID, name, serverName, pubKey, shortID, flow)
	if err != nil {
		return nil, fmt.Errorf("build vless URI: %w", err)
	}

	return map[string]any{
		"client_id":   clientID,
		"clientId":    clientID,
		"uuid":        clientID,
		"name":        name,
		"config":      vlessURI,
		"public_key":  pubKey,
		"short_id":    shortID,
		"flow":        flow,
		"server_name": serverName,
		"port":        port,
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

	cfgBytes, err := client.DownloadFile(ctx, XrayConfigPath)
	if err != nil {
		return fmt.Errorf("failed to download xray config: %w", err)
	}

	cfg, err := ParseXrayConfig(cfgBytes)
	if err != nil {
		return fmt.Errorf("failed to parse xray config: %w", err)
	}

	for i := range cfg.Inbounds {
		filtered := make([]XrayClient, 0, len(cfg.Inbounds[i].Settings.Clients))
		for _, c := range cfg.Inbounds[i].Settings.Clients {
			if c.ID != clientID {
				filtered = append(filtered, c)
			}
		}
		cfg.Inbounds[i].Settings.Clients = filtered
	}

	updatedBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal updated xray config: %w", err)
	}

	if err := client.UploadSudoFile(ctx, XrayConfigPath, updatedBytes, 0644); err != nil {
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

	cfgBytes, err := client.DownloadFile(ctx, XrayConfigPath)
	if err != nil {
		return []map[string]any{}, nil
	}

	cfg, err := ParseXrayConfig(cfgBytes)
	if err != nil || len(cfg.Inbounds) == 0 {
		return []map[string]any{}, nil
	}

	clients := make([]map[string]any, 0, len(cfg.Inbounds[0].Settings.Clients))
	for _, c := range cfg.Inbounds[0].Settings.Clients {
		clients = append(clients, map[string]any{
			"client_id": c.ID,
			"clientId":  c.ID,
			"uuid":      c.ID,
			"name":      c.Email,
			"flow":      c.Flow,
		})
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

	cfgBytes, err := client.DownloadFile(ctx, XrayConfigPath)
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
	serverName := "gateway.icloud.com"
	if len(realitySettings.ServerNames) > 0 {
		serverName = realitySettings.ServerNames[0]
	}
	shortID := ""
	if len(realitySettings.ShortIDs) > 0 {
		shortID = realitySettings.ShortIDs[0]
	}

	pubKey, err := DerivePublicKey(realitySettings.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("derive reality public key: %w", err)
	}

	return BuildVLESSURI(
		server.Host,
		cfg.Inbounds[0].Port,
		foundClient.ID,
		foundClient.Email,
		serverName,
		pubKey,
		shortID,
		foundClient.Flow,
	)
}
