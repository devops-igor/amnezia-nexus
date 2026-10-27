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

// AddClient adds basic-auth credentials to the Caddyfile and triggers zero-downtime caddy reload.
func (m *NaiveManager) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return nil, err
	}

	unlock, err := m.lockServer(ctx, client, server.ID)
	if err != nil {
		return nil, err
	}
	defer unlock()

	// 1. Download existing Caddyfile
	caddyfileBytes, err := client.DownloadSudoFile(ctx, NaiveCaddyfilePath)
	if err != nil {
		return nil, fmt.Errorf("download Caddyfile: %w", err)
	}

	domain, port, clients, err := ParseCaddyfile(string(caddyfileBytes))
	if err != nil {
		return nil, fmt.Errorf("parse Caddyfile: %w", err)
	}
	if domain == "" {
		domain = server.Host
	}

	// 2. Generate or extract credentials
	var username, password string
	if u, ok := clientParams["username"].(string); ok && strings.TrimSpace(u) != "" {
		username = strings.TrimSpace(u)
	}
	if p, ok := clientParams["password"].(string); ok && strings.TrimSpace(p) != "" {
		password = strings.TrimSpace(p)
	}
	if username == "" || password == "" {
		genUser, genPass, err := GenerateNaiveCredentials()
		if err != nil {
			return nil, fmt.Errorf("generate credentials: %w", err)
		}
		if username == "" {
			username = genUser
		}
		if password == "" {
			password = genPass
		}
	}

	name := username
	if n, ok := clientParams["name"].(string); ok && strings.TrimSpace(n) != "" {
		name = strings.TrimSpace(n)
	}

	now := time.Now().UTC()
	m.recordClientCreation(username, now)

	// 3. Append new client credentials
	clients = append(clients, NaiveClient{
		Username: username,
		Password: password,
	})

	// 4. Render and upload updated Caddyfile
	updatedContent := RenderCaddyfile(port, domain, clients)
	if err := client.UploadSudoFile(ctx, NaiveCaddyfilePath, []byte(updatedContent), 0644); err != nil {
		return nil, fmt.Errorf("upload updated Caddyfile: %w", err)
	}

	// 5. Zero-downtime graceful configuration reload via loopback admin API
	reloadCmd := fmt.Sprintf("docker exec %s caddy reload --config /etc/caddy/Caddyfile", ssh.EscapeShellArg(NaiveContainerName))
	if _, errOut, code, err := client.RunSudoCommand(ctx, reloadCmd); err != nil || code != 0 {
		return nil, fmt.Errorf("failed to reload caddy container (code %d): %s: %w", code, errOut, err)
	}

	// 6. Build client URI
	uri, err := BuildNaiveURI(domain, port, username, password, name)
	if err != nil {
		return nil, fmt.Errorf("build naive URI: %w", err)
	}

	return map[string]any{
		"client_id":    username,
		"clientId":     username,
		"username":     username,
		"password":     password,
		"name":         name,
		"config":       uri,
		"domain":       domain,
		"port":         port,
		"creationDate": now.Format(time.RFC3339),
		"created_at":   now.Format(time.RFC3339),
	}, nil
}

// RemoveClient deletes a basic-auth credential and gracefully reloads Caddy.
func (m *NaiveManager) RemoveClient(ctx context.Context, server *models.Server, clientID string) error {
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

	caddyfileBytes, err := client.DownloadSudoFile(ctx, NaiveCaddyfilePath)
	if err != nil {
		return fmt.Errorf("download Caddyfile: %w", err)
	}

	domain, port, clients, err := ParseCaddyfile(string(caddyfileBytes))
	if err != nil {
		return fmt.Errorf("parse Caddyfile: %w", err)
	}

	filtered := make([]NaiveClient, 0, len(clients))
	for _, c := range clients {
		if c.Username != clientID {
			filtered = append(filtered, c)
		}
	}

	updatedContent := RenderCaddyfile(port, domain, filtered)
	if err := client.UploadSudoFile(ctx, NaiveCaddyfilePath, []byte(updatedContent), 0644); err != nil {
		return fmt.Errorf("upload updated Caddyfile: %w", err)
	}

	reloadCmd := fmt.Sprintf("docker exec %s caddy reload --config /etc/caddy/Caddyfile", ssh.EscapeShellArg(NaiveContainerName))
	if _, errOut, code, err := client.RunSudoCommand(ctx, reloadCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to reload caddy container (code %d): %s: %w", code, errOut, err)
	}

	return nil
}

// GetClients returns all basic-auth clients from the Caddyfile.
func (m *NaiveManager) GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return nil, err
	}

	caddyfileBytes, err := client.DownloadSudoFile(ctx, NaiveCaddyfilePath)
	if err != nil {
		return nil, fmt.Errorf("download caddyfile: %w", err)
	}

	_, _, clients, err := ParseCaddyfile(string(caddyfileBytes))
	if err != nil {
		return nil, fmt.Errorf("parse caddyfile: %w", err)
	}

	results := make([]map[string]any, 0, len(clients))
	for _, c := range clients {
		client := map[string]any{
			"client_id": c.Username,
			"clientId":  c.Username,
			"username":  c.Username,
		}
		if createdAt, ok := m.recentClientCreation(c.Username); ok {
			client["creationDate"] = createdAt.Format(time.RFC3339)
		}
		results = append(results, client)
	}

	return results, nil
}

// GetClientConfig returns the https:// connection URI for a client.
func (m *NaiveManager) GetClientConfig(ctx context.Context, server *models.Server, clientID string) (string, error) {
	if clientID == "" {
		return "", errors.New("clientID cannot be empty")
	}

	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return "", err
	}

	caddyfileBytes, err := client.DownloadSudoFile(ctx, NaiveCaddyfilePath)
	if err != nil {
		return "", fmt.Errorf("download Caddyfile: %w", err)
	}

	domain, port, clients, err := ParseCaddyfile(string(caddyfileBytes))
	if err != nil {
		return "", fmt.Errorf("parse Caddyfile: %w", err)
	}
	if domain == "" {
		domain = server.Host
	}

	var foundClient *NaiveClient
	for _, c := range clients {
		if c.Username == clientID {
			foundClient = &c
			break
		}
	}
	if foundClient == nil {
		return "", fmt.Errorf("client %q not found in Caddyfile", clientID)
	}

	return BuildNaiveURI(domain, port, foundClient.Username, foundClient.Password, foundClient.Username)
}
