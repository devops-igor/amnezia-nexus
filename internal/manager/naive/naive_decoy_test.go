package naive

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

type decoyRecordingNaiveSSHClient struct {
	*mockNaiveSSHClient
	mu    sync.Mutex
	modes map[string]os.FileMode
}

func newDecoyRecordingNaiveSSHClient() *decoyRecordingNaiveSSHClient {
	return &decoyRecordingNaiveSSHClient{
		mockNaiveSSHClient: newMockNaiveSSHClient(),
		modes:              make(map[string]os.FileMode),
	}
}

func (c *decoyRecordingNaiveSSHClient) UploadSudoFile(ctx context.Context, remotePath string, content []byte, mode os.FileMode) error {
	c.mu.Lock()
	c.modes[remotePath] = mode
	c.mu.Unlock()
	return c.mockNaiveSSHClient.UploadSudoFile(ctx, remotePath, content, mode)
}

func TestRenderCaddyfile_StaticDecoySite(t *testing.T) {
	tests := []struct {
		name        string
		port        int
		domain      string
		clients     []NaiveClient
		wantRoot    string
		wantServer  string
		wantNotRoot string
	}{
		{
			name:   "port 443 with clients",
			port:   443,
			domain: "mc.example.com",
			clients: []NaiveClient{
				{Username: "player1", Password: "supersecretpassword1"},
			},
			wantRoot:    "root * /var/www/html",
			wantServer:  "file_server",
			wantNotRoot: "root * /srv",
		},
		{
			name:        "port 443 with nil clients",
			port:        443,
			domain:      "voxel.example.org",
			clients:     nil,
			wantRoot:    "root * /var/www/html",
			wantServer:  "file_server",
			wantNotRoot: "root * /srv",
		},
		{
			name:        "port 443 with empty clients",
			port:        443,
			domain:      "craft.example.net",
			clients:     []NaiveClient{},
			wantRoot:    "root * /var/www/html",
			wantServer:  "file_server",
			wantNotRoot: "root * /srv",
		},
		{
			name:   "custom port 8443 with clients",
			port:   8443,
			domain: "node.example.com",
			clients: []NaiveClient{
				{Username: "miner", Password: "diamondpickaxe123"},
			},
			wantRoot:    "root * /var/www/html",
			wantServer:  "file_server",
			wantNotRoot: "root * /srv",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RenderCaddyfile(tt.port, tt.domain, tt.clients)

			if !strings.Contains(got, tt.wantRoot) {
				t.Errorf("RenderCaddyfile() missing expected root directive %q:\n%s", tt.wantRoot, got)
			}
			if !strings.Contains(got, tt.wantServer) {
				t.Errorf("RenderCaddyfile() missing expected file_server directive %q:\n%s", tt.wantServer, got)
			}
			if strings.Contains(got, tt.wantNotRoot) {
				t.Errorf("RenderCaddyfile() contains obsolete root directive %q:\n%s", tt.wantNotRoot, got)
			}

			// Verify route order: @rawProbe -> forward_proxy (if present) -> root * /var/www/html -> file_server
			rawProbeIdx := strings.Index(got, "@rawProbe")
			if rawProbeIdx == -1 {
				t.Fatalf("RenderCaddyfile() missing @rawProbe block:\n%s", got)
			}

			rootIdx := strings.Index(got, tt.wantRoot)
			fileServerIdx := strings.Index(got, tt.wantServer)

			if rootIdx <= rawProbeIdx {
				t.Errorf("root directive (%d) must appear after @rawProbe (%d)", rootIdx, rawProbeIdx)
			}
			if fileServerIdx <= rootIdx {
				t.Errorf("file_server directive (%d) must appear after root directive (%d)", fileServerIdx, rootIdx)
			}

			if len(tt.clients) > 0 {
				forwardProxyIdx := strings.Index(got, "forward_proxy {")
				if forwardProxyIdx == -1 {
					t.Fatalf("RenderCaddyfile() missing forward_proxy block when clients present:\n%s", got)
				}
				if forwardProxyIdx <= rawProbeIdx {
					t.Errorf("forward_proxy (%d) must appear after @rawProbe (%d)", forwardProxyIdx, rawProbeIdx)
				}
				if rootIdx <= forwardProxyIdx {
					t.Errorf("root directive (%d) must appear after forward_proxy (%d)", rootIdx, forwardProxyIdx)
				}
			}
		})
	}
}

func TestInstall_UploadsDecoyIndexHTML(t *testing.T) {
	mockSSH := newDecoyRecordingNaiveSSHClient()
	pool := &mockNaivePool{client: mockSSH}
	locks := awg.NewServerLockRegistry()
	mgr := NewNaiveManagerWithServerLocks(pool, locks)

	server := &models.Server{
		ID:      690,
		Host:    "198.51.100.90",
		SSHPort: 22,
	}
	ctx := context.Background()

	installParams := map[string]any{
		"port": 443,
		"naive_options": models.NaiveInstallOptions{
			Port:   "443",
			Domain: "minecraft.example.com",
		},
	}

	if err := mgr.Install(ctx, server, installParams); err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	expectedFilePath := "/opt/amnezia/caddy/www/index.html"
	mockSSH.mu.Lock()
	uploadedBytes, fileExists := mockSSH.files[expectedFilePath]
	uploadMode, modeExists := mockSSH.modes[expectedFilePath]
	commands := append([]string(nil), mockSSH.commands...)
	mockSSH.mu.Unlock()

	if !fileExists || len(uploadedBytes) == 0 {
		t.Fatalf("expected decoy index.html to be uploaded to %s", expectedFilePath)
	}

	// Verify content matches embedded Minecraft template
	if !strings.Contains(string(uploadedBytes), "VOXELNET") {
		t.Errorf("uploaded index.html does not appear to contain VOXELNET template:\n%s", string(uploadedBytes)[:min(200, len(uploadedBytes))])
	}
	if len(uploadedBytes) != len(minecraftDecoyHTML) {
		t.Errorf("uploaded index.html size = %d, want embedded template size %d", len(uploadedBytes), len(minecraftDecoyHTML))
	}

	// Verify upload mode is 0644
	if !modeExists {
		t.Fatalf("no upload mode recorded for %s", expectedFilePath)
	}
	if uploadMode != 0644 {
		t.Errorf("uploaded index.html mode = %04o, want 0644", uploadMode)
	}

	// Verify directory creation command created /opt/amnezia/caddy/www with permissions 0755
	foundWWWDirChmod := false
	for _, cmd := range commands {
		if strings.Contains(cmd, "mkdir -p") && strings.Contains(cmd, NaiveWWWDir) &&
			strings.Contains(cmd, "chmod 0755") && strings.Contains(cmd, NaiveWWWDir) {
			foundWWWDirChmod = true
			break
		}
	}
	if !foundWWWDirChmod {
		t.Errorf("expected directory creation command with chmod 0755 for %s, recorded commands:\n%v", NaiveWWWDir, commands)
	}
}

func TestInstall_DockerRunMountsDecoyVolume(t *testing.T) {
	mockSSH := newDecoyRecordingNaiveSSHClient()
	pool := &mockNaivePool{client: mockSSH}
	locks := awg.NewServerLockRegistry()
	mgr := NewNaiveManagerWithServerLocks(pool, locks)

	server := &models.Server{
		ID:      691,
		Host:    "198.51.100.91",
		SSHPort: 22,
	}
	ctx := context.Background()

	installParams := map[string]any{
		"port": 443,
		"naive_options": models.NaiveInstallOptions{
			Port:   "443",
			Domain: "voxelnet.example.org",
		},
	}

	if err := mgr.Install(ctx, server, installParams); err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	mockSSH.mu.Lock()
	var runCmd string
	for _, cmd := range mockSSH.commands {
		if strings.Contains(cmd, "docker run") {
			runCmd = cmd
			break
		}
	}
	mockSSH.mu.Unlock()

	if runCmd == "" {
		t.Fatalf("docker run command was not recorded")
	}

	expectedMountPattern := "-v '/opt/amnezia/caddy/www':/var/www/html:ro"
	unquotedMountPattern := "-v /opt/amnezia/caddy/www:/var/www/html:ro"
	if !strings.Contains(runCmd, expectedMountPattern) && !strings.Contains(runCmd, unquotedMountPattern) {
		t.Errorf("docker run must mount decoy volume (-v /opt/amnezia/caddy/www:/var/www/html:ro), got:\n%s", runCmd)
	}

	if strings.Contains(runCmd, ":/srv:ro") {
		t.Errorf("docker run must NOT mount obsolete /srv volume, got:\n%s", runCmd)
	}
}

func TestParseCaddyfile_StaticDecoyRoundTrip(t *testing.T) {
	tests := []struct {
		name           string
		port           int
		domain         string
		clients        []NaiveClient
		wantClientsLen int
	}{
		{
			name:   "single client with static decoy",
			port:   443,
			domain: "mc.voxelnet.io",
			clients: []NaiveClient{
				{Username: "craftsman", Password: "securepassword789"},
			},
			wantClientsLen: 1,
		},
		{
			name:           "zero clients with static decoy",
			port:           443,
			domain:         "hub.voxelnet.io",
			clients:        nil,
			wantClientsLen: 0,
		},
		{
			name:   "multiple clients with custom port and static decoy",
			port:   8443,
			domain: "play.voxelnet.io",
			clients: []NaiveClient{
				{Username: "steve", Password: "stevepassword1"},
				{Username: "alex", Password: "alexpassword2"},
			},
			wantClientsLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rendered := RenderCaddyfile(tt.port, tt.domain, tt.clients)

			// Confirm static decoy directives are present in rendered Caddyfile
			if !strings.Contains(rendered, "root * /var/www/html") {
				t.Fatalf("rendered Caddyfile missing root * /var/www/html:\n%s", rendered)
			}
			if !strings.Contains(rendered, "file_server") {
				t.Fatalf("rendered Caddyfile missing file_server:\n%s", rendered)
			}

			// Confirm ParseCaddyfile parses it cleanly
			parsedDomain, parsedPort, parsedClients, err := ParseCaddyfile(rendered)
			if err != nil {
				t.Fatalf("ParseCaddyfile failed on rendered decoy Caddyfile: %v\nContent:\n%s", err, rendered)
			}

			if parsedDomain != tt.domain {
				t.Errorf("ParseCaddyfile domain = %q, want %q", parsedDomain, tt.domain)
			}
			if parsedPort != tt.port {
				t.Errorf("ParseCaddyfile port = %d, want %d", parsedPort, tt.port)
			}
			if len(parsedClients) != tt.wantClientsLen {
				t.Errorf("ParseCaddyfile clients count = %d, want %d", len(parsedClients), tt.wantClientsLen)
			}

			for i, wantClient := range tt.clients {
				if i < len(parsedClients) {
					if parsedClients[i].Username != wantClient.Username || parsedClients[i].Password != wantClient.Password {
						t.Errorf("parsed client [%d] = %+v, want %+v", i, parsedClients[i], wantClient)
					}
				}
			}
		})
	}
}

func TestGetDecoyHTML(t *testing.T) {
	tests := []struct {
		name         string
		theme        string
		wantSnippet  string
		wantTemplate []byte
	}{
		{
			name:         "creative-studio returns Creative Studio template",
			theme:        DecoyThemeCreativeStudio,
			wantSnippet:  "Aura Creative Studio",
			wantTemplate: creativeStudioDecoyHTML,
		},
		{
			name:         "creative-studio case-insensitive with whitespace",
			theme:        "  CREATIVE-STUDIO  ",
			wantSnippet:  "Aura Creative Studio",
			wantTemplate: creativeStudioDecoyHTML,
		},
		{
			name:         "minecraft returns Minecraft template",
			theme:        DecoyThemeMinecraft,
			wantSnippet:  "VOXELNET",
			wantTemplate: minecraftDecoyHTML,
		},
		{
			name:         "minecraft case-insensitive with whitespace",
			theme:        "  MINECRAFT  ",
			wantSnippet:  "VOXELNET",
			wantTemplate: minecraftDecoyHTML,
		},
		{
			name:         "default returns Minecraft template",
			theme:        DecoyThemeDefault,
			wantSnippet:  "VOXELNET",
			wantTemplate: minecraftDecoyHTML,
		},
		{
			name:         "empty theme falls back to Minecraft template",
			theme:        "",
			wantSnippet:  "VOXELNET",
			wantTemplate: minecraftDecoyHTML,
		},
		{
			name:         "unknown theme falls back to Minecraft template",
			theme:        "random-portfolio-theme",
			wantSnippet:  "VOXELNET",
			wantTemplate: minecraftDecoyHTML,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetDecoyHTML(tt.theme)
			if len(got) == 0 {
				t.Fatalf("GetDecoyHTML(%q) returned empty bytes", tt.theme)
			}
			if len(got) != len(tt.wantTemplate) {
				t.Errorf("GetDecoyHTML(%q) length = %d, want %d", tt.theme, len(got), len(tt.wantTemplate))
			}
			if !strings.Contains(string(got), tt.wantSnippet) {
				t.Errorf("GetDecoyHTML(%q) does not contain %q", tt.theme, tt.wantSnippet)
			}
		})
	}
}

func TestInstall_UploadsSelectedDecoyTemplate(t *testing.T) {
	tests := []struct {
		name          string
		installParams map[string]any
		wantSnippet   string
		wantTemplate  []byte
	}{
		{
			name: "creative-studio theme via NaiveInstallOptions struct",
			installParams: map[string]any{
				"port": 443,
				"naive_options": models.NaiveInstallOptions{
					Port:          "443",
					Domain:        "cs.example.com",
					DecoyTemplate: "creative-studio",
				},
			},
			wantSnippet:  "Aura Creative Studio",
			wantTemplate: creativeStudioDecoyHTML,
		},
		{
			name: "creative-studio theme via pointer to NaiveInstallOptions",
			installParams: map[string]any{
				"port": 443,
				"naive_options": &models.NaiveInstallOptions{
					Port:          "443",
					Domain:        "cs-ptr.example.com",
					DecoyTemplate: "creative-studio",
				},
			},
			wantSnippet:  "Aura Creative Studio",
			wantTemplate: creativeStudioDecoyHTML,
		},
		{
			name: "creative-studio theme via map[string]any options",
			installParams: map[string]any{
				"port": 443,
				"naive_options": map[string]any{
					"port":           "443",
					"domain":         "cs-map.example.com",
					"decoy_template": "creative-studio",
				},
			},
			wantSnippet:  "Aura Creative Studio",
			wantTemplate: creativeStudioDecoyHTML,
		},
		{
			name: "minecraft theme explicit",
			installParams: map[string]any{
				"port": 443,
				"naive_options": models.NaiveInstallOptions{
					Port:          "443",
					Domain:        "mc-explicit.example.com",
					DecoyTemplate: "minecraft",
				},
			},
			wantSnippet:  "VOXELNET",
			wantTemplate: minecraftDecoyHTML,
		},
		{
			name: "default theme",
			installParams: map[string]any{
				"port": 443,
				"naive_options": models.NaiveInstallOptions{
					Port:          "443",
					Domain:        "default-theme.example.com",
					DecoyTemplate: "default",
				},
			},
			wantSnippet:  "VOXELNET",
			wantTemplate: minecraftDecoyHTML,
		},
		{
			name: "empty theme defaults to minecraft",
			installParams: map[string]any{
				"port": 443,
				"naive_options": models.NaiveInstallOptions{
					Port:          "443",
					Domain:        "empty-theme.example.com",
					DecoyTemplate: "",
				},
			},
			wantSnippet:  "VOXELNET",
			wantTemplate: minecraftDecoyHTML,
		},
		{
			name: "unknown theme falls back to minecraft",
			installParams: map[string]any{
				"port": 443,
				"naive_options": models.NaiveInstallOptions{
					Port:          "443",
					Domain:        "unknown-theme.example.com",
					DecoyTemplate: "unsupported-theme",
				},
			},
			wantSnippet:  "VOXELNET",
			wantTemplate: minecraftDecoyHTML,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSSH := newDecoyRecordingNaiveSSHClient()
			pool := &mockNaivePool{client: mockSSH}
			locks := awg.NewServerLockRegistry()
			mgr := NewNaiveManagerWithServerLocks(pool, locks)

			server := &models.Server{
				ID:      700,
				Host:    "198.51.100.95",
				SSHPort: 22,
			}
			ctx := context.Background()

			if err := mgr.Install(ctx, server, tt.installParams); err != nil {
				t.Fatalf("Install failed: %v", err)
			}

			expectedFilePath := "/opt/amnezia/caddy/www/index.html"
			mockSSH.mu.Lock()
			uploadedBytes, fileExists := mockSSH.files[expectedFilePath]
			uploadMode, modeExists := mockSSH.modes[expectedFilePath]
			mockSSH.mu.Unlock()

			if !fileExists || len(uploadedBytes) == 0 {
				t.Fatalf("expected decoy index.html to be uploaded to %s", expectedFilePath)
			}

			if !strings.Contains(string(uploadedBytes), tt.wantSnippet) {
				t.Errorf("uploaded index.html does not contain snippet %q:\n%s", tt.wantSnippet, string(uploadedBytes)[:min(200, len(uploadedBytes))])
			}

			if len(uploadedBytes) != len(tt.wantTemplate) {
				t.Errorf("uploaded index.html size = %d, want template size %d", len(uploadedBytes), len(tt.wantTemplate))
			}

			if !modeExists || uploadMode != 0644 {
				t.Errorf("uploaded index.html mode = %04o, want 0644", uploadMode)
			}
		})
	}
}
