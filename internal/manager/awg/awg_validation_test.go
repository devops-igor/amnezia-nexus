package awg

import (
	"context"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestAddClientPreservesLegacyInterfaceParams(t *testing.T) {
	client := newMockAWGSSHClient()
	const legacy = `[Interface]
PrivateKey = serverPrivKey1234567890123456789012345=
Address = 10.100.0.1/16
ListenPort = 55424
MTU = 1280
S1 = 12
S2 = 12
S3 = 12
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
`
	client.files["/opt/amnezia/awg/awg0.conf"] = []byte(legacy)
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	server := &models.Server{ID: 611, Host: "198.51.100.11", SSHPort: 22, SSHUser: "root"}

	res, err := mgr.AddClient(context.Background(), server, map[string]any{"clientName": "Legacy peer"})
	if err != nil {
		t.Fatalf("AddClient rejected existing interface values: %v", err)
	}
	config := string(client.files["/opt/amnezia/awg/awg0.conf"])
	for _, line := range strings.Split(strings.TrimSpace(legacy), "\n") {
		if !strings.Contains(config, line+"\n") {
			t.Fatalf("peer save lost interface value %q: %q", line, config)
		}
	}
	if !strings.Contains(config, "[Peer]") || res["client_id"] == nil {
		t.Fatalf("peer save did not add the peer: %q", config)
	}
}

func TestSaveServerConfigStillValidatesNewParams(t *testing.T) {
	cases := []struct {
		name string
		params string
		want string
	}{
		{name: "forward collision", params: "S1 = 12\nS2 = 68\n", want: "collision"},
		{name: "reverse collision", params: "S1 = 68\nS2 = 12\n", want: "collision"},
		{name: "new low header", params: "H1 = 1\n", want: "between 5"},
		{name: "new invalid numeric", params: "S1 = 0\n", want: "between 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := newMockAWGSSHClient()
			mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
			err := mgr.saveServerConfig(context.Background(), client, "[Interface]\nPrivateKey = test\n"+tc.params)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("new values must be rejected with %q: %v", tc.want, err)
			}
			for path := range client.files {
				if strings.Contains(path, "_amnz_edit_config") {
					t.Fatalf("invalid config was uploaded: %s", path)
				}
			}
		})
	}
}
