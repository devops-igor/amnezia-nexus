package awg

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

const legacyInterfaceConfig = `[Interface]
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

const (
	testLegacyPeerPubKey = "pubkey12345678901234567890123456789012="
	testLegacyPeerPSK    = "pskKey123456789012345678901234567890123="
	testLegacyPeerIP     = "10.100.0.2"
	testLegacyPeerSec    = "\n[Peer]\nPublicKey = " + testLegacyPeerPubKey + "\nPresharedKey = " + testLegacyPeerPSK + "\nAllowedIPs = 10.100.0.2/32\n"
)

func newLegacyServerMock(initialPeersConfig string, initialClients []AWGClient) (*mockAWGSSHClient, *AWGManager, *models.Server) {
	client := newMockAWGSSHClient()
	client.files["/opt/amnezia/awg/awg0.conf"] = []byte(legacyInterfaceConfig + initialPeersConfig)
	if initialClients != nil {
		raw, _ := json.Marshal(initialClients)
		client.files["/opt/amnezia/awg/clientsTable"] = raw
	}
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	server := &models.Server{ID: 611, Host: "198.51.100.11", SSHPort: 22, SSHUser: "root"}
	return client, mgr, server
}

func defaultLegacyClients() []AWGClient {
	return []AWGClient{
		{
			ClientID: testLegacyPeerPubKey,
			UserData: AWGClientUserData{
				ClientName:       "Legacy client",
				ClientPrivateKey: "privkey1234567890123456789012345678901234=",
				ClientIP:         testLegacyPeerIP,
				PSK:              testLegacyPeerPSK,
				Enabled:          true,
				AWGMimicry:       "tls",
			},
		},
	}
}

func assertLegacyInterfacePreserved(t *testing.T, config string) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(legacyInterfaceConfig), "\n") {
		if !strings.Contains(config, line+"\n") {
			t.Fatalf("peer save lost interface value %q: %q", line, config)
		}
	}
}

func TestAddClientPreservesLegacyInterfaceParams(t *testing.T) {
	client := newMockAWGSSHClient()
	client.files["/opt/amnezia/awg/awg0.conf"] = []byte(legacyInterfaceConfig)
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	server := &models.Server{ID: 611, Host: "198.51.100.11", SSHPort: 22, SSHUser: "root"}

	res, err := mgr.AddClient(context.Background(), server, map[string]any{"clientName": "Legacy peer"})
	if err != nil {
		t.Fatalf("AddClient rejected existing interface values: %v", err)
	}
	config := string(client.files["/opt/amnezia/awg/awg0.conf"])
	assertLegacyInterfacePreserved(t, config)
	if !strings.Contains(config, "[Peer]") || res["client_id"] == nil {
		t.Fatalf("peer save did not add the peer: %q", config)
	}
}

func TestRemoveClientPreservesLegacyInterfaceParams(t *testing.T) {
	client, mgr, server := newLegacyServerMock(testLegacyPeerSec, defaultLegacyClients())
	ctx := context.Background()

	err := mgr.RemoveClient(ctx, server, testLegacyPeerPubKey)
	if err != nil {
		t.Fatalf("RemoveClient failed on legacy server config: %v", err)
	}
	config := string(client.files["/opt/amnezia/awg/awg0.conf"])
	assertLegacyInterfacePreserved(t, config)
	if strings.Contains(config, testLegacyPeerPubKey) {
		t.Fatalf("RemoveClient did not remove peer from config: %q", config)
	}
}

func TestToggleClientPreservesLegacyInterfaceParams(t *testing.T) {
	client, mgr, server := newLegacyServerMock(testLegacyPeerSec, defaultLegacyClients())
	ctx := context.Background()

	// Disable client
	if err := mgr.ToggleClient(ctx, server, testLegacyPeerPubKey, false); err != nil {
		t.Fatalf("ToggleClient(disable) failed on legacy server config: %v", err)
	}
	configDisabled := string(client.files["/opt/amnezia/awg/awg0.conf"])
	assertLegacyInterfacePreserved(t, configDisabled)
	if strings.Contains(configDisabled, testLegacyPeerPubKey) {
		t.Fatalf("ToggleClient(disable) did not remove peer from config: %q", configDisabled)
	}

	// Enable client back
	if err := mgr.ToggleClient(ctx, server, testLegacyPeerPubKey, true); err != nil {
		t.Fatalf("ToggleClient(enable) failed on legacy server config: %v", err)
	}
	configEnabled := string(client.files["/opt/amnezia/awg/awg0.conf"])
	assertLegacyInterfacePreserved(t, configEnabled)
	if !strings.Contains(configEnabled, testLegacyPeerPubKey) {
		t.Fatalf("ToggleClient(enable) did not add peer back to config: %q", configEnabled)
	}
}

func TestEditClientPreservesLegacyInterfaceParams(t *testing.T) {
	client, mgr, server := newLegacyServerMock(testLegacyPeerSec, defaultLegacyClients())
	ctx := context.Background()

	// Disable client (triggers updateServerConfigPeer with enable=false)
	if err := mgr.EditClient(ctx, server, testLegacyPeerPubKey, map[string]any{"enabled": false}); err != nil {
		t.Fatalf("EditClient(enabled=false) failed on legacy server config: %v", err)
	}
	configDisabled := string(client.files["/opt/amnezia/awg/awg0.conf"])
	assertLegacyInterfacePreserved(t, configDisabled)
	if strings.Contains(configDisabled, testLegacyPeerPubKey) {
		t.Fatalf("EditClient(enabled=false) did not remove peer from config: %q", configDisabled)
	}

	// Re-enable client (triggers updateServerConfigPeer with enable=true)
	if err := mgr.EditClient(ctx, server, testLegacyPeerPubKey, map[string]any{"enabled": true}); err != nil {
		t.Fatalf("EditClient(enabled=true) failed on legacy server config: %v", err)
	}
	configEnabled := string(client.files["/opt/amnezia/awg/awg0.conf"])
	assertLegacyInterfacePreserved(t, configEnabled)
	if !strings.Contains(configEnabled, testLegacyPeerPubKey) {
		t.Fatalf("EditClient(enabled=true) did not add peer back to config: %q", configEnabled)
	}
}

func TestRollbackServerConfigSurgicallyPreservesLegacyInterfaceParams(t *testing.T) {
	ctx := context.Background()

	t.Run("non-upsert rollback via RollbackAddClient", func(t *testing.T) {
		client, mgr, server := newLegacyServerMock(testLegacyPeerSec, defaultLegacyClients())
		rollbackResult := map[string]any{
			"is_upsert":      false,
			"client_pub_key": testLegacyPeerPubKey,
			"client_ip":      testLegacyPeerIP,
		}
		if err := mgr.RollbackAddClient(ctx, server, rollbackResult); err != nil {
			t.Fatalf("RollbackAddClient(non-upsert) failed on legacy server config: %v", err)
		}
		config := string(client.files["/opt/amnezia/awg/awg0.conf"])
		assertLegacyInterfacePreserved(t, config)
		if strings.Contains(config, testLegacyPeerPubKey) {
			t.Fatalf("RollbackAddClient did not remove peer from config: %q", config)
		}
	})

	t.Run("upsert rollback via RollbackAddClient", func(t *testing.T) {
		const newPubKey = "newPubKey123456789012345678901234567890="
		newPeerSec := "\n[Peer]\nPublicKey = " + newPubKey + "\nPresharedKey = " + testLegacyPeerPSK + "\nAllowedIPs = 10.100.0.2/32\n"
		client, mgr, server := newLegacyServerMock(newPeerSec, []AWGClient{
			{
				ClientID: newPubKey,
				UserData: AWGClientUserData{
					ClientName: "Legacy client",
					ClientIP:   testLegacyPeerIP,
					PSK:        testLegacyPeerPSK,
					Enabled:    true,
					AWGMimicry: "tls",
				},
			},
		})
		rollbackResult := map[string]any{
			"is_upsert":             true,
			"client_pub_key":        newPubKey,
			"existing_pub_key":      testLegacyPeerPubKey,
			"previous_peer_section": testLegacyPeerSec,
			"previous_client": &AWGClient{
				ClientID: testLegacyPeerPubKey,
				UserData: AWGClientUserData{
					ClientName: "Legacy client",
					ClientIP:   testLegacyPeerIP,
					PSK:        testLegacyPeerPSK,
					Enabled:    true,
					AWGMimicry: "tls",
				},
			},
		}
		if err := mgr.RollbackAddClient(ctx, server, rollbackResult); err != nil {
			t.Fatalf("RollbackAddClient(upsert) failed on legacy server config: %v", err)
		}
		config := string(client.files["/opt/amnezia/awg/awg0.conf"])
		assertLegacyInterfacePreserved(t, config)
		if strings.Contains(config, newPubKey) || !strings.Contains(config, testLegacyPeerPubKey) {
			t.Fatalf("RollbackAddClient(upsert) did not restore previous peer: %q", config)
		}
	})

	t.Run("direct rollbackServerConfigSurgically call", func(t *testing.T) {
		client, mgr, _ := newLegacyServerMock(testLegacyPeerSec, nil)
		err := mgr.rollbackServerConfigSurgically(ctx, client, false, false, testLegacyPeerPubKey, testLegacyPeerIP, nil)
		if err != nil {
			t.Fatalf("rollbackServerConfigSurgically failed on legacy config: %v", err)
		}
		config := string(client.files["/opt/amnezia/awg/awg0.conf"])
		assertLegacyInterfacePreserved(t, config)
		if strings.Contains(config, testLegacyPeerPubKey) {
			t.Fatalf("rollbackServerConfigSurgically did not remove peer: %q", config)
		}
	})
}

func TestRestorePreviousPeerPreservesLegacyInterfaceParams(t *testing.T) {
	client, mgr, _ := newLegacyServerMock("", nil)
	ctx := context.Background()

	restored, err := mgr.restorePreviousPeer(ctx, client, legacyInterfaceConfig+testLegacyPeerSec, defaultLegacyClients())
	if err != nil || !restored {
		t.Fatalf("restorePreviousPeer failed on legacy server config: %v", err)
	}
	config := string(client.files["/opt/amnezia/awg/awg0.conf"])
	assertLegacyInterfacePreserved(t, config)
	if !strings.Contains(config, testLegacyPeerPubKey) {
		t.Fatalf("restorePreviousPeer did not write config: %q", config)
	}
}

func TestRemovePeerFromRemotePreservesLegacyInterfaceParams(t *testing.T) {
	client, mgr, _ := newLegacyServerMock(testLegacyPeerSec, defaultLegacyClients())
	ctx := context.Background()

	err := mgr.removePeerFromRemote(ctx, client, testLegacyPeerPubKey, testLegacyPeerIP)
	if err != nil {
		t.Fatalf("removePeerFromRemote failed on legacy server config: %v", err)
	}
	config := string(client.files["/opt/amnezia/awg/awg0.conf"])
	assertLegacyInterfacePreserved(t, config)
	if strings.Contains(config, testLegacyPeerPubKey) {
		t.Fatalf("removePeerFromRemote did not remove peer from config: %q", config)
	}
}

func TestSaveServerConfigStillValidatesNewParams(t *testing.T) {
	cases := []struct {
		name   string
		params string
		want   string
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
