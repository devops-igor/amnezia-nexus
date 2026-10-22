package awg_test

import (
	"context"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
)

const legacyRollbackServerConf = "[Interface]\n" +
	"PrivateKey = serverPrivKey1234567890123456789012345=\n" +
	"Address = 10.100.0.1/16\n" +
	"ListenPort = 55424\n" +
	"MTU = 1280\n" +
	"S1 = 12\n" +
	"S2 = 12\n" +
	"S3 = 12\n" +
	"S4 = 12\n" +
	"H1 = 1\n" +
	"H2 = 2\n" +
	"H3 = 3\n" +
	"H4 = 4\n"

func TestAddClient_LegacyServerRollbackRemovesPeerAndReleasesLease(t *testing.T) {
	mgr, db, sshClient, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()
	ctx := context.Background()
	sshClient.files["/opt/amnezia/awg/awg0.conf"] = []byte(legacyRollbackServerConf)
	sshClient.failEnsureNAT.Store(true)

	if _, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "legacy-rollback"}); err == nil {
		t.Fatal("expected AddClient to fail at NAT step")
	}
	sshClient.mu.RLock()
	conf := string(sshClient.files["/opt/amnezia/awg/awg0.conf"])
	sshClient.mu.RUnlock()
	if strings.Contains(conf, "[Peer]") || !strings.Contains(conf, "S1 = 12\n") || !strings.Contains(conf, "H1 = 1\n") {
		t.Fatalf("rollback did not remove peer / lost legacy values: %q", conf)
	}
	allocated, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil || len(allocated) != 0 {
		t.Fatalf("lease must be released after successful remote removal: %v %v", allocated, err)
	}
}

func TestAddClient_LegacyServerRekeyRollbackRestoresPreviousPeer(t *testing.T) {
	mgr, db, sshClient, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()
	ctx := context.Background()
	const k1 = "ERERERERERERERERERERERERERERERERERERERERERE="
	const k2 = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI="
	sshClient.files["/opt/amnezia/awg/awg0.conf"] = []byte(legacyRollbackServerConf)

	res1, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "Alice", "public_key": k1})
	if err != nil {
		t.Fatalf("initial AddClient on legacy server failed: %v", err)
	}
	ip1, _ := res1["client_ip"].(string)
	sshClient.failSyncconfOnce.Store(true)
	if _, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "Alice", "public_key": k2}); err == nil {
		t.Fatal("expected re-key AddClient to fail")
	}
	sshClient.mu.RLock()
	conf := string(sshClient.files["/opt/amnezia/awg/awg0.conf"])
	sshClient.mu.RUnlock()
	_, peers, err := awg.ParseServerConfig(conf)
	if err != nil || len(peers) != 1 || peers[0].PublicKey != k1 {
		t.Fatalf("expected K1 restored: %+v %v", peers, err)
	}
	if !strings.Contains(conf, "S1 = 12\n") || !strings.Contains(conf, "H1 = 1\n") {
		t.Fatalf("rekey rollback lost legacy interface values: %q", conf)
	}
	owner, err := db.GetAWGIPAllocationOwner(ctx, server.ID, ip1)
	if err != nil || owner != k1 {
		t.Fatalf("expected lease reverted to K1, got %q (%v)", owner, err)
	}
}
