package database

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestIsBackendTunnelClientProtocolScoped(t *testing.T) {
	ctx := t.Context()
	db, err := Open(filepath.Join(t.TempDir(), "backend-match.db"), "test-secret-key-1234567890123456")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	serverID, err := db.CreateServer(ctx, &models.Server{Name: "match", Host: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := json.Marshal(models.NaiveProxyParams{Username: "SameID", Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: serverID, Protocol: models.ProtocolNaive, ProtocolParams: p,
		InterfaceName: "naive-match", Status: models.TunnelStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	vlessParams, err := json.Marshal(models.VLESSRealityParams{UUID: "AABB-CCDD"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: serverID, Protocol: models.ProtocolVLESS, ProtocolParams: vlessParams,
		InterfaceName: "vless-match", Status: models.TunnelStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, proto, id string
		serverID        int64
		want            bool
	}{
		{name: "naive exact", proto: models.ProtocolNaive, id: "SameID", serverID: serverID, want: true},
		{name: "naive case sensitive", proto: models.ProtocolNaive, id: "sameid", serverID: serverID},
		{name: "vless collision", proto: models.ProtocolVLESS, id: "SameID", serverID: serverID},
		{name: "vless case insensitive", proto: models.ProtocolVLESS, id: "aabb-ccdd", serverID: serverID, want: true},
		{name: "naive cannot match vless", proto: models.ProtocolNaive, id: "AABB-CCDD", serverID: serverID},
		{name: "other server", proto: models.ProtocolNaive, id: "SameID", serverID: serverID + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := db.IsBackendTunnelClient(ctx, tc.serverID, tc.proto, tc.id)
			if err != nil || got != tc.want {
				t.Fatalf("match = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}
