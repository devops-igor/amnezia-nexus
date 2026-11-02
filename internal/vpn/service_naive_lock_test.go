package vpn

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

func TestAuditNativeReadinessBlocksServiceReaders(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sid, _, _ := createTestServerAndKey(t, db, "audit-native-lock", "198.51.100.1")
	raw, err := json.Marshal(models.NaiveProxyParams{Username: "audit-user", Password: "audit-password", Domain: "naive.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := svc.pool.AddTunnelWithConfig(ctx, sid, "198.51.100.1:443", "", tunnel.BackendTunnelOptions{Protocol: models.ProtocolNaive, ProtocolParams: raw})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "naive")
	marker := filepath.Join(dir, "entered")
	script := "#!/usr/bin/python3\nimport json,socket,sys,time\nfrom urllib.parse import urlparse\nc=json.load(open(sys.argv[1]));open('" + marker + "','w').close();time.sleep(0.5);u=urlparse(c['listen']);s=socket.socket();s.bind((u.hostname,u.port));s.listen();time.sleep(30)\n"
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NAIVE_BIN_PATH", bin)
	t.Setenv("NAIVE_DISABLE_DOWNLOAD", "0")
	finished := make(chan error, 1)
	go func() { finished <- svc.finishEnableBackend(ctx, svc.pool, tun, nil, sid, 0) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native process not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
	reader := make(chan struct{})
	go func() {
		svc.mu.RLock()
		_ = svc.adminDisableEpoch
		svc.mu.RUnlock()
		close(reader)
	}()
	blocked := false
	select {
	case <-reader:
	case <-time.After(150 * time.Millisecond):
		blocked = true
	}
	err = <-finished
	<-reader
	if dev := svc.backendDevices[tun.ID]; dev != nil {
		defer dev.Close()
	}
	t.Logf("unrelated Service.mu reader blocked during native startup=%v activationError=%v", blocked, err)
	if blocked {
		t.Fatal("native readiness executes under service-wide state lock")
	}
}
