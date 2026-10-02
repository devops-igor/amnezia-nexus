package vpn

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQualificationSubject_LifecycleAndConfigFreezing(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "panel_test.db")
	configPath := filepath.Join(tempDir, "frozen-client.conf")
	readyPath := filepath.Join(tempDir, "subject.ready")

	// Allocate a free ephemeral port for testing
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen ephemeral udp: %v", err)
	}
	listenPort := socket.LocalAddr().(*net.UDPAddr).Port
	_ = socket.Close()

	cfg := QualificationSubjectConfig{
		DBPath:           dbPath,
		FrozenConfigPath: configPath,
		ReadyPath:        readyPath,
		ListenPort:       listenPort,
		EchoPort:         40001,
		UnderlayHostIP:   "10.254.250.1",
		DestinationIP:    "10.100.0.1",
	}

	subject, err := NewQualificationSubject(cfg)
	if err != nil {
		t.Fatalf("NewQualificationSubject failed: %v", err)
	}

	// 1. Verify frozen-client.conf was written BEFORE and exists with 0600 permissions
	fi, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("frozen-client.conf stat: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("frozen-client.conf permissions = %o, want 0600", fi.Mode().Perm())
	}
	confBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read frozen-client.conf: %v", err)
	}
	confStr := string(confBytes)
	for _, expected := range []string{
		"[Interface]",
		"Address = 10.100.",
		"PrivateKey = ",
		"H1 = ",
		"H2 = ",
		"H3 = ",
		"H4 = ",
		"S1 = 50",
		"S2 = 100",
		"S3 = 150",
		"S4 = 200",
		"HeaderProtectionKey = ",
		"[Peer]",
		"PublicKey = ",
		"Endpoint = 10.254.250.1:",
		"AllowedIPs = 0.0.0.0/0",
	} {
		if !strings.Contains(confStr, expected) {
			t.Errorf("frozen-client.conf missing line/token %q", expected)
		}
	}

	// 2. Verify subject.ready was written and contains valid JSON metadata
	readyBytes, err := os.ReadFile(readyPath)
	if err != nil {
		t.Fatalf("read subject.ready: %v", err)
	}
	var readyMeta map[string]any
	if err := json.Unmarshal(readyBytes, &readyMeta); err != nil {
		t.Fatalf("unmarshal subject.ready: %v", err)
	}
	if readyMeta["status"] != "ready" {
		t.Errorf("ready status = %v, want ready", readyMeta["status"])
	}
	if int(readyMeta["listen_port"].(float64)) != listenPort {
		t.Errorf("ready listen_port = %v, want %d", readyMeta["listen_port"], listenPort)
	}

	// 3. Verify component accessors
	if subject.DB() == nil {
		t.Error("subject.DB() returned nil")
	}
	if subject.Service() == nil {
		t.Error("subject.Service() returned nil")
	}
	if subject.Engine() == nil {
		t.Error("subject.Engine() returned nil")
	}

	// 4. Clean shutdown and idempotence
	if err := subject.Stop(); err != nil {
		t.Fatalf("subject.Stop() failed: %v", err)
	}
	if _, err := os.Stat(readyPath); !os.IsNotExist(err) {
		t.Errorf("subject.ready should have been removed on stop, err: %v", err)
	}
	// Verify double stop is idempotent
	if err := subject.Stop(); err != nil {
		t.Errorf("second subject.Stop() returned error: %v", err)
	}
}

// TestQualificationSubject_Transitions verifies that:
// 1. Specifying the obsolete "custom" engine is rejected fail-closed.
// 2. Multi-stage restarts in upstream mode with ReuseDB preserve frozen client configs and readiness.
func TestQualificationSubject_Transitions(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "panel_test.db")
	configPath := filepath.Join(tempDir, "frozen-client.conf")
	readyPath := filepath.Join(tempDir, "subject.ready")

	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen ephemeral udp: %v", err)
	}
	listenPort := socket.LocalAddr().(*net.UDPAddr).Port
	_ = socket.Close()

	// Step 0: Custom engine must fail closed
	cfgCustom := QualificationSubjectConfig{
		DBPath:           dbPath,
		FrozenConfigPath: configPath,
		ReadyPath:        readyPath,
		ListenPort:       listenPort,
		EchoPort:         40001,
		UnderlayHostIP:   "10.254.250.1",
		DestinationIP:    "10.100.0.1",
		Engine:           "custom",
	}
	if _, err := NewQualificationSubject(cfgCustom); err == nil {
		t.Fatal("expected error requesting custom engine on QualificationSubject, got nil")
	}

	// Step 1: Start Leg 1 in Upstream Engine Mode (fresh DB)
	cfg1 := QualificationSubjectConfig{
		DBPath:           dbPath,
		FrozenConfigPath: configPath,
		ReadyPath:        readyPath,
		ListenPort:       listenPort,
		EchoPort:         40001,
		UnderlayHostIP:   "10.254.250.1",
		DestinationIP:    "10.100.0.1",
		Engine:           "upstream",
		ReuseDB:          false,
	}

	sub1, err := NewQualificationSubject(cfg1)
	if err != nil {
		t.Fatalf("NewQualificationSubject upstream leg 1 failed: %v", err)
	}
	if sub1.Engine() == nil {
		t.Error("expected sub1 IngressEngine to be initialized")
	}

	confBytes1, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read frozen-client.conf leg 1: %v", err)
	}
	readyBytes1, err := os.ReadFile(readyPath)
	if err != nil {
		t.Fatalf("read subject.ready leg 1: %v", err)
	}
	var ready1 map[string]any
	if err := json.Unmarshal(readyBytes1, &ready1); err != nil {
		t.Fatalf("unmarshal ready 1: %v", err)
	}
	if ready1["engine"] != "upstream" {
		t.Errorf("leg 1 ready engine = %v, want upstream", ready1["engine"])
	}

	if err := sub1.Stop(); err != nil {
		t.Fatalf("sub1.Stop failed: %v", err)
	}

	// Step 2: Restart Leg 2 in Upstream Engine Mode with ReuseDB = true
	cfg2 := QualificationSubjectConfig{
		DBPath:           dbPath,
		FrozenConfigPath: configPath,
		ReadyPath:        readyPath,
		ListenPort:       listenPort,
		EchoPort:         40001,
		UnderlayHostIP:   "10.254.250.1",
		DestinationIP:    "10.100.0.1",
		Engine:           "upstream",
		ReuseDB:          true,
	}

	sub2, err := NewQualificationSubject(cfg2)
	if err != nil {
		t.Fatalf("NewQualificationSubject upstream with ReuseDB leg 2 failed: %v", err)
	}
	if sub2.Engine() == nil {
		t.Error("expected sub2 IngressEngine to be initialized")
	}

	confBytes2, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read frozen-client.conf leg 2: %v", err)
	}
	if string(confBytes1) != string(confBytes2) {
		t.Fatal("frozen-client.conf mutated during restart to upstream leg 2")
	}

	readyBytes2, err := os.ReadFile(readyPath)
	if err != nil {
		t.Fatalf("read subject.ready leg 2: %v", err)
	}
	var ready2 map[string]any
	if err := json.Unmarshal(readyBytes2, &ready2); err != nil {
		t.Fatalf("unmarshal ready 2: %v", err)
	}
	if ready2["engine"] != "upstream" {
		t.Errorf("leg 2 ready engine = %v, want upstream", ready2["engine"])
	}

	if err := sub2.Stop(); err != nil {
		t.Fatalf("sub2.Stop failed: %v", err)
	}

	// Step 3: Restart Leg 3 in Upstream Engine Mode with ReuseDB = true
	cfg3 := QualificationSubjectConfig{
		DBPath:           dbPath,
		FrozenConfigPath: configPath,
		ReadyPath:        readyPath,
		ListenPort:       listenPort,
		EchoPort:         40001,
		UnderlayHostIP:   "10.254.250.1",
		DestinationIP:    "10.100.0.1",
		Engine:           "upstream",
		ReuseDB:          true,
	}

	sub3, err := NewQualificationSubject(cfg3)
	if err != nil {
		t.Fatalf("NewQualificationSubject upstream with ReuseDB leg 3 failed: %v", err)
	}
	if sub3.Engine() == nil {
		t.Error("expected sub3 IngressEngine to be initialized")
	}

	confBytes3, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read frozen-client.conf leg 3: %v", err)
	}
	if string(confBytes1) != string(confBytes3) {
		t.Fatal("frozen-client.conf mutated during restart to upstream leg 3")
	}

	readyBytes3, err := os.ReadFile(readyPath)
	if err != nil {
		t.Fatalf("read subject.ready leg 3: %v", err)
	}
	var ready3 map[string]any
	if err := json.Unmarshal(readyBytes3, &ready3); err != nil {
		t.Fatalf("unmarshal ready 3: %v", err)
	}
	if ready3["engine"] != "upstream" {
		t.Errorf("leg 3 ready engine = %v, want upstream", ready3["engine"])
	}

	if err := sub3.Stop(); err != nil {
		t.Fatalf("sub3.Stop failed: %v", err)
	}
}
