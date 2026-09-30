package vpn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDifferential_DependencyPinningAndEnvironment verifies exact upstream module and version pinning
// and captures environment details (Go version, OS, arch, Nexus commit).
func TestDifferential_DependencyPinningAndEnvironment(t *testing.T) {
	repoRoot, err := FindRepoRoot()
	if err != nil {
		t.Fatalf("FindRepoRoot failed: %v", err)
	}

	manifest, err := VerifyEnvironmentAndDependencies(repoRoot)
	if err != nil {
		t.Fatalf("VerifyEnvironmentAndDependencies failed: %v", err)
	}

	if manifest.UpstreamAWGModule != ExpectedUpstreamAWGModule {
		t.Errorf("upstream AWG module = %q, want %q", manifest.UpstreamAWGModule, ExpectedUpstreamAWGModule)
	}
	if manifest.UpstreamAWGVer != ExpectedUpstreamAWGVersion {
		t.Errorf("upstream AWG version = %q, want %q", manifest.UpstreamAWGVer, ExpectedUpstreamAWGVersion)
	}
	if manifest.NexusVersion == "" {
		t.Error("NexusVersion is empty in environment manifest")
	}
	if manifest.GoVersion == "" {
		t.Error("GoVersion is empty in environment manifest")
	}
	if manifest.OS == "" {
		t.Error("OS is empty in environment manifest")
	}
	if manifest.Arch == "" {
		t.Error("Arch is empty in environment manifest")
	}

	t.Logf("Environment pinned: Go=%s OS=%s Arch=%s Nexus=%s Commit=%s Upstream=%s@%s",
		manifest.GoVersion, manifest.OS, manifest.Arch, manifest.NexusVersion, manifest.NexusCommit,
		manifest.UpstreamAWGModule, manifest.UpstreamAWGVer)

	// Negative subtest: fail-fast on version mismatch
	t.Run("FailFastOnVersionMismatch", func(t *testing.T) {
		tempDir := t.TempDir()
		dummyGoMod := fmt.Sprintf("module test\n\ngo 1.26\n\nrequire %s v3.0.0\n", ExpectedUpstreamAWGModule)
		if err := os.WriteFile(filepath.Join(tempDir, "go.mod"), []byte(dummyGoMod), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := VerifyEnvironmentAndDependencies(tempDir)
		if err == nil {
			t.Fatal("expected failure on upstream AWG version mismatch, got nil")
		}
		if !strings.Contains(err.Error(), "mismatch") {
			t.Errorf("expected version mismatch error, got: %v", err)
		}
	})
}

// TestDifferential_ConfigFreezingAndRedactedManifest validates frozen config hashing,
// redacted manifest generation, and strict privacy invariant enforcement.
func TestDifferential_ConfigFreezingAndRedactedManifest(t *testing.T) {
	harness := NewDifferentialHarness(t)

	if harness.rawClientConfig == "" {
		t.Fatal("frozen rawClientConfig is empty")
	}

	expectedHash := sha256.Sum256([]byte(harness.rawClientConfig))
	expectedHashHex := hex.EncodeToString(expectedHash[:])
	if harness.frozenHash != expectedHashHex {
		t.Fatalf("frozen hash = %q, want %q", harness.frozenHash, expectedHashHex)
	}

	manifest := harness.manifest
	if err := manifest.ValidatePrivacy(); err != nil {
		t.Fatalf("manifest privacy validation failed: %v", err)
	}

	if manifest.RenderedConfigHash != harness.frozenHash {
		t.Errorf("manifest hash = %q, want %q", manifest.RenderedConfigHash, harness.frozenHash)
	}
	if manifest.ClientPublicKey != harness.clientPeer.PublicKey {
		t.Errorf("manifest ClientPublicKey = %q, want %q", manifest.ClientPublicKey, harness.clientPeer.PublicKey)
	}
	if manifest.AssignedIP != harness.clientPeer.AllowedIP.Addr().String() {
		t.Errorf("manifest AssignedIP = %q, want %q", manifest.AssignedIP, harness.clientPeer.AllowedIP.Addr().String())
	}
	if manifest.ServerPort != harness.listenPort {
		t.Errorf("manifest ServerPort = %d, want %d", manifest.ServerPort, harness.listenPort)
	}
	if !strings.HasPrefix(manifest.ServerEndpoint, "<redacted-ip>:") {
		t.Errorf("manifest ServerEndpoint = %q, expected <redacted-ip>:port", manifest.ServerEndpoint)
	}
	if manifest.HeaderProtection != "<present-32B>" {
		t.Errorf("manifest HeaderProtection = %q, want <present-32B>", manifest.HeaderProtection)
	}
	if manifest.S1 != 50 || manifest.S2 != 100 || manifest.S3 != 150 || manifest.S4 != 200 {
		t.Errorf("manifest S1..S4 mismatch: S1=%d S2=%d S3=%d S4=%d", manifest.S1, manifest.S2, manifest.S3, manifest.S4)
	}
	if manifest.PersistentKeepalive == "" {
		t.Error("manifest PersistentKeepalive is empty")
	}

	// Privacy defense tests: verify rejection of unredacted secrets or server IPs
	t.Run("PrivacyRejectsPrivateKey", func(t *testing.T) {
		bad := *manifest
		bad.H1 = "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		if err := bad.ValidatePrivacy(); err == nil {
			t.Error("expected error for unredacted PrivateKey in manifest")
		}
	})

	t.Run("PrivacyRejectsUnredactedServerIP", func(t *testing.T) {
		bad := *manifest
		bad.ServerEndpoint = "198.51.100.1:51820"
		if err := bad.ValidatePrivacy(); err == nil {
			t.Error("expected error for unredacted server IP in manifest")
		}
	})

	t.Run("PrivacyRejectsRawHeaderProtectionKey", func(t *testing.T) {
		bad := *manifest
		bad.HeaderProtection = "raw-secret-key-32-bytes-long-here"
		if err := bad.ValidatePrivacy(); err == nil {
			t.Error("expected error for unredacted header protection key")
		}
	})

	t.Run("PrivacyRejectsFilesystemPaths", func(t *testing.T) {
		bad := *manifest
		bad.H1 = "/" + "home" + "/user/nexus/config"
		if err := bad.ValidatePrivacy(); err == nil {
			t.Error("expected error for local filesystem path in manifest")
		}
	})

	// Generate and write checked-in compatibility evidence manifest
	repoRoot, err := FindRepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	envManifest, err := VerifyEnvironmentAndDependencies(repoRoot)
	if err != nil {
		t.Fatal(err)
	}

	evidenceManifest := CompatibilityEvidenceManifest{
		SchemaVersion: "1.0.0",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Environment:   *envManifest,
		FrozenConfig:  *manifest,
	}

	if err := evidenceManifest.ValidatePrivacy(); err != nil {
		t.Fatalf("full evidence manifest privacy validation failed: %v", err)
	}

	evidenceJSON, err := json.MarshalIndent(evidenceManifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	taskArtifactPath := filepath.Join(repoRoot, "tasks", "issue-392-differential-compatibility", "evidence_manifest.json")
	if err := os.MkdirAll(filepath.Dir(taskArtifactPath), 0o755); err != nil {
		t.Fatalf("failed to create directory for evidence manifest: %v", err)
	}
	if err := os.WriteFile(taskArtifactPath, evidenceJSON, 0o600); err != nil {
		t.Fatalf("failed to write evidence manifest to %s: %v", taskArtifactPath, err)
	}
	if customDir := os.Getenv("NEXUS_ARTIFACT_DIR"); customDir != "" {
		if !filepath.IsAbs(customDir) {
			customDir = filepath.Join(repoRoot, customDir)
		}
		_ = os.MkdirAll(customDir, 0o755)
		customPath := filepath.Join(customDir, "evidence_manifest.json")
		if err := os.WriteFile(customPath, evidenceJSON, 0o600); err != nil {
			t.Logf("warning: failed to write custom evidence manifest to %s: %v", customPath, err)
		}
	}
}

// TestDifferential_SequentialReferenceVsSubjectBaseline runs reference server, connects client,
// verifies echo and handshake, cleanly shuts down, then runs Nexus subject server on the same port
// reusing the same frozen client configuration, and asserts exact outcome parity and zero drops.
func TestDifferential_SequentialReferenceVsSubjectBaseline(t *testing.T) {
	harness := NewDifferentialHarness(t)
	ctx := t.Context()

	tcpTestPayload := []byte("differential-baseline-tcp-streaming-payload-12345")
	udpSeqCount := 5
	udpTestPayloads := make([][]byte, udpSeqCount)
	for i := 0; i < udpSeqCount; i++ {
		udpTestPayloads[i] = []byte(fmt.Sprintf("differential-baseline-udp-seq-%04d", i+1))
	}

	// ==========================================
	// Phase 1: Reference Standalone Upstream AWG Server
	// ==========================================
	t.Log("Starting Reference Server...")
	refServer, err := harness.StartReferenceServer()
	if err != nil {
		t.Fatalf("StartReferenceServer failed: %v", err)
	}
	t.Log("Reference Server started")

	t.Log("Creating Reference Client...")
	refClient, err := harness.NewClient()
	if err != nil {
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("refClient NewClient failed: %v", err)
	}
	t.Log("Reference Client created")

	// 1a. TCP echo
	t.Log("Dialing TCP on Reference Server...")
	dialCtx, cancelDial := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancelDial()
	refTCPConn, err := refClient.DialTCP(dialCtx)
	if err != nil {
		_ = refClient.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("refClient DialTCP failed: %v", err)
	}
	t.Log("TCP connected on Reference Server. Exchanging TCP echo...")
	refTCPEcho, err := refClient.ExchangeTCP(refTCPConn, tcpTestPayload)
	_ = refTCPConn.Close()
	if err != nil {
		_ = refClient.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("refClient ExchangeTCP failed: %v", err)
	}
	t.Log("TCP echo exchange completed on Reference Server")
	if !bytes.Equal(tcpTestPayload, refTCPEcho) {
		_ = refClient.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("refClient TCP echo mismatch: got %q, want %q", refTCPEcho, tcpTestPayload)
	}

	// 1b. Sequenced UDP echo
	refUDPConn, err := refClient.DialUDP()
	if err != nil {
		_ = refClient.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("refClient DialUDP failed: %v", err)
	}
	refUDPEchoes := make([][]byte, udpSeqCount)
	for i := 0; i < udpSeqCount; i++ {
		echo, err := refClient.ExchangeUDP(refUDPConn, udpTestPayloads[i])
		if err != nil {
			_ = refUDPConn.Close()
			_ = refClient.Close()
			_ = harness.StopReferenceServer(refServer)
			t.Fatalf("refClient ExchangeUDP seq %d failed: %v", i+1, err)
		}
		refUDPEchoes[i] = echo
		if !bytes.Equal(udpTestPayloads[i], echo) {
			_ = refUDPConn.Close()
			_ = refClient.Close()
			_ = harness.StopReferenceServer(refServer)
			t.Fatalf("refClient UDP seq %d mismatch: got %q, want %q", i+1, echo, udpTestPayloads[i])
		}
	}
	_ = refUDPConn.Close()

	if refClient.LastHandshakeTime().IsZero() {
		_ = refClient.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatal("refClient recorded zero handshake time")
	}

	// Clean reference teardown
	if err := refClient.Close(); err != nil {
		t.Fatalf("refClient Close failed: %v", err)
	}
	if err := harness.StopReferenceServer(refServer); err != nil {
		t.Fatalf("StopReferenceServer failed: %v", err)
	}

	// Assert port is completely free before subject binds
	harness.AssertPortFree(5 * time.Second)

	// ==========================================
	// Phase 2: Subject Server (Nexus IngressEngine)
	// ==========================================
	subServer, err := harness.StartSubjectServer()
	if err != nil {
		t.Fatalf("StartSubjectServer failed: %v", err)
	}

	// Client reuses the EXACT SAME frozen client config without reissuing credentials
	subClient, err := harness.NewClient()
	if err != nil {
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("subClient NewClient failed: %v", err)
	}

	// 2a. TCP echo
	subTCPConn, err := subClient.DialTCP(ctx)
	if err != nil {
		_ = subClient.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("subClient DialTCP failed: %v", err)
	}
	subTCPEcho, err := subClient.ExchangeTCP(subTCPConn, tcpTestPayload)
	_ = subTCPConn.Close()
	if err != nil {
		_ = subClient.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("subClient ExchangeTCP failed: %v", err)
	}
	if !bytes.Equal(tcpTestPayload, subTCPEcho) {
		_ = subClient.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("subClient TCP echo mismatch: got %q, want %q", subTCPEcho, tcpTestPayload)
	}

	// 2b. Sequenced UDP echo
	subUDPConn, err := subClient.DialUDP()
	if err != nil {
		_ = subClient.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("subClient DialUDP failed: %v", err)
	}
	subUDPEchoes := make([][]byte, udpSeqCount)
	for i := 0; i < udpSeqCount; i++ {
		echo, err := subClient.ExchangeUDP(subUDPConn, udpTestPayloads[i])
		if err != nil {
			_ = subUDPConn.Close()
			_ = subClient.Close()
			_ = harness.StopSubjectServer(subServer)
			t.Fatalf("subClient ExchangeUDP seq %d failed: %v", i+1, err)
		}
		subUDPEchoes[i] = echo
		if !bytes.Equal(udpTestPayloads[i], echo) {
			_ = subUDPConn.Close()
			_ = subClient.Close()
			_ = harness.StopSubjectServer(subServer)
			t.Fatalf("subClient UDP seq %d mismatch: got %q, want %q", i+1, echo, udpTestPayloads[i])
		}
	}
	_ = subUDPConn.Close()

	if subClient.LastHandshakeTime().IsZero() {
		_ = subClient.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatal("subClient recorded zero handshake time")
	}

	// Assert zero routing drops on Nexus
	routerStats := subServer.engine.Router().StatsSnapshot()
	if routerStats.MalformedPacketDrops != 0 {
		t.Errorf("router MalformedPacketDrops = %d, want 0", routerStats.MalformedPacketDrops)
	}
	if routerStats.UnmappedSourceIPDrops != 0 {
		t.Errorf("router UnmappedSourceIPDrops = %d, want 0", routerStats.UnmappedSourceIPDrops)
	}
	if routerStats.OwnershipMismatchDrops != 0 {
		t.Errorf("router OwnershipMismatchDrops = %d, want 0", routerStats.OwnershipMismatchDrops)
	}
	if routerStats.AdmissionRejectedDrops != 0 {
		t.Errorf("router AdmissionRejectedDrops = %d, want 0", routerStats.AdmissionRejectedDrops)
	}

	queueFull, noRoute, _ := harness.svc.forwarder.DropStats()
	if queueFull != 0 || noRoute != 0 {
		t.Errorf("forwarder drops: queueFull=%d noRoute=%d, want 0", queueFull, noRoute)
	}

	retStats := subServer.engine.ReturnStats()
	if retStats.MalformedDrops != 0 || retStats.UnmappedDrops != 0 || retStats.OwnershipMismatchDrops != 0 {
		t.Errorf("return drops: %+v, want all 0", retStats)
	}

	// Clean subject teardown
	if err := subClient.Close(); err != nil {
		t.Fatalf("subClient Close failed: %v", err)
	}
	if err := harness.StopSubjectServer(subServer); err != nil {
		t.Fatalf("StopSubjectServer failed: %v", err)
	}
	harness.AssertPortFree(5 * time.Second)

	// ==========================================
	// Phase 3: Differential Outcome Parity Comparison
	// ==========================================
	if !bytes.Equal(refTCPEcho, subTCPEcho) {
		t.Fatalf("TCP echo mismatch between reference and subject: ref=%q sub=%q", refTCPEcho, subTCPEcho)
	}
	for i := 0; i < udpSeqCount; i++ {
		if !bytes.Equal(refUDPEchoes[i], subUDPEchoes[i]) {
			t.Fatalf("UDP seq %d echo mismatch between reference and subject: ref=%q sub=%q", i+1, refUDPEchoes[i], subUDPEchoes[i])
		}
	}
}

// TestCompatibility_SubjectServerRestart verifies that when the subject engine restarts
// with the same DB and rendered config, the client re-establishes connection and resumes traffic.
func TestCompatibility_SubjectServerRestart(t *testing.T) {
	harness := NewDifferentialHarness(t)
	ctx := t.Context()

	subServer, err := harness.StartSubjectServer()
	if err != nil {
		t.Fatalf("StartSubjectServer failed: %v", err)
	}

	client, err := harness.NewClient()
	if err != nil {
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("NewClient failed: %v", err)
	}

	// Pre-restart communication
	tcpPayload := []byte("pre-restart-tcp-payload")
	cConn, err := client.DialTCP(ctx)
	if err != nil {
		_ = client.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("pre-restart DialTCP failed: %v", err)
	}
	echo, err := client.ExchangeTCP(cConn, tcpPayload)
	_ = cConn.Close()
	if err != nil || !bytes.Equal(tcpPayload, echo) {
		_ = client.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("pre-restart ExchangeTCP failed: %v, got %q", err, echo)
	}
	_ = client.Close()

	// Engine Restart on the same port with same DB and config
	subServer, err = harness.RestartSubjectServer(subServer)
	if err != nil {
		t.Fatalf("RestartSubjectServer failed: %v", err)
	}
	defer func() {
		_ = harness.StopSubjectServer(subServer)
	}()

	// Post-restart connection re-establishment using the EXACT same frozen configuration
	client2, err := harness.NewClient()
	if err != nil {
		t.Fatalf("post-restart NewClient failed: %v", err)
	}
	defer func() {
		_ = client2.Close()
	}()

	postTCPPayload := []byte("post-restart-resumed-tcp-payload")
	cConn2, err := client2.DialTCP(ctx)
	if err != nil {
		t.Fatalf("post-restart DialTCP failed: %v", err)
	}
	defer func() {
		_ = cConn2.Close()
	}()

	postEcho, err := client2.ExchangeTCP(cConn2, postTCPPayload)
	if err != nil || !bytes.Equal(postTCPPayload, postEcho) {
		t.Fatalf("post-restart ExchangeTCP failed: %v, got %q", err, postEcho)
	}

	postUDPPayload := []byte("post-restart-resumed-udp-payload")
	uConn2, err := client2.DialUDP()
	if err != nil {
		t.Fatalf("post-restart DialUDP failed: %v", err)
	}
	defer func() {
		_ = uConn2.Close()
	}()

	postUDPEcho, err := client2.ExchangeUDP(uConn2, postUDPPayload)
	if err != nil || !bytes.Equal(postUDPPayload, postUDPEcho) {
		t.Fatalf("post-restart ExchangeUDP failed: %v, got %q", err, postUDPEcho)
	}

	if client2.LastHandshakeTime().IsZero() {
		t.Fatal("client2 recorded zero handshake time after server restart")
	}

	// Verify zero drops on restarted engine
	routerStats := subServer.engine.Router().StatsSnapshot()
	if routerStats.MalformedPacketDrops != 0 || routerStats.UnmappedSourceIPDrops != 0 || routerStats.OwnershipMismatchDrops != 0 {
		t.Errorf("router drops on restarted engine: %+v", routerStats)
	}
}

// TestCompatibility_BidirectionalEchoComparison verifies high-volume streaming TCP
// and sequenced UDP datagram parity between Reference Server and Nexus Subject Server.
func TestCompatibility_BidirectionalEchoComparison(t *testing.T) {
	harness := NewDifferentialHarness(t)
	ctx := t.Context()

	// 8 KB streaming payload
	streamingPayload := make([]byte, 8192)
	for i := range streamingPayload {
		streamingPayload[i] = byte((i * 31) % 256)
	}

	// Sequenced UDP datagrams
	const numUDP = 10
	udpPayloads := make([][]byte, numUDP)
	for i := 0; i < numUDP; i++ {
		udpPayloads[i] = make([]byte, 128)
		_, _ = rand.Read(udpPayloads[i])
		// Embed sequence header
		udpPayloads[i][0] = byte(i)
	}

	// 1. Run on Reference Server
	refServer, err := harness.StartReferenceServer()
	if err != nil {
		t.Fatalf("StartReferenceServer: %v", err)
	}
	refClient, err := harness.NewClient()
	if err != nil {
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("refClient NewClient: %v", err)
	}

	refTCPConn, err := refClient.DialTCP(ctx)
	if err != nil {
		_ = refClient.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("ref TCP dial: %v", err)
	}
	refStreamEcho, err := refClient.ExchangeTCP(refTCPConn, streamingPayload)
	_ = refTCPConn.Close()
	if err != nil || !bytes.Equal(streamingPayload, refStreamEcho) {
		_ = refClient.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("ref streaming TCP exchange failed: %v", err)
	}

	refUDPConn, err := refClient.DialUDP()
	if err != nil {
		_ = refClient.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("ref UDP dial: %v", err)
	}
	refUDPEchoes := make([][]byte, numUDP)
	for i := 0; i < numUDP; i++ {
		echo, err := refClient.ExchangeUDP(refUDPConn, udpPayloads[i])
		if err != nil || !bytes.Equal(udpPayloads[i], echo) {
			_ = refUDPConn.Close()
			_ = refClient.Close()
			_ = harness.StopReferenceServer(refServer)
			t.Fatalf("ref UDP seq %d exchange failed: %v", i, err)
		}
		refUDPEchoes[i] = echo
	}
	_ = refUDPConn.Close()
	_ = refClient.Close()
	_ = harness.StopReferenceServer(refServer)
	harness.AssertPortFree(5 * time.Second)

	// 2. Run on Subject Server (Nexus)
	subServer, err := harness.StartSubjectServer()
	if err != nil {
		t.Fatalf("StartSubjectServer: %v", err)
	}
	subClient, err := harness.NewClient()
	if err != nil {
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("subClient NewClient: %v", err)
	}

	subTCPConn, err := subClient.DialTCP(ctx)
	if err != nil {
		_ = subClient.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("sub TCP dial: %v", err)
	}
	subStreamEcho, err := subClient.ExchangeTCP(subTCPConn, streamingPayload)
	_ = subTCPConn.Close()
	if err != nil || !bytes.Equal(streamingPayload, subStreamEcho) {
		_ = subClient.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("sub streaming TCP exchange failed: %v", err)
	}

	subUDPConn, err := subClient.DialUDP()
	if err != nil {
		_ = subClient.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("sub UDP dial: %v", err)
	}
	subUDPEchoes := make([][]byte, numUDP)
	for i := 0; i < numUDP; i++ {
		echo, err := subClient.ExchangeUDP(subUDPConn, udpPayloads[i])
		if err != nil || !bytes.Equal(udpPayloads[i], echo) {
			_ = subUDPConn.Close()
			_ = subClient.Close()
			_ = harness.StopSubjectServer(subServer)
			t.Fatalf("sub UDP seq %d exchange failed: %v", i, err)
		}
		subUDPEchoes[i] = echo
	}
	_ = subUDPConn.Close()
	_ = subClient.Close()
	_ = harness.StopSubjectServer(subServer)
	harness.AssertPortFree(5 * time.Second)

	// 3. Compare Parity
	if !bytes.Equal(refStreamEcho, subStreamEcho) {
		t.Fatal("streaming TCP echo differs between reference and subject")
	}
	for i := 0; i < numUDP; i++ {
		if !bytes.Equal(refUDPEchoes[i], subUDPEchoes[i]) {
			t.Fatalf("UDP seq %d echo differs between reference and subject", i)
		}
	}
}
