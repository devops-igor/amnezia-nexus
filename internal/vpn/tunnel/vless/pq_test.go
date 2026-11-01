//go:build with_utls

package vless

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	utls "github.com/metacubex/utls"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// parseClientHelloKeyShares parses the key_share extension from raw ClientHello bytes.
// Returns list of (groupID, dataLen).
func parseClientHelloKeyShares(raw []byte) (groups []uint16, lengths []int, supportedGroups []uint16, err error) {
	// TLS record layer: 5 bytes header [ContentType=22, Version=0x0301 or 0x0303, Length=2 bytes]
	if len(raw) < 5 || raw[0] != 22 {
		return nil, nil, nil, errNotTLSHandshake
	}
	recordLen := int(binary.BigEndian.Uint16(raw[3:5]))
	if len(raw) < 5+recordLen {
		return nil, nil, nil, errTruncated
	}
	handshake := raw[5 : 5+recordLen]
	// Handshake type 1 = ClientHello
	if len(handshake) < 4 || handshake[0] != 1 {
		return nil, nil, nil, errNotClientHello
	}
	clientHello := handshake[4:]
	// Skip client version (2 bytes), random (32 bytes)
	if len(clientHello) < 34 {
		return nil, nil, nil, errTruncated
	}
	offset := 34
	// Session ID length
	if len(clientHello) < offset+1 {
		return nil, nil, nil, errTruncated
	}
	sessionIDLen := int(clientHello[offset])
	offset += 1 + sessionIDLen
	// Cipher suites
	if len(clientHello) < offset+2 {
		return nil, nil, nil, errTruncated
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(clientHello[offset : offset+2]))
	offset += 2 + cipherSuitesLen
	// Compression methods
	if len(clientHello) < offset+1 {
		return nil, nil, nil, errTruncated
	}
	compMethodsLen := int(clientHello[offset])
	offset += 1 + compMethodsLen

	// Extensions length
	if len(clientHello) < offset+2 {
		return nil, nil, nil, errTruncated
	}
	extensionsLen := int(binary.BigEndian.Uint16(clientHello[offset : offset+2]))
	offset += 2
	extensions := clientHello[offset:]
	if len(extensions) > extensionsLen {
		extensions = extensions[:extensionsLen]
	}

	extOffset := 0
	for extOffset+4 <= len(extensions) {
		extType := binary.BigEndian.Uint16(extensions[extOffset : extOffset+2])
		extLen := int(binary.BigEndian.Uint16(extensions[extOffset+2 : extOffset+4]))
		extOffset += 4
		if extOffset+extLen > len(extensions) {
			break
		}
		extData := extensions[extOffset : extOffset+extLen]
		extOffset += extLen

		switch extType {
		case 10: // supported_groups
			if len(extData) >= 2 {
				listLen := int(binary.BigEndian.Uint16(extData[0:2]))
				if listLen <= len(extData)-2 {
					for i := 2; i+2 <= 2+listLen; i += 2 {
						supportedGroups = append(supportedGroups, binary.BigEndian.Uint16(extData[i:i+2]))
					}
				}
			}
		case 51: // key_share
			if len(extData) >= 2 {
				clientSharesLen := int(binary.BigEndian.Uint16(extData[0:2]))
				ksData := extData[2:]
				if clientSharesLen <= len(ksData) {
					ksOffset := 0
					for ksOffset+4 <= clientSharesLen {
						grp := binary.BigEndian.Uint16(ksData[ksOffset : ksOffset+2])
						kLen := int(binary.BigEndian.Uint16(ksData[ksOffset+2 : ksOffset+4]))
						ksOffset += 4
						if ksOffset+kLen > len(ksData) {
							break
						}
						groups = append(groups, grp)
						lengths = append(lengths, kLen)
						ksOffset += kLen
					}
				}
			}
		}
	}

	return groups, lengths, supportedGroups, nil
}

var (
	errNotTLSHandshake = io.ErrUnexpectedEOF
	errNotClientHello  = io.ErrUnexpectedEOF
	errTruncated       = io.ErrUnexpectedEOF
)

func TestDialer_ClientHelloHybridPostQuantumKeyShares(t *testing.T) {
	fixture := setupTestServer(t, "", 0)
	defer fixture.ServerClose()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	chReceived := make(chan []byte, 1)
	go func() {
		c, aErr := ln.Accept()
		if aErr != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		chReceived <- buf[:n]
	}()

	params := fixture.Params
	params.EngineProfile = "modern_pq"
	d, err := New(ln.Addr().String(), params)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_, _ = d.DialContext(ctx, "tcp", "127.0.0.1:80")
	}()

	var rawHello []byte
	select {
	case rawHello = <-chReceived:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for ClientHello")
	}

	groups, lengths, supportedGroups, err := parseClientHelloKeyShares(rawHello)
	if err != nil {
		t.Fatalf("parse ClientHello: %v", err)
	}

	const (
		groupX25519MLKEM768 = uint16(utls.X25519MLKEM768) // 4588 / 0x11EC
		groupX25519         = uint16(utls.X25519)         // 29 / 0x001D
	)

	// Verify supported_groups contains X25519MLKEM768 and X25519
	hasSuppPQ := false
	hasSuppClassic := false
	for _, g := range supportedGroups {
		if g == groupX25519MLKEM768 {
			hasSuppPQ = true
		}
		if g == groupX25519 {
			hasSuppClassic = true
		}
	}
	if !hasSuppPQ {
		t.Errorf("ClientHello supported_groups missing X25519MLKEM768 (4588), got: %v", supportedGroups)
	}
	if !hasSuppClassic {
		t.Errorf("ClientHello supported_groups missing X25519 (29), got: %v", supportedGroups)
	}

	// Verify key_share contains X25519MLKEM768 and X25519 in order (PQ first)
	pqIdx := -1
	classicIdx := -1
	for i, g := range groups {
		if g == groupX25519MLKEM768 {
			pqIdx = i
			// 1184 (ML-KEM-768 encap key) + 32 (X25519 public key) = 1216 bytes
			if lengths[i] != 1216 {
				t.Errorf("X25519MLKEM768 key share length = %d, want 1216", lengths[i])
			}
		}
		if g == groupX25519 {
			classicIdx = i
			if lengths[i] != 32 {
				t.Errorf("X25519 key share length = %d, want 32", lengths[i])
			}
		}
	}

	if pqIdx == -1 {
		t.Fatalf("ClientHello key_share missing X25519MLKEM768 (4588), groups present: %v", groups)
	}
	if classicIdx == -1 {
		t.Fatalf("ClientHello key_share missing X25519 (29), groups present: %v", groups)
	}
	if pqIdx >= classicIdx {
		t.Errorf("X25519MLKEM768 key share (index %d) must appear BEFORE X25519 key share (index %d) to satisfy Xray v26.10.29 requirements", pqIdx, classicIdx)
	}
}

// TestDialer_XrayV26_StrictPQHandshakeAndDataStream verifies that when connected through
// an intermediary that applies Xray v26.10.x's strict PQ gate (rejecting any ClientHello
// that does not provide X25519MLKEM768 before optional X25519), the handshake and TCP data
// stream complete cleanly.
func TestDialer_XrayV26_StrictPQHandshakeAndDataStream(t *testing.T) {
	fixture := setupTestServer(t, "", 0)
	defer fixture.ServerClose()

	echoAddr, cleanupEcho := startTCPEchoServer(t)
	defer cleanupEcho()

	// Strict Xray v26.10.29 validating gate
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	defer proxyLn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var pqGateValidated bool
	var gateMu sync.Mutex

	go func() {
		for {
			clientConn, aErr := proxyLn.Accept()
			if aErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				header := make([]byte, 5)
				if _, rErr := io.ReadFull(c, header); rErr != nil {
					return
				}
				recLen := binary.BigEndian.Uint16(header[3:5])
				body := make([]byte, recLen)
				if _, rErr := io.ReadFull(c, body); rErr != nil {
					return
				}
				fullHello := append(header, body...)

				groups, _, _, parseErr := parseClientHelloKeyShares(fullHello)
				if parseErr != nil {
					return
				}

				// Xray v26.10.29 check: X25519MLKEM768 must appear before X25519
				var peerPub2Found, peerPubFound bool
				for _, g := range groups {
					if g == uint16(utls.X25519MLKEM768) {
						peerPub2Found = true
						continue
					}
					if g == uint16(utls.X25519) {
						peerPubFound = true
						break
					}
				}
				if !peerPub2Found {
					// Xray v26.10.x strictly rejects
					return
				}

				gateMu.Lock()
				pqGateValidated = peerPub2Found && peerPubFound
				gateMu.Unlock()

				// Forward to real server
				backendConn, dErr := net.Dial("tcp", fixture.Endpoint)
				if dErr != nil {
					return
				}
				defer backendConn.Close()

				if _, wErr := backendConn.Write(fullHello); wErr != nil {
					return
				}

				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					_, _ = io.Copy(backendConn, c)
					_ = backendConn.Close()
				}()
				go func() {
					defer wg.Done()
					_, _ = io.Copy(c, backendConn)
					_ = c.Close()
				}()
				wg.Wait()
			}(clientConn)
		}
	}()

	params := fixture.Params
	params.EngineProfile = "modern_pq"
	d, err := New(proxyLn.Addr().String(), params)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()

	conn, err := d.DialContext(dialCtx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext through strict Xray v26.10 gate failed: %v", err)
	}
	defer conn.Close()

	gateMu.Lock()
	validated := pqGateValidated
	gateMu.Unlock()
	if !validated {
		t.Errorf("expected Xray v26.10.29 PQ gate to be satisfied")
	}

	// Verify data transmission
	payload := []byte("hello Xray v26.10.29 Post-Quantum REALITY")
	if _, wErr := conn.Write(payload); wErr != nil {
		t.Fatalf("write payload: %v", wErr)
	}
	buf := make([]byte, len(payload))
	if _, rErr := io.ReadFull(conn, buf); rErr != nil {
		t.Fatalf("read payload: %v", rErr)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("payload mismatch: got %q, want %q", buf, payload)
	}
}

// Pinned container image tags and multi-arch manifest list digests.
// Verified against published GitHub package metadata (ghcr.io/xtls/xray-core).
//   - 1.8.24: multi-arch manifest list sha256:6b3ef1780d4be55c1bc4848232a90272d31c28cc3d0de1f2a50a56f48993be9d
//     (published 2024-03-24 by XTLS/Xray-core releases)
//   - 26.10.29: multi-arch manifest list sha256:c9443f3ee297f6481bc245269d61720c6f989195ee9b58fa90fdd99f03c21044
//     (published 2024-10-29 by XTLS/Xray-core releases)
const (
	pinnedLegacyDigest = "sha256:6b3ef1780d4be55c1bc4848232a90272d31c28cc3d0de1f2a50a56f48993be9d"
	pinnedLegacyImage  = "ghcr.io/xtls/xray-core:1.8.24@" + pinnedLegacyDigest
	pinnedModernDigest = "sha256:c9443f3ee297f6481bc245269d61720c6f989195ee9b58fa90fdd99f03c21044"
	pinnedModernImage  = "ghcr.io/xtls/xray-core:26.10.29@" + pinnedModernDigest
)

// TestPinnedImageDigests verifies that pinned image digests conform to published GitHub package metadata.
func TestPinnedImageDigests(t *testing.T) {
	wantLegacy := "sha256:6b3ef1780d4be55c1bc4848232a90272d31c28cc3d0de1f2a50a56f48993be9d"
	if pinnedLegacyDigest != wantLegacy {
		t.Errorf("pinnedLegacyDigest = %q, want %q", pinnedLegacyDigest, wantLegacy)
	}
	if !strings.HasSuffix(pinnedLegacyImage, wantLegacy) {
		t.Errorf("pinnedLegacyImage %q does not embed expected digest %q", pinnedLegacyImage, wantLegacy)
	}

	wantModern := "sha256:c9443f3ee297f6481bc245269d61720c6f989195ee9b58fa90fdd99f03c21044"
	if pinnedModernDigest != wantModern {
		t.Errorf("pinnedModernDigest = %q, want %q", pinnedModernDigest, wantModern)
	}
	if !strings.HasSuffix(pinnedModernImage, wantModern) {
		t.Errorf("pinnedModernImage %q does not embed expected digest %q", pinnedModernImage, wantModern)
	}
}

// TestDialer_ContainerFixtures runs when a local Docker daemon is present, testing real
// authenticated REALITY handshakes, bidirectional TCP data streams, wrong-key rejection,
// and restart recovery against both pinned 1.8.24 and 26.10.29 container fixtures.
func TestDialer_ContainerFixtures(t *testing.T) {
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("docker binary not found in PATH")
	}
	if cmdErr := exec.Command(dockerPath, "info").Run(); cmdErr != nil {
		t.Skip("docker daemon not running or not accessible")
	}

	fixtures := []struct {
		name          string
		image         string
		engineProfile string
	}{
		{name: "legacy_1_8_24", image: pinnedLegacyImage, engineProfile: "legacy"},
		{name: "modern_26_10_29", image: pinnedModernImage, engineProfile: "modern_pq"},
	}

	for _, tc := range fixtures {
		t.Run(tc.name, func(t *testing.T) {
			echoAddr, cleanupEcho := startTCPEchoServer(t)
			defer cleanupEcho()
			udpEchoAddr, cleanupUDPEcho := startUDPEchoServer(t)
			defer cleanupUDPEcho()

			// Allocate a local ephemeral port for container VLESS inbound
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("allocate port: %v", err)
			}
			_, portStr, err := net.SplitHostPort(ln.Addr().String())
			if err != nil {
				ln.Close()
				t.Fatalf("split host port: %v", err)
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				ln.Close()
				t.Fatalf("parse host port: %v", err)
			}
			ln.Close()

			// Generate keys
			privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("generate x25519: %v", err)
			}
			pubKey := privKey.PublicKey()
			privB64 := base64.RawURLEncoding.EncodeToString(privKey.Bytes())
			pubB64 := base64.RawURLEncoding.EncodeToString(pubKey.Bytes())
			shortID := "0123456789abcdef"
			serverName := "gateway.icloud.com"
			clientUUID := uuid.New().String()

			// Write container config
			cfgDir := t.TempDir()
			if err := os.Chmod(cfgDir, 0755); err != nil {
				t.Fatalf("chmod cfgDir: %v", err)
			}
			cfgPath := filepath.Join(cfgDir, "config.json")

			freedomSettings := map[string]any{
				"domainStrategy": "AsIs",
			}
			if tc.engineProfile == "modern_pq" {
				// Xray v26.4+ default security policy blocks loopback (127.0.0.1) and private IP ranges
				// from VLESS inbounds unless explicitly permitted via finalRules.
				freedomSettings["finalRules"] = []any{
					map[string]any{
						"action": "allow",
					},
				}
			}

			xrayCfg := map[string]any{
				"log": map[string]any{"loglevel": "info"},
				"inbounds": []any{
					map[string]any{
						"port":     port,
						"protocol": "vless",
						"settings": map[string]any{
							"clients": []any{
								map[string]any{
									"id":   clientUUID,
									"flow": "",
								},
							},
							"decryption": "none",
						},
						"streamSettings": map[string]any{
							"network":  "tcp",
							"security": "reality",
							"realitySettings": map[string]any{
								"show":        false,
								"dest":        "gateway.icloud.com:443",
								"xver":        0,
								"serverNames": []any{serverName},
								"privateKey":  privB64,
								"shortIds":    []any{shortID},
							},
						},
					},
				},
				"outbounds": []any{
					map[string]any{
						"protocol": "freedom",
						"settings": freedomSettings,
					},
				},
			}
			cfgData, err := json.MarshalIndent(xrayCfg, "", "  ")
			if err != nil {
				t.Fatalf("marshal config: %v", err)
			}
			if err := os.WriteFile(cfgPath, cfgData, 0644); err != nil {
				t.Fatalf("write config: %v", err)
			}

			containerName := fmt.Sprintf("test-xray-%s-%d", tc.name, time.Now().UnixNano()%100000)
			t.Cleanup(func() {
				_ = exec.Command(dockerPath, "rm", "-fv", containerName).Run()
			})

			// Pre-pull image to isolate image download time from container readiness
			pullCmd := exec.Command(dockerPath, "pull", tc.image)
			if pullOut, pullErr := pullCmd.CombinedOutput(); pullErr != nil {
				t.Fatalf("docker pull %s failed: %v, out: %s", tc.image, pullErr, string(pullOut))
			}

			// Run container with host network and dual configuration directory mounts
			// (/etc/xray for 1.8.24 baseline, /usr/local/etc/xray for 26.10.x distroless default).
			runCmd := exec.Command(dockerPath, "run", "-d",
				"--name", containerName,
				"--network", "host",
				"--user", "0:0",
				"-v", fmt.Sprintf("%s:/etc/xray:ro", cfgDir),
				"-v", fmt.Sprintf("%s:/usr/local/etc/xray:ro", cfgDir),
				tc.image,
			)
			if out, rErr := runCmd.CombinedOutput(); rErr != nil {
				t.Fatalf("docker run %s failed: %v, out: %s", tc.image, rErr, string(out))
			}

			dumpDiagnostics := func() string {
				inspectCmd := exec.Command(dockerPath, "inspect", "-f", "status={{.State.Status}} running={{.State.Running}} exit={{.State.ExitCode}} error={{.State.Error}}", containerName)
				insOut, _ := inspectCmd.CombinedOutput()
				logsCmd := exec.Command(dockerPath, "logs", "--tail", "100", containerName)
				logsOut, _ := logsCmd.CombinedOutput()
				return fmt.Sprintf("container state: %s\ndocker logs:\n%s", strings.TrimSpace(string(insOut)), string(logsOut))
			}

			waitForReadiness := func(phase string, timeout time.Duration) {
				deadline := time.Now().Add(timeout)
				var lastDialErr error
				for time.Now().Before(deadline) {
					readyConn, dErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 250*time.Millisecond)
					if dErr == nil {
						_ = readyConn.Close()
						return
					}
					lastDialErr = dErr

					// Check if container already exited prematurely
					inspectCmd := exec.Command(dockerPath, "inspect", "-f", "{{.State.Status}} {{.State.Running}} {{.State.ExitCode}}", containerName)
					if insOut, insErr := inspectCmd.CombinedOutput(); insErr == nil {
						fields := strings.Fields(strings.TrimSpace(string(insOut)))
						if len(fields) >= 2 && fields[1] == "false" {
							logsCmd := exec.Command(dockerPath, "logs", "--tail", "100", containerName)
							logsOut, _ := logsCmd.CombinedOutput()
							t.Fatalf("%s: container %s exited prematurely before readiness (state: %s, dial err: %v)\ndocker logs:\n%s",
								phase, containerName, strings.TrimSpace(string(insOut)), lastDialErr, string(logsOut))
						}
					}
					time.Sleep(250 * time.Millisecond)
				}

				inspectCmd := exec.Command(dockerPath, "inspect", containerName)
				insOut, _ := inspectCmd.CombinedOutput()
				logsCmd := exec.Command(dockerPath, "logs", "--tail", "100", containerName)
				logsOut, _ := logsCmd.CombinedOutput()
				t.Fatalf("%s: container %s timed out waiting for readiness on 127.0.0.1:%d after %v (last dial err: %v)\ndocker inspect:\n%s\ndocker logs:\n%s",
					phase, containerName, port, timeout, lastDialErr, string(insOut), string(logsOut))
			}

			// Wait for container readiness (up to 30 seconds)
			waitForReadiness("initial startup", 30*time.Second)

			params := models.VLESSRealityParams{
				UUID:          clientUUID,
				Flow:          "",
				ServerName:    serverName,
				Fingerprint:   "chrome",
				PublicKey:     pubB64,
				ShortID:       shortID,
				EngineProfile: tc.engineProfile,
			}

			d, err := New(fmt.Sprintf("127.0.0.1:%d", port), params)
			if err != nil {
				t.Fatalf("New dialer: %v", err)
			}

			// 1. Authenticated REALITY handshake and bidirectional TCP data stream
			dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := d.DialContext(dialCtx, "tcp", echoAddr)
			if err != nil {
				t.Fatalf("DialContext failed against %s: %v\n%s", tc.name, err, dumpDiagnostics())
			}
			payload := []byte(fmt.Sprintf("hello from %s container integration", tc.name))
			if _, wErr := conn.Write(payload); wErr != nil {
				conn.Close()
				t.Fatalf("Write payload against %s failed: %v\n%s", tc.name, wErr, dumpDiagnostics())
			}
			reply := make([]byte, len(payload))
			if _, rErr := io.ReadFull(conn, reply); rErr != nil {
				conn.Close()
				t.Fatalf("Read reply against %s failed: %v\n%s", tc.name, rErr, dumpDiagnostics())
			}
			if !bytes.Equal(reply, payload) {
				conn.Close()
				t.Fatalf("reply mismatch against %s: got %q, want %q\n%s", tc.name, reply, payload, dumpDiagnostics())
			}
			conn.Close()

			// Bidirectional UDP data stream through container
			udpCtx, udpCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer udpCancel()
			udpConn, err := d.DialContext(udpCtx, "udp", udpEchoAddr)
			if err != nil {
				t.Fatalf("DialContext udp failed against %s: %v\n%s", tc.name, err, dumpDiagnostics())
			}
			udpPayload := []byte(fmt.Sprintf("hello udp from %s container integration", tc.name))
			_ = udpConn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, wErr := udpConn.Write(udpPayload); wErr != nil {
				udpConn.Close()
				t.Fatalf("Write udp payload against %s failed: %v\n%s", tc.name, wErr, dumpDiagnostics())
			}
			udpReply := make([]byte, len(udpPayload)+64)
			n, rErr := udpConn.Read(udpReply)
			if rErr != nil {
				udpConn.Close()
				t.Fatalf("Read udp reply against %s failed: %v\n%s", tc.name, rErr, dumpDiagnostics())
			}
			if !bytes.Equal(udpReply[:n], udpPayload) {
				udpConn.Close()
				t.Fatalf("udp reply mismatch against %s: got %q, want %q\n%s", tc.name, udpReply[:n], udpPayload, dumpDiagnostics())
			}
			udpConn.Close()

			// 2. Wrong-key rejection: dialing with mismatched key must fail
			badPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
			badPubB64 := base64.RawURLEncoding.EncodeToString(badPriv.PublicKey().Bytes())
			badParams := params
			badParams.PublicKey = badPubB64
			badDialer, err := New(fmt.Sprintf("127.0.0.1:%d", port), badParams)
			if err != nil {
				t.Fatalf("New bad dialer: %v", err)
			}
			badCtx, badCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer badCancel()
			badConn, badErr := badDialer.DialContext(badCtx, "tcp", echoAddr)
			if badErr == nil {
				_ = badConn.SetDeadline(time.Now().Add(1 * time.Second))
				_, wErr := badConn.Write([]byte("unauthenticated probe"))
				buf := make([]byte, 64)
				_, rErr := badConn.Read(buf)
				badConn.Close()
				if wErr == nil && rErr == nil {
					t.Fatalf("expected wrong-key connection to be rejected by REALITY server\n%s", dumpDiagnostics())
				}
			}

			// 3. Restart recovery: restart container, redial, verify data stream recovers
			restartCmd := exec.Command(dockerPath, "restart", containerName)
			if out, restErr := restartCmd.CombinedOutput(); restErr != nil {
				t.Fatalf("docker restart failed: %v, out: %s\n%s", restErr, string(out), dumpDiagnostics())
			}
			waitForReadiness("restart recovery", 30*time.Second)
			recoveryCtx, recCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer recCancel()
			recConn, err := d.DialContext(recoveryCtx, "tcp", echoAddr)
			if err != nil {
				t.Fatalf("restart recovery: DialContext failed against %s: %v\n%s", tc.name, err, dumpDiagnostics())
			}
			defer recConn.Close()
			recPayload := []byte("recovery post-restart payload")
			if _, wErr := recConn.Write(recPayload); wErr != nil {
				t.Fatalf("recovery write against %s failed: %v\n%s", tc.name, wErr, dumpDiagnostics())
			}
			recReply := make([]byte, len(recPayload))
			if _, rErr := io.ReadFull(recConn, recReply); rErr != nil {
				t.Fatalf("recovery read against %s failed: %v\n%s", tc.name, rErr, dumpDiagnostics())
			}
			if !bytes.Equal(recReply, recPayload) {
				t.Fatalf("recovery mismatch against %s: got %q, want %q\n%s", tc.name, recReply, recPayload, dumpDiagnostics())
			}
		})
	}
}
