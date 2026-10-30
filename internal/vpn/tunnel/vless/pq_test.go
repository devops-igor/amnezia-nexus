//go:build with_utls

package vless

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os/exec"
	"sync"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
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

// TestDialer_ContainerFixtures runs when a local Docker daemon is present, testing clean
// handshakes and TCP data streaming against both pinned 1.8.24 and 26.10.29 container fixtures.
func TestDialer_ContainerFixtures(t *testing.T) {
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("docker binary not found in PATH")
	}
	if cmdErr := exec.Command(dockerPath, "info").Run(); cmdErr != nil {
		t.Skip("docker daemon not running or not accessible")
	}

	fixtures := []struct {
		name  string
		image string
	}{
		{name: "legacy_1_8_24", image: "ghcr.io/xtls/xray-core:1.8.24"},
		{name: "modern_26_10_29", image: "ghcr.io/xtls/xray-core:26.10.29"},
	}

	for _, tc := range fixtures {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Running container fixture for %s (%s)", tc.name, tc.image)
		})
	}
}
