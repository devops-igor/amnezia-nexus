package health

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

func startMockAWGServer(t *testing.T, h1, h2 uint32, s1, s2 int) (net.PacketConn, []byte, string, int) {
	return startMockAWGServerWithHP(t, nil, h1, h2, s1, s2)
}

func startMockAWGServerWithHP(t *testing.T, hpKey []byte, h1, h2 uint32, s1, s2 int) (net.PacketConn, []byte, string, int) {
	serverPriv, serverPub := generateTestKeypair(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}

	host, portStr, _ := net.SplitHostPort(pc.LocalAddr().String())
	port, _ := strconv.Atoi(portStr)

	go func() {
		buf := make([]byte, 2048)
		for {
			n, clientAddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < s1+116 {
				continue
			}

			if len(hpKey) == 32 {
				cip := newHeaderProtectionCipher(hpKey, buf[:n])
				if cip != nil && n >= s1+MessageInitiationSize {
					cip.XORKeyStream(buf[s1:s1+MessageInitiationSize], buf[s1:s1+MessageInitiationSize])
				}
			}

			msgBody := buf[s1 : s1+116]
			msgType := binary.LittleEndian.Uint32(msgBody[0:4])
			if msgType != h1 {
				continue
			}
			senderIdx := binary.LittleEndian.Uint32(msgBody[4:8])
			clientEPub := msgBody[8:40]
			encryptedStatic := msgBody[40:88]
			encryptedTimestamp := msgBody[88:116]

			serverHSum := blake2s.Sum256(append(InitialHash[:], serverPub...))
			serverH := serverHSum[:]
			serverCK := InitialChainKey[:]

			serverHSum = blake2s.Sum256(append(serverH, clientEPub...))
			serverH = serverHSum[:]
			serverCK = KDF1(serverCK, clientEPub)

			serverSS1, _ := curve25519.X25519(serverPriv, clientEPub)
			var serverKey1 []byte
			serverCK, serverKey1 = KDF2(serverCK, serverSS1)

			serverAead1, _ := chacha20poly1305.New(serverKey1)
			nonce0 := make([]byte, 12)
			clientStaticPub, _ := serverAead1.Open(nil, nonce0, encryptedStatic, serverH)
			serverHSum = blake2s.Sum256(append(serverH, encryptedStatic...))
			serverH = serverHSum[:]

			serverSS2, _ := curve25519.X25519(serverPriv, clientStaticPub)
			var serverKey2 []byte
			serverCK, serverKey2 = KDF2(serverCK, serverSS2)

			serverAead2, _ := chacha20poly1305.New(serverKey2)
			_, _ = serverAead2.Open(nil, nonce0, encryptedTimestamp, serverH)
			serverHSum = blake2s.Sum256(append(serverH, encryptedTimestamp...))
			serverH = serverHSum[:]

			serverEPriv, serverEPub := generateTestKeypair(t)
			serverHSum = blake2s.Sum256(append(serverH, serverEPub...))
			serverH = serverHSum[:]
			serverCK = KDF1(serverCK, serverEPub)

			serverSS3, _ := curve25519.X25519(serverEPriv, clientEPub)
			serverCK = KDF1(serverCK, serverSS3)

			serverSS4, _ := curve25519.X25519(serverEPriv, clientStaticPub)
			serverCK = KDF1(serverCK, serverSS4)

			var serverTau, serverKey3 []byte
			_, serverTau, serverKey3 = KDF3(serverCK, make([]byte, 32))
			serverHSum = blake2s.Sum256(append(serverH, serverTau...))
			serverH = serverHSum[:]

			serverAead3, _ := chacha20poly1305.New(serverKey3)
			encryptedEmpty := serverAead3.Seal(nil, nonce0, []byte{}, serverH)

			respMsgType := make([]byte, 4)
			binary.LittleEndian.PutUint32(respMsgType, h2)
			serverSenderIdx := make([]byte, 4)
			binary.LittleEndian.PutUint32(serverSenderIdx, 12345)
			respReceiverIdx := make([]byte, 4)
			binary.LittleEndian.PutUint32(respReceiverIdx, senderIdx)

			var respMsgBody []byte
			respMsgBody = append(respMsgBody, respMsgType...)
			respMsgBody = append(respMsgBody, serverSenderIdx...)
			respMsgBody = append(respMsgBody, respReceiverIdx...)
			respMsgBody = append(respMsgBody, serverEPub...)
			respMsgBody = append(respMsgBody, encryptedEmpty...)

			mac1KeySum := blake2s.Sum256(append(LabelMAC1, clientStaticPub...))
			hMac1, _ := blake2s.New128(mac1KeySum[:])
			hMac1.Write(respMsgBody)
			respMac1 := hMac1.Sum(nil)
			respMac2 := make([]byte, 16)

			var respPacket []byte
			if s2 > 0 {
				pad := make([]byte, s2)
				_, _ = rand.Read(pad)
				respPacket = append(respPacket, pad...)
			}
			respPacket = append(respPacket, respMsgBody...)
			respPacket = append(respPacket, respMac1...)
			respPacket = append(respPacket, respMac2...)

			if len(hpKey) == 32 {
				cip := newHeaderProtectionCipher(hpKey, respPacket)
				if cip != nil && len(respPacket) >= s2+MessageResponseSize {
					cip.XORKeyStream(respPacket[s2:s2+MessageResponseSize], respPacket[s2:s2+MessageResponseSize])
				}
			}

			_, _ = pc.WriteTo(respPacket, clientAddr)
		}
	}()

	return pc, serverPub, host, port
}

func TestPerformAWGHandshake(t *testing.T) {
	ctx := context.Background()
	h1 := DefaultH1
	h2 := DefaultH2
	s1 := DefaultS1
	s2 := DefaultS2

	pc, serverPub, host, port := startMockAWGServer(t, h1, h2, s1, s2)
	defer func() {
		_ = pc.Close()
	}()

	serverPubB64 := base64.StdEncoding.EncodeToString(serverPub)
	params := map[string]any{
		"init_packet_magic_header":     strconv.FormatUint(uint64(h1), 10),
		"response_packet_magic_header": strconv.FormatUint(uint64(h2), 10),
		"init_packet_junk_size":        strconv.Itoa(s1),
		"response_packet_junk_size":    strconv.Itoa(s2),
		"junk_packet_count":            "2",
		"junk_packet_min_size":         "10",
		"junk_packet_max_size":         "20",
	}

	res, err := PerformAWGHandshake(ctx, host, port, serverPubB64, "", "", "", params, "quic", 2*time.Second)
	if err != nil {
		t.Fatalf("PerformAWGHandshake returned error: %v", err)
	}

	if reachable, ok := res["reachable"].(bool); !ok || !reachable {
		t.Errorf("expected reachable to be true, got %v (err=%v)", reachable, res["error"])
	}

	// Test with invalid endpoint
	resDead, _ := PerformAWGHandshake(ctx, "127.0.0.1", 1, serverPubB64, "", "", "", params, "", 200*time.Millisecond)
	if reachable, ok := resDead["reachable"].(bool); !ok || reachable {
		t.Errorf("expected unreachable for closed port, got: %v", resDead)
	}
}

func TestPerformAWGHandshake_HeaderProtection(t *testing.T) {
	ctx := context.Background()
	h1 := DefaultH1
	h2 := DefaultH2
	s1 := DefaultS1
	s2 := DefaultS2

	hpKey := []byte("01234567890123456789012345678901")
	hpKeyB64 := base64.StdEncoding.EncodeToString(hpKey)

	pc, serverPub, host, port := startMockAWGServerWithHP(t, hpKey, h1, h2, s1, s2)
	defer func() {
		_ = pc.Close()
	}()

	serverPubB64 := base64.StdEncoding.EncodeToString(serverPub)
	params := map[string]any{
		"init_packet_magic_header":     strconv.FormatUint(uint64(h1), 10),
		"response_packet_magic_header": strconv.FormatUint(uint64(h2), 10),
		"init_packet_junk_size":        strconv.Itoa(s1),
		"response_packet_junk_size":    strconv.Itoa(s2),
		"header_protection_key":        hpKeyB64,
	}

	// 1. Explicit hpKey argument
	res, err := PerformAWGHandshake(ctx, host, port, serverPubB64, "", "", hpKeyB64, params, "quic", 2*time.Second)
	if err != nil {
		t.Fatalf("PerformAWGHandshake with explicit hpKey returned error: %v", err)
	}
	if reachable, ok := res["reachable"].(bool); !ok || !reachable {
		t.Errorf("expected reachable to be true with explicit hpKey, got %v (err=%v)", reachable, res["error"])
	}
	if completed, ok := res["handshake_complete"].(bool); !ok || !completed {
		t.Errorf("expected handshake_complete to be true with explicit hpKey")
	}

	// 2. hpKey resolved from awgParams when hpKey argument is empty
	resParams, err := PerformAWGHandshake(ctx, host, port, serverPubB64, "", "", "", params, "", 2*time.Second)
	if err != nil {
		t.Fatalf("PerformAWGHandshake with awgParams hpKey returned error: %v", err)
	}
	if reachable, ok := resParams["reachable"].(bool); !ok || !reachable {
		t.Errorf("expected reachable to be true with awgParams hpKey, got %v (err=%v)", reachable, resParams["error"])
	}

	// 3. Probing with empty hpKey against HP-enabled server fails verification or times out
	resNoHP, err := PerformAWGHandshake(ctx, host, port, serverPubB64, "", "", "", nil, "", 200*time.Millisecond)
	if err != nil {
		t.Fatalf("PerformAWGHandshake returned hard error: %v", err)
	}
	if reachable, ok := resNoHP["reachable"].(bool); ok && reachable {
		t.Errorf("expected unreachable when probing HP server without hpKey")
	}

	// 4. Invalid base64 hpKey returns hard error
	if _, err := PerformAWGHandshake(ctx, host, port, serverPubB64, "", "", "invalid-b64!!!", params, "", 200*time.Millisecond); err == nil {
		t.Errorf("expected error for invalid base64 hpKey")
	}
}

func TestRunAutoTrialProfiles(t *testing.T) {
	ctx := context.Background()
	h1 := DefaultH1
	h2 := DefaultH2
	s1 := DefaultS1
	s2 := DefaultS2

	pc, serverPub, host, port := startMockAWGServer(t, h1, h2, s1, s2)
	defer func() {
		_ = pc.Close()
	}()

	serverPubB64 := base64.StdEncoding.EncodeToString(serverPub)
	params := map[string]any{
		"init_packet_magic_header":     strconv.FormatUint(uint64(h1), 10),
		"response_packet_magic_header": strconv.FormatUint(uint64(h2), 10),
		"init_packet_junk_size":        strconv.Itoa(s1),
		"response_packet_junk_size":    strconv.Itoa(s2),
	}

	results, err := RunAutoTrialProfiles(ctx, host, port, serverPubB64, "", "", "", params, 2*time.Second)
	if err != nil {
		t.Fatalf("RunAutoTrialProfiles failed: %v", err)
	}

	for _, proto := range []string{"tls", "quic", "dns", "sip"} {
		res, ok := results[proto]
		if !ok {
			t.Fatalf("missing profile result for %s", proto)
		}
		if reachable, ok := res["reachable"].(bool); !ok || !reachable {
			t.Errorf("profile %s expected reachable, got %v (err=%v)", proto, reachable, res["error"])
		}
	}

	// Test invalid key errors
	if _, err := ProbeAWGEndpoint(ctx, "127.0.0.1:55424", "invalid-key", "", "", "", 0, 0, 0, 0, 0); err == nil {
		t.Errorf("expected error for invalid server key")
	}
	if _, err := ProbeAWGEndpoint(ctx, "127.0.0.1:55424", serverPubB64, "invalid-key", "", "", 0, 0, 0, 0, 0); err == nil {
		t.Errorf("expected error for invalid client key")
	}
	if _, err := ProbeAWGEndpoint(ctx, "127.0.0.1:55424", serverPubB64, "", "invalid-key", "", 0, 0, 0, 0, 0); err == nil {
		t.Errorf("expected error for invalid psk")
	}
}

func TestExtractAWGExplicitParams(t *testing.T) {
	// 1. Nil map
	_, _, _, _, found := ExtractAWGExplicitParams(nil)
	if found {
		t.Errorf("expected found=false for nil map")
	}

	// 2. Map with unrelated keys only (Finding 2 regression)
	unrelated := map[string]any{
		"installed":  true,
		"port":       51820,
		"public_key": "dummy-key",
	}
	_, _, _, _, found = ExtractAWGExplicitParams(unrelated)
	if found {
		t.Errorf("expected found=false for map with unrelated keys")
	}

	// 3. Map with explicit H1/H2/S1/S2
	explicitMap := map[string]any{
		"init_packet_magic_header":     "1111",
		"response_packet_magic_header": "2222",
		"init_packet_junk_size":        "30",
		"response_packet_junk_size":    "40",
	}
	h1, h2, s1, s2, found := ExtractAWGExplicitParams(explicitMap)
	if !found || h1 != 1111 || h2 != 2222 || s1 != 30 || s2 != 40 {
		t.Errorf("expected explicit params (1111, 2222, 30, 40, true), got (%d, %d, %d, %d, %v)", h1, h2, s1, s2, found)
	}

	// 4. Short keys (h1, h2, s1, s2)
	shortKeys := map[string]string{
		"h1": "5555",
		"h2": "6666",
		"s1": "10",
		"s2": "20",
	}
	h1, h2, s1, s2, found = ExtractAWGExplicitParams(shortKeys)
	if !found || h1 != 5555 || h2 != 6666 || s1 != 10 || s2 != 20 {
		t.Errorf("expected short keys params (5555, 6666, 10, 20, true), got (%d, %d, %d, %d, %v)", h1, h2, s1, s2, found)
	}

	// 5. Secondary AWG keys (h3, h4, jc, etc.)
	secondaryMap := map[string]any{
		"h3": 7777,
	}
	_, _, _, _, found = ExtractAWGExplicitParams(secondaryMap)
	if !found {
		t.Errorf("expected found=true for secondary AWG key h3")
	}

	jcMap := map[string]any{
		"junk_packet_count": 4,
	}
	_, _, _, _, found = ExtractAWGExplicitParams(jcMap)
	if !found {
		t.Errorf("expected found=true for junk_packet_count")
	}
}

func TestExtractAWGHeaderLimits_FallbackHierarchy(t *testing.T) {
	// 1. When defaultH1 == 0 and map has no AWG keys, must NOT return legacy DefaultH1
	emptyMap := map[string]any{"installed": true}
	h1, h2, s1, s2 := ExtractAWGHeaderLimits(emptyMap, 0, 0, -1, -1)
	if h1 != 0 || h2 != 0 || s1 != -1 || s2 != -1 {
		t.Errorf("expected (0, 0, -1, -1) when defaultH1=0 and map has no keys, got (%d, %d, %d, %d)", h1, h2, s1, s2)
	}

	// 2. When defaultH1 > 0 is passed, falls back to supplied defaults
	h1, h2, s1, s2 = ExtractAWGHeaderLimits(emptyMap, DefaultH1, DefaultH2, DefaultS1, DefaultS2)
	if h1 != DefaultH1 || h2 != DefaultH2 || s1 != DefaultS1 || s2 != DefaultS2 {
		t.Errorf("expected legacy defaults when supplied, got (%d, %d, %d, %d)", h1, h2, s1, s2)
	}

	// 3. When explicit parameters exist, they override defaults
	params := map[string]any{"h1": "9999"}
	h1, h2, s1, s2 = ExtractAWGHeaderLimits(params, 0, 0, -1, -1)
	if h1 != 9999 || h2 != DefaultH2 || s1 != DefaultS1 || s2 != DefaultS2 {
		t.Errorf("expected h1=9999 with DefaultH2 fallback, got (%d, %d, %d, %d)", h1, h2, s1, s2)
	}
}

func TestExtractHeaderProtectionKey_CasingAndStyles(t *testing.T) {
	expectedKey := "BSX9ZtdoVp6sTwS+ziidJqp/aBjHrp1+xSOzc3+Z36Y="

	// 1. PascalCase HeaderProtectionKey (live server format)
	m1 := map[string]any{"HeaderProtectionKey": expectedKey}
	if k := ExtractHeaderProtectionKey(m1); k != expectedKey {
		t.Errorf("expected %q for PascalCase HeaderProtectionKey, got %q", expectedKey, k)
	}

	// 2. snake_case header_protection_key
	m2 := map[string]any{"header_protection_key": expectedKey}
	if k := ExtractHeaderProtectionKey(m2); k != expectedKey {
		t.Errorf("expected %q for snake_case header_protection_key, got %q", expectedKey, k)
	}

	// 3. short key hpkey
	m3 := map[string]any{"hpkey": expectedKey}
	if k := ExtractHeaderProtectionKey(m3); k != expectedKey {
		t.Errorf("expected %q for short key hpkey, got %q", expectedKey, k)
	}

	// 4. map[string]string variant
	m4 := map[string]string{"HeaderProtectionKey": expectedKey}
	if k := ExtractHeaderProtectionKey(m4); k != expectedKey {
		t.Errorf("expected %q for map[string]string HeaderProtectionKey, got %q", expectedKey, k)
	}

	// 5. ExtractAWGExplicitParams detects HeaderProtectionKey
	_, _, _, _, found := ExtractAWGExplicitParams(m1)
	if !found {
		t.Errorf("expected ExtractAWGExplicitParams to return found=true for HeaderProtectionKey")
	}
}
