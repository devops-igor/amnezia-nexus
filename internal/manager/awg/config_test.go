package awg

import (
	"strings"
	"testing"
)

func TestRenderServerConfig(t *testing.T) {
	params := &AWGParams{
		JunkPacketCount:           "4",
		JunkPacketMinSize:         "30",
		JunkPacketMaxSize:         "80",
		InitPacketJunkSize:        "40",
		ResponsePacketJunkSize:    "60",
		InitPacketMagicHeader:     "12345",
		ResponsePacketMagicHeader: "67890",
		I1:                        "<b 0xdeadbeef>", // Should NOT be in server config!
	}

	peers := []AWGPeer{
		{
			PublicKey:    "pubkey1",
			PresharedKey: "psk1",
			AllowedIPs:   "10.8.1.2/32",
		},
	}

	conf := RenderServerConfig("serverPrivKey", "10.8.1.1", "24", "55424", "1280", params, peers)

	if !strings.Contains(conf, "[Interface]") || !strings.Contains(conf, "[Peer]") {
		t.Errorf("missing sections in server config")
	}
	if !strings.Contains(conf, "PrivateKey = serverPrivKey") {
		t.Errorf("missing private key")
	}
	if !strings.Contains(conf, "PublicKey = pubkey1") {
		t.Errorf("missing peer public key")
	}
	if strings.Contains(conf, "I1") || strings.Contains(conf, "deadbeef") {
		t.Errorf("server config must NEVER contain I1-I5 signatures")
	}
}

func TestRenderClientConfig(t *testing.T) {
	params := &AWGParams{
		JunkPacketCount:           "4",
		JunkPacketMinSize:         "30",
		JunkPacketMaxSize:         "80",
		InitPacketJunkSize:        "40",
		ResponsePacketJunkSize:    "60",
		InitPacketMagicHeader:     "12345",
		ResponsePacketMagicHeader: "67890",
		I1:                        "<b 0xdeadbeef>",
	}

	conf := RenderClientConfig("clientPrivKey", "10.8.1.2", "serverPubKey", "psk1", "1.2.3.4:55424", "94.140.14.14", "94.140.15.15", "1280", params, nil)

	if !strings.Contains(conf, "Address = 10.8.1.2/32") {
		t.Errorf("missing client Address")
	}
	if !strings.Contains(conf, "I1 = <b 0xdeadbeef>") {
		t.Errorf("missing I1 in client config")
	}
	if !strings.Contains(conf, "Endpoint = 1.2.3.4:55424") {
		t.Errorf("missing Endpoint in client config")
	}
	if !strings.Contains(conf, "PersistentKeepalive = 25") {
		t.Errorf("expected default PersistentKeepalive = 25 when ud is nil")
	}
}

func TestRenderClientConfig_AWG3_Compliance(t *testing.T) {
	rat := 125
	rt := 5
	rej := 180
	kt := 10
	mha := 6
	pk := 27
	cpAdd := "16-64"

	ud := &AWGClientUserData{
		ClientName:             "testuser",
		ClientPrivateKey:       "clientPrivKey123",
		ClientIP:               "10.100.0.5",
		Enabled:                true,
		RekeyAfterTime:         &rat,
		RekeyTimeout:           &rt,
		RejectAfterTime:        &rej,
		KeepaliveTimeout:       &kt,
		MaxHandshakeAttempts:   &mha,
		PersistentKeepalive:    &pk,
		ContentPaddingAddition: &cpAdd,
	}

	params := &AWGParams{
		JunkPacketCount:            "3",
		JunkPacketMinSize:          "40",
		JunkPacketMaxSize:          "70",
		InitPacketJunkSize:         "16",
		ResponsePacketJunkSize:     "16",
		CookieReplyPacketJunkSize:  "16",
		TransportPacketJunkSize:    "16",
		InitPacketMagicHeader:      "11111",
		ResponsePacketMagicHeader:  "22222",
		UnderloadPacketMagicHeader: "33333",
		TransportPacketMagicHeader: "44444",
		HeaderProtectionKey:        "W1234567890abcdefghijklmnopqrstuvwxyzAB=",
	}

	conf := RenderClientConfig(
		"clientPrivKey123",
		"10.100.0.5",
		"serverPub123",
		"psk456",
		"lb.example.com:51820",
		"1.1.1.1",
		"1.0.0.1",
		"1420",
		params,
		ud,
	)

	// Verify [Interface] section directives
	interfaceDirectives := []string{
		"Address = 10.100.0.5/32",
		"DNS = 1.1.1.1, 1.0.0.1",
		"PrivateKey = clientPrivKey123",
		"MTU = 1420",
		"Jc = 3",
		"Jmin = 40",
		"Jmax = 70",
		"S1 = 16",
		"S2 = 16",
		"S3 = 16",
		"S4 = 16",
		"H1 = 11111",
		"H2 = 22222",
		"H3 = 33333",
		"H4 = 44444",
		"HeaderProtectionKey = W1234567890abcdefghijklmnopqrstuvwxyzAB=",
		"RekeyAfterTime = 125",
		"RekeyTimeout = 5",
		"RejectAfterTime = 180",
		"KeepaliveTimeout = 10",
		"MaxHandshakeAttempts = 6",
		"ContentPaddingAddition = 16-64",
	}

	for _, d := range interfaceDirectives {
		if !strings.Contains(conf, d) {
			t.Errorf("RenderClientConfig missing [Interface] directive: %q\nFull config:\n%s", d, conf)
		}
	}

	// Verify [Peer] section directives
	peerDirectives := []string{
		"PublicKey = serverPub123",
		"PresharedKey = psk456",
		"AllowedIPs = 0.0.0.0/0, ::/0",
		"Endpoint = lb.example.com:51820",
		"PersistentKeepalive = 27",
	}

	for _, d := range peerDirectives {
		if !strings.Contains(conf, d) {
			t.Errorf("RenderClientConfig missing [Peer] directive: %q\nFull config:\n%s", d, conf)
		}
	}

	// Verify default PersistentKeepalive = 25 was replaced by randomized value 27
	if strings.Contains(conf, "PersistentKeepalive = 25") {
		t.Errorf("RenderClientConfig emitted default PersistentKeepalive = 25 instead of ud value 27")
	}
}

func TestParseServerConfig(t *testing.T) {
	confText := `
[Interface]
PrivateKey = sPriv
Address = 10.8.1.1/24
ListenPort = 55424
MTU = 1280
Jc = 4
Jmin = 30
Jmax = 80
S1 = 40
S2 = 60
H1 = 12345
H2 = 67890

[Peer]
PublicKey = pKey1
PresharedKey = psk1
AllowedIPs = 10.8.1.2/32

[Peer]
PublicKey = pKey2
AllowedIPs = 10.8.1.3/32
`

	params, peers, err := ParseServerConfig(confText)
	if err != nil {
		t.Fatalf("ParseServerConfig failed: %v", err)
	}

	if params["port"] != "55424" || params["junk_packet_count"] != "4" || params["init_packet_magic_header"] != "12345" {
		t.Errorf("unexpected parsed params: %+v", params)
	}

	if len(peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(peers))
	}
	if peers[0].PublicKey != "pKey1" || peers[0].PresharedKey != "psk1" {
		t.Errorf("unexpected peer 1: %+v", peers[0])
	}
	if peers[1].PublicKey != "pKey2" || peers[1].PresharedKey != "" {
		t.Errorf("unexpected peer 2: %+v", peers[1])
	}
}

func TestGetNextIP(t *testing.T) {
	usedIPs := []string{"10.8.1.2", "10.8.1.3"}
	nextIP, err := GetNextIP(usedIPs, "10.8.1.0", 24, "10.8.1.1")
	if err != nil {
		t.Fatalf("GetNextIP failed: %v", err)
	}
	if nextIP != "10.8.1.4" {
		t.Errorf("expected 10.8.1.4, got %s", nextIP)
	}

	// Test subnet exhaustion on /30 (usable: .1 gateway, .2 client)
	usedAll := []string{"10.8.1.2"}
	_, err = GetNextIP(usedAll, "10.8.1.0", 30, "10.8.1.1")
	if err == nil {
		t.Errorf("expected error on subnet exhaustion")
	}
}

func TestClientsTableSerialization(t *testing.T) {
	clients := []AWGClient{
		{
			ClientID: "pubkey1",
			UserData: AWGClientUserData{
				ClientName:       "User1",
				ClientPrivateKey: "privkey1",
				ClientIP:         "10.8.1.2",
				Enabled:          true,
			},
		},
	}

	jsonStr, err := SerializeClientsTable(clients)
	if err != nil {
		t.Fatalf("SerializeClientsTable failed: %v", err)
	}

	parsed, err := ParseClientsTable(jsonStr)
	if err != nil {
		t.Fatalf("ParseClientsTable failed: %v", err)
	}
	if len(parsed) != 1 || parsed[0].ClientID != "pubkey1" || parsed[0].UserData.ClientName != "User1" {
		t.Errorf("parsed clients mismatch: %+v", parsed)
	}

	// Test legacy dict format
	legacyJSON := `{"client1": {"clientName": "LegacyUser"}}`
	parsedLegacy, err := ParseClientsTable(legacyJSON)
	if err != nil || len(parsedLegacy) != 1 || parsedLegacy[0].UserData.ClientName != "LegacyUser" {
		t.Errorf("failed to parse legacy JSON format: %v, %+v", err, parsedLegacy)
	}
}
