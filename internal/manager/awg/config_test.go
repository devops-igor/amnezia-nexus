package awg

import (
	"reflect"
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
	rat := DegenerateTimingRange(125)
	rt := DegenerateTimingRange(5)
	rej := DegenerateTimingRange(180)
	kt := DegenerateTimingRange(10)
	mha := DegenerateTimingRange(6)
	pk := DegenerateTimingRange(27)
	cpAdd := "16-64"

	ud := &AWGClientUserData{
		ClientName:             "testuser",
		ClientPrivateKey:       "clientPrivKey123",
		ClientIP:               "10.100.0.5",
		Enabled:                true,
		RekeyAfterTime:         rat,
		RekeyTimeout:           rt,
		RejectAfterTime:        rej,
		KeepaliveTimeout:       kt,
		MaxHandshakeAttempts:   mha,
		PersistentKeepalive:    pk,
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

func TestRenderClientConfig_TimingRanges(t *testing.T) {
	rat := NewTimingRange(100, 140)
	rt := NewTimingRange(4, 6)
	rej := NewTimingRange(160, 200)
	kt := NewTimingRange(8, 12)
	mha := NewTimingRange(4, 8)
	pk := NewTimingRange(22, 30)

	ud := &AWGClientUserData{
		ClientName:           "testuser-range",
		ClientPrivateKey:     "clientPrivKeyRange",
		ClientIP:             "10.100.0.6",
		Enabled:              true,
		RekeyAfterTime:       rat,
		RekeyTimeout:         rt,
		RejectAfterTime:      rej,
		KeepaliveTimeout:     kt,
		MaxHandshakeAttempts: mha,
		PersistentKeepalive:  pk,
	}

	conf := RenderClientConfig(
		"clientPrivKeyRange",
		"10.100.0.6",
		"serverPub123",
		"psk456",
		"lb.example.com:51820",
		"1.1.1.1",
		"1.0.0.1",
		"1420",
		nil,
		ud,
	)

	expectedDirectives := []string{
		"RekeyAfterTime = 100-140",
		"RekeyTimeout = 4-6",
		"RejectAfterTime = 160-200",
		"KeepaliveTimeout = 8-12",
		"MaxHandshakeAttempts = 4-8",
		"PersistentKeepalive = 22-30",
	}

	for _, d := range expectedDirectives {
		if !strings.Contains(conf, d) {
			t.Errorf("RenderClientConfig missing timing range directive: %q\nFull config:\n%s", d, conf)
		}
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

func TestParseServerConfig_InlineComments(t *testing.T) {
	confText := `
[Interface]
PrivateKey = sPrivKeyBase64Value==
Address = 10.8.1.1/24
ListenPort = 51820 ; udp port
MTU = 1280 # tunnel mtu
Jc = 5 # number of junk packets
Jmin = 30 ; min junk size
Jmax = 80 # max junk size
S1 = 40 # init junk
S2 = 60 ; response junk
S3 = 10 # cookie junk
S4 = 20 ; transport junk
H1 = 12345 # magic
H2 = 67890 ; magic
H3 = 11111 # underload
H4 = 22222 ; transport magic

[Peer]
PublicKey = pKey1WithBase64Chars+/=
PresharedKey = psk1AlsoBase64==
AllowedIPs = 10.8.1.2/32 # client
`
	params, peers, err := ParseServerConfig(confText)
	if err != nil {
		t.Fatalf("ParseServerConfig failed: %v", err)
	}

	want := map[string]string{
		"port":                          "51820",
		"mtu":                           "1280",
		"junk_packet_count":             "5",
		"junk_packet_min_size":          "30",
		"junk_packet_max_size":          "80",
		"init_packet_junk_size":         "40",
		"response_packet_junk_size":     "60",
		"cookie_reply_packet_junk_size": "10",
		"transport_packet_junk_size":    "20",
		"init_packet_magic_header":      "12345",
		"response_packet_magic_header":  "67890",
		"underload_packet_magic_header": "11111",
		"transport_packet_magic_header": "22222",
	}
	for k, v := range want {
		if params[k] != v {
			t.Errorf("param %s: got %q, want %q", k, params[k], v)
		}
	}
	if params["PrivateKey"] != "sPrivKeyBase64Value==" {
		t.Errorf("PrivateKey should keep base64 intact, got %q", params["PrivateKey"])
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].PublicKey != "pKey1WithBase64Chars+/=" {
		t.Errorf("peer PublicKey mangled: %q", peers[0].PublicKey)
	}
	if peers[0].PresharedKey != "psk1AlsoBase64==" {
		t.Errorf("peer PresharedKey mangled: %q", peers[0].PresharedKey)
	}
	if peers[0].AllowedIPs != "10.8.1.2/32" {
		t.Errorf("AllowedIPs: got %q", peers[0].AllowedIPs)
	}
}

func TestStripComment(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"5 # number of junk packets", "5"},
		{"51820 ; port", "51820"},
		{"1280", "1280"},
		{"abc+/=", "abc+/="},
		{"on#no-space-still-comment", "on"},
		{"  42  # x  ", "42"},
	}
	for _, tc := range cases {
		if got := stripComment(strings.TrimSpace(tc.in)); got != tc.want {
			t.Errorf("stripComment(%q)=%q, want %q", tc.in, got, tc.want)
		}
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

func TestClientsTable_TimingParametersBackwardCompat(t *testing.T) {
	// 1. JSON with stored bare integers (legacy / existing production format)
	legacyIntsJSON := `[
		{
			"clientId": "pubkey-legacy",
			"userData": {
				"clientName": "LegacyClient",
				"enabled": true,
				"rekey_after_time": 125,
				"rekey_timeout": 5,
				"reject_after_time": 180,
				"keepalive_timeout": 10,
				"max_handshake_attempts": 6,
				"persistent_keepalive": 25
			}
		}
	]`

	parsedLegacy, err := ParseClientsTable(legacyIntsJSON)
	if err != nil {
		t.Fatalf("ParseClientsTable with bare ints failed: %v", err)
	}
	if len(parsedLegacy) != 1 {
		t.Fatalf("expected 1 client, got %d", len(parsedLegacy))
	}
	udLegacy := parsedLegacy[0].UserData
	if udLegacy.RekeyAfterTime == nil || udLegacy.RekeyAfterTime.Lo != 125 || udLegacy.RekeyAfterTime.Hi != 125 || !udLegacy.RekeyAfterTime.IsDegenerate() {
		t.Errorf("expected degenerate RekeyAfterTime 125, got %+v", udLegacy.RekeyAfterTime)
	}
	if udLegacy.RekeyTimeout == nil || udLegacy.RekeyTimeout.Lo != 5 || udLegacy.RekeyTimeout.Hi != 5 {
		t.Errorf("expected degenerate RekeyTimeout 5, got %+v", udLegacy.RekeyTimeout)
	}
	if udLegacy.PersistentKeepalive == nil || udLegacy.PersistentKeepalive.Lo != 25 || udLegacy.PersistentKeepalive.Hi != 25 {
		t.Errorf("expected degenerate PersistentKeepalive 25, got %+v", udLegacy.PersistentKeepalive)
	}

	// 2. JSON with stored range strings (AWG 3.1 format)
	rangeJSON := `[
		{
			"clientId": "pubkey-range",
			"userData": {
				"clientName": "RangeClient",
				"enabled": true,
				"rekey_after_time": "100-140",
				"rekey_timeout": "4-6",
				"reject_after_time": "160-200",
				"keepalive_timeout": "8-12",
				"max_handshake_attempts": "4-8",
				"persistent_keepalive": "22-30"
			}
		}
	]`

	parsedRange, err := ParseClientsTable(rangeJSON)
	if err != nil {
		t.Fatalf("ParseClientsTable with ranges failed: %v", err)
	}
	if len(parsedRange) != 1 {
		t.Fatalf("expected 1 client, got %d", len(parsedRange))
	}
	udRange := parsedRange[0].UserData
	if udRange.RekeyAfterTime == nil || udRange.RekeyAfterTime.Lo != 100 || udRange.RekeyAfterTime.Hi != 140 || udRange.RekeyAfterTime.IsDegenerate() {
		t.Errorf("expected range RekeyAfterTime [100, 140], got %+v", udRange.RekeyAfterTime)
	}
	if udRange.RekeyTimeout == nil || udRange.RekeyTimeout.Lo != 4 || udRange.RekeyTimeout.Hi != 6 {
		t.Errorf("expected range RekeyTimeout [4, 6], got %+v", udRange.RekeyTimeout)
	}
	if udRange.PersistentKeepalive == nil || udRange.PersistentKeepalive.Lo != 22 || udRange.PersistentKeepalive.Hi != 30 {
		t.Errorf("expected range PersistentKeepalive [22, 30], got %+v", udRange.PersistentKeepalive)
	}

	// 3. Serialize and re-parse roundtrip
	serialized, err := SerializeClientsTable(parsedRange)
	if err != nil {
		t.Fatalf("SerializeClientsTable failed: %v", err)
	}
	reparsed, err := ParseClientsTable(serialized)
	if err != nil {
		t.Fatalf("re-parsing serialized clientsTable failed: %v", err)
	}
	if reparsed[0].UserData.RekeyAfterTime.String() != "100-140" {
		t.Errorf("expected RekeyAfterTime '100-140', got %q", reparsed[0].UserData.RekeyAfterTime.String())
	}
}

func TestParseServerConfig_HeaderProtectionKeyAndRandomTrailers(t *testing.T) {
	confText := `
[Interface]
PrivateKey = sPriv
Address = 10.8.1.1/24
ListenPort = 33950
MTU = 1280
HeaderProtectionKey = dGVzdC1oZWFkZXItcHJvdGVjdGlvbi1rZXktMTIzNDU=
RandomTrailers = on

[Peer]
PublicKey = pKey1
AllowedIPs = 10.8.1.2/32
`

	params, _, err := ParseServerConfig(confText)
	if err != nil {
		t.Fatalf("ParseServerConfig failed: %v", err)
	}

	if params["header_protection_key"] != "dGVzdC1oZWFkZXItcHJvdGVjdGlvbi1rZXktMTIzNDU=" {
		t.Errorf("expected header_protection_key to be extracted, got %q", params["header_protection_key"])
	}
	if params["random_trailers"] != "on" {
		t.Errorf("expected random_trailers 'on', got %q", params["random_trailers"])
	}

	// Test lowercase variant without underscores
	confLower := `
[Interface]
PrivateKey = sPriv
Address = 10.8.1.1/24
ListenPort = 33950
headerprotectionkey = abcdef123456
randomtrailers = true
`
	paramsLower, _, err := ParseServerConfig(confLower)
	if err != nil {
		t.Fatalf("ParseServerConfig failed: %v", err)
	}
	if paramsLower["header_protection_key"] != "abcdef123456" {
		t.Errorf("expected headerprotectionkey mapped to header_protection_key, got %q", paramsLower["header_protection_key"])
	}
	if paramsLower["random_trailers"] != "true" {
		t.Errorf("expected randomtrailers mapped to random_trailers, got %q", paramsLower["random_trailers"])
	}
}

func TestRenderClientConfig_HeaderProtectionKeyAndRandomTrailers(t *testing.T) {
	params := &AWGParams{
		HeaderProtectionKey: "dGVzdC1oZWFkZXItcHJvdGVjdGlvbi1rZXktMTIzNDU=",
		RandomTrailers:      "on",
	}

	cfg := RenderClientConfig("clientPriv", "10.8.1.2", "serverPub123", "psk123", "91.226.221.253:33950", "", "", "1280", params, nil)

	if !strings.Contains(cfg, "HeaderProtectionKey = dGVzdC1oZWFkZXItcHJvdGVjdGlvbi1rZXktMTIzNDU=") {
		t.Errorf("expected HeaderProtectionKey rendered in client config, got:\n%s", cfg)
	}
	if !strings.Contains(cfg, "RandomTrailers = on") {
		t.Errorf("expected RandomTrailers = on rendered in client config, got:\n%s", cfg)
	}
	if !strings.Contains(cfg, "PublicKey = serverPub123") {
		t.Errorf("expected PublicKey rendered in client config, got:\n%s", cfg)
	}

	// Guard against empty serverPubKey
	cfgEmptyPub := RenderClientConfig("clientPriv", "10.8.1.2", "", "psk123", "91.226.221.253:33950", "", "", "1280", params, nil)
	if !strings.Contains(cfgEmptyPub, "PublicKey = ") {
		t.Errorf("expected PublicKey = in client config, got:\n%s", cfgEmptyPub)
	}
}

func TestParseServerConfig_DisableCookies(t *testing.T) {
	confText := `
[Interface]
PrivateKey = sPriv
Address = 10.8.1.1/24
ListenPort = 33950
MTU = 1280
DisableCookies = on

[Peer]
PublicKey = pKey1
AllowedIPs = 10.8.1.2/32
`
	params, _, err := ParseServerConfig(confText)
	if err != nil {
		t.Fatalf("ParseServerConfig failed: %v", err)
	}
	if params["disable_cookies"] != "on" {
		t.Errorf("expected disable_cookies 'on', got %q", params["disable_cookies"])
	}

	// Test lowercase variant disablecookies
	confLower := `
[Interface]
PrivateKey = sPriv
Address = 10.8.1.1/24
disablecookies = on
`
	paramsLower, _, err := ParseServerConfig(confLower)
	if err != nil {
		t.Fatalf("ParseServerConfig failed: %v", err)
	}
	if paramsLower["disable_cookies"] != "on" {
		t.Errorf("expected disablecookies mapped to disable_cookies, got %q", paramsLower["disable_cookies"])
	}

	// Test snake_case variant disable_cookies
	confSnake := `
[Interface]
PrivateKey = sPriv
Address = 10.8.1.1/24
disable_cookies = on
`
	paramsSnake, _, err := ParseServerConfig(confSnake)
	if err != nil {
		t.Fatalf("ParseServerConfig failed: %v", err)
	}
	if paramsSnake["disable_cookies"] != "on" {
		t.Errorf("expected disable_cookies mapped to disable_cookies, got %q", paramsSnake["disable_cookies"])
	}
}

func TestRenderClientConfig_DisableCookies(t *testing.T) {
	params := &AWGParams{
		DisableCookies: "on",
	}
	cfg := RenderClientConfig("clientPriv", "10.8.1.2", "serverPub123", "psk123", "91.226.221.253:33950", "", "", "1280", params, nil)
	if !strings.Contains(cfg, "DisableCookies = on") {
		t.Errorf("expected DisableCookies = on in client config, got:\n%s", cfg)
	}
}

func TestRenderServerConfig_DisableCookies(t *testing.T) {
	params := &AWGParams{
		DisableCookies: "on",
	}
	conf := RenderServerConfig("serverPrivKey", "10.8.1.1", "24", "55424", "1280", params, nil)
	if !strings.Contains(conf, "DisableCookies = on") {
		t.Errorf("expected DisableCookies = on in server config, got:\n%s", conf)
	}
}

func TestParseCPSBlob_RejectsInvalidHex(t *testing.T) {
	// Valid hex blob
	validBytes, err := ParseCPSBlob("<b 0x01020304>")
	if err != nil {
		t.Fatalf("expected valid hex to parse, got err: %v", err)
	}
	if len(validBytes) != 4 || validBytes[0] != 1 || validBytes[3] != 4 {
		t.Errorf("unexpected bytes from valid blob: %x", validBytes)
	}

	// Non-hex characters in <b 0x...> blob (e.g. reported mflaredotcom corruption)
	_, err = ParseCPSBlob("<b 0x0102036dflaredotcom0405>")
	if err == nil {
		t.Fatalf("expected error for non-hex characters in CPS blob, got nil")
	}
	if !strings.Contains(err.Error(), "invalid hex in CPS blob") {
		t.Errorf("expected descriptive error mentioning invalid hex, got %v", err)
	}

	// Non-hex in random prefix blob
	_, err = ParseCPSBlob("<r 2><b 0x0102036dflaredotcom0405>")
	if err == nil {
		t.Fatalf("expected error for non-hex characters in random prefix CPS blob, got nil")
	}
	if !strings.Contains(err.Error(), "invalid hex in CPS blob") {
		t.Errorf("expected descriptive error mentioning invalid hex, got %v", err)
	}

	// Empty hex in <b 0x>
	_, err = ParseCPSBlob("<b 0x>")
	if err == nil {
		t.Fatalf("expected error for empty hex data in <b 0x>, got nil")
	}

	// Invalid characters zzzz
	_, err = ParseCPSBlob("<b 0xzzzz>")
	if err == nil {
		t.Fatalf("expected error for invalid hex zzzz, got nil")
	}
}

func TestRenderServerConfig_AWG31_Fields(t *testing.T) {
	tests := []struct {
		name    string
		params  *AWGParams
		want    []string
		wantAbs []string
	}{
		{
			name: "3.x_params_emit_hp_fields",
			params: &AWGParams{
				JunkPacketCount:       "4",
				InitPacketMagicHeader: "12345",
				HeaderProtectionKey:   "AbCdEf1234567890AbCdEf1234567890AbCdEf1234567=",
				RandomTrailers:        "on",
				DisableCookies:        "on",
			},
			want:    []string{"HeaderProtectionKey = AbCdEf1234567890AbCdEf1234567890AbCdEf1234567=", "RandomTrailers = on", "DisableCookies = on"},
			wantAbs: nil,
		},
		{
			name:    "2.0_params_omit_hp_fields",
			params:  &AWGParams{JunkPacketCount: "4", InitPacketMagicHeader: "12345"},
			want:    []string{"Jc = 4", "H1 = 12345"},
			wantAbs: []string{"HeaderProtectionKey", "RandomTrailers", "DisableCookies"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conf := RenderServerConfig("srvPriv", "10.8.1.1", "24", "55424", "1280", tc.params, nil)
			for _, want := range tc.want {
				if !strings.Contains(conf, want+"\n") {
					t.Errorf("server config missing line %q\nconfig:\n%s", want, conf)
				}
			}
			for _, absent := range tc.wantAbs {
				if strings.Contains(conf, absent) {
					t.Errorf("server config must not contain %q\nconfig:\n%s", absent, conf)
				}
			}
		})
	}

	// ContentPaddingAddition is client-side only: never in server config.
	conf := RenderServerConfig("srvPriv", "10.8.1.1", "24", "55424", "1280",
		&AWGParams{HeaderProtectionKey: "K==", ContentPaddingAddition: "16-64"}, nil)
	if strings.Contains(conf, "ContentPaddingAddition") {
		t.Errorf("server config must not contain ContentPaddingAddition")
	}
}

func TestRenderClientConfig_AWG31_Fields(t *testing.T) {
	hpKey := "ClientHPKeyAbCdEf1234567890AbCdEf1234567890="
	tests := []struct {
		name    string
		params  *AWGParams
		want    []string
		wantAbs []string
	}{
		{
			name: "3.x_params_emit_hp_key_and_flags",
			params: &AWGParams{
				JunkPacketCount:     "4",
				I1:                  "<b 0xdeadbeef>",
				HeaderProtectionKey: hpKey,
				RandomTrailers:      "on",
				DisableCookies:      "on",
			},
			want: []string{
				"HeaderProtectionKey = " + hpKey,
				"RandomTrailers = on",
				"DisableCookies = on",
			},
		},
		{
			name:    "2.0_params_omit_hp_fields",
			params:  &AWGParams{JunkPacketCount: "4"},
			wantAbs: []string{"HeaderProtectionKey", "RandomTrailers", "DisableCookies"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conf := RenderClientConfig("cliPriv", "10.8.1.2", "srvPub", "psk", "1.2.3.4:55424", "", "", "1280", tc.params, nil)
			for _, want := range tc.want {
				if !strings.Contains(conf, want+"\n") {
					t.Errorf("client config missing line %q\nconfig:\n%s", want, conf)
				}
			}
			for _, absent := range tc.wantAbs {
				if strings.Contains(conf, absent) {
					t.Errorf("client config must not contain %q\nconfig:\n%s", absent, conf)
				}
			}
		})
	}
}

// TestRenderClientConfig_AWG31_ServerParamsRoundTrip verifies the client HP key
// is derived from the server's parsed config (not regenerated): a 3.1 server
// config is parsed, mapped into AWGParams, and rendered into the client config
// with the identical HeaderProtectionKey value.
func TestRenderClientConfig_AWG31_ServerParamsRoundTrip(t *testing.T) {
	serverHPKey := "RoundTripHPKeyAbCdEf1234567890AbCdEf12345678="
	serverConf := RenderServerConfig("srvPriv", "10.8.1.1", "24", "55424", "1280", &AWGParams{
		JunkPacketCount:     "5",
		HeaderProtectionKey: serverHPKey,
		RandomTrailers:      "on",
		DisableCookies:      "on",
	}, nil)

	parsed, _, err := ParseServerConfig(serverConf)
	if err != nil {
		t.Fatalf("ParseServerConfig failed: %v", err)
	}
	if parsed["header_protection_key"] != serverHPKey {
		t.Fatalf("parsed header_protection_key = %q, want %q", parsed["header_protection_key"], serverHPKey)
	}
	if parsed["random_trailers"] != "on" || parsed["disable_cookies"] != "on" {
		t.Errorf("parsed flags = %q/%q, want on/on", parsed["random_trailers"], parsed["disable_cookies"])
	}

	parsedParams := AWGParamsFromMap(convertStringMapToAny(parsed))
	clientConf := RenderClientConfig("cliPriv", "10.8.1.2", "srvPub", "psk", "1.2.3.4:55424", "", "", "1280", parsedParams, nil)

	if !strings.Contains(clientConf, "HeaderProtectionKey = "+serverHPKey+"\n") {
		t.Errorf("client config HP key differs from server config\nclient:\n%s", clientConf)
	}
}

// TestRenderServerConfig_20Regression pins the exact 2.0 output: with no 3.x
// fields set the rendered config must be byte-identical to the pre-3.1 output.
func TestRenderServerConfig_20Regression(t *testing.T) {
	params := &AWGParams{
		JunkPacketCount:            "4",
		JunkPacketMinSize:          "30",
		JunkPacketMaxSize:          "80",
		InitPacketJunkSize:         "40",
		ResponsePacketJunkSize:     "60",
		CookieReplyPacketJunkSize:  "20",
		TransportPacketJunkSize:    "23",
		InitPacketMagicHeader:      "12345",
		ResponsePacketMagicHeader:  "67890",
		UnderloadPacketMagicHeader: "11111",
		TransportPacketMagicHeader: "22222",
	}
	peers := []AWGPeer{{PublicKey: "pubkey1", PresharedKey: "psk1", AllowedIPs: "10.8.1.2/32"}}

	got := RenderServerConfig("serverPrivKey", "10.8.1.1", "24", "55424", "1280", params, peers)
	want := `[Interface]
PrivateKey = serverPrivKey
Address = 10.8.1.1/24
MTU = 1280
ListenPort = 55424
Jc = 4
Jmin = 30
Jmax = 80
S1 = 40
S2 = 60
S3 = 20
S4 = 23
H1 = 12345
H2 = 67890
H3 = 11111
H4 = 22222

[Peer]
PublicKey = pubkey1
PresharedKey = psk1
AllowedIPs = 10.8.1.2/32
`
	if got != want {
		t.Errorf("2.0 server config changed.\ngot:\n%s\nwant:\n%s", got, want)
	}
}

// TestParseServerConfig_20ConfigUnchanged proves that adding the 3.x keys to
// ParseServerConfig's paramMap does not alter parsing of 2.0-only configs
// (every key/value must be identical, and no phantom keys appear).
func TestParseServerConfig_20ConfigUnchanged(t *testing.T) {
	conf20 := `[Interface]
PrivateKey = k
Address = 10.8.1.1/24
MTU = 1280
ListenPort = 55424
Jc = 4
Jmin = 30
Jmax = 80
S1 = 40
S2 = 60
H1 = 12345
H2 = 67890
`

	params, peers, err := ParseServerConfig(conf20)
	if err != nil {
		t.Fatalf("ParseServerConfig failed: %v", err)
	}
	if len(peers) != 0 {
		t.Errorf("expected no peers, got %d", len(peers))
	}
	wantParams := map[string]string{
		"Address":                      "10.8.1.1/24",
		"PrivateKey":                   "k",
		"port":                         "55424",
		"mtu":                          "1280",
		"junk_packet_count":            "4",
		"junk_packet_min_size":         "30",
		"junk_packet_max_size":         "80",
		"init_packet_junk_size":        "40",
		"response_packet_junk_size":    "60",
		"init_packet_magic_header":     "12345",
		"response_packet_magic_header": "67890",
	}
	if !reflect.DeepEqual(params, wantParams) {
		t.Errorf("parsed 2.0 params changed.\ngot:  %#v\nwant: %#v", params, wantParams)
	}
}
