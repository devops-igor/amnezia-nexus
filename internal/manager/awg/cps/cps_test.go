package cps

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	gossh "golang.org/x/crypto/ssh"
)

func TestGenTLS(t *testing.T) {
	pkt, err := GenTLS("example.com")
	if err != nil {
		t.Fatalf("GenTLS failed: %v", err)
	}

	if len(pkt) < 100 {
		t.Fatalf("GenTLS returned packet too short: %d bytes", len(pkt))
	}

	// Check TLS Record Header: Handshake (0x16), Version (0x0301)
	if pkt[0] != 0x16 || pkt[1] != 0x03 || pkt[2] != 0x01 {
		t.Errorf("invalid TLS record header: %x %x %x", pkt[0], pkt[1], pkt[2])
	}

	// Check Handshake Type: ClientHello (0x01)
	if pkt[5] != 0x01 {
		t.Errorf("invalid handshake type: %x", pkt[5])
	}

	// Check that domain is present in SNI
	if !bytes.Contains(pkt, []byte("example.com")) {
		t.Errorf("domain example.com not found in TLS ClientHello")
	}

	// Test default domain selection
	pktDef, err := GenTLS("")
	if err != nil {
		t.Fatalf("GenTLS with default domain failed: %v", err)
	}
	if len(pktDef) < 100 {
		t.Fatalf("GenTLS default domain returned packet too short")
	}
}

func TestGenQUICInitial(t *testing.T) {
	pkt, err := GenQUICInitial("example.com")
	if err != nil {
		t.Fatalf("GenQUICInitial failed: %v", err)
	}

	if len(pkt) != 216 {
		t.Fatalf("GenQUICInitial expected 216 bytes, got %d", len(pkt))
	}

	// First byte must have high bits set (0xC0 or 0xC3)
	if pkt[0] != 0xC0 && pkt[0] != 0xC3 {
		t.Errorf("unexpected first byte in QUIC initial: 0x%02X", pkt[0])
	}

	// QUIC v1 Version: 0x00000001 at bytes 1..4
	if !bytes.Equal(pkt[1:5], []byte{0x00, 0x00, 0x00, 0x01}) {
		t.Errorf("unexpected QUIC version: %x", pkt[1:5])
	}

	// DCID len and SCID len must be 8
	if pkt[5] != 8 || pkt[14] != 8 {
		t.Errorf("unexpected CID lengths: DCID len=%d, SCID len=%d", pkt[5], pkt[14])
	}
}

func TestGenQUICShort(t *testing.T) {
	pkt, err := GenQUICShort()
	if err != nil {
		t.Fatalf("GenQUICShort failed: %v", err)
	}

	if len(pkt) < 49 || len(pkt) > 105 {
		t.Fatalf("GenQUICShort expected 49-105 bytes, got %d", len(pkt))
	}

	// Short header first byte has fixed 0x40 bit set
	if pkt[0]&0x40 == 0 {
		t.Errorf("short header fixed bit not set: 0x%02X", pkt[0])
	}
}

func TestGenDNS(t *testing.T) {
	pkt, err := GenDNS("google.com")
	if err != nil {
		t.Fatalf("GenDNS failed: %v", err)
	}

	if len(pkt) < 20 {
		t.Fatalf("GenDNS returned packet too short: %d", len(pkt))
	}

	// Flags: 0x0100
	if pkt[0] != 0x01 || pkt[1] != 0x00 {
		t.Errorf("invalid DNS flags: %x %x", pkt[0], pkt[1])
	}

	// Check domain labels: \x06google\x03com\x00
	expectedQName := []byte("\x06google\x03com\x00")
	if !bytes.Contains(pkt, expectedQName) {
		t.Errorf("DNS QNAME not formatted correctly")
	}

	// Test default domain
	pktDef, err := GenDNS("")
	if err != nil {
		t.Fatalf("GenDNS default domain failed: %v", err)
	}
	if len(pktDef) < 20 {
		t.Fatalf("GenDNS default domain returned packet too short")
	}
}

func TestGenSIP(t *testing.T) {
	pkt, err := GenSIP("sip.example.com")
	if err != nil {
		t.Fatalf("GenSIP failed: %v", err)
	}

	str := string(pkt)
	if !strings.HasPrefix(str, "REGISTER sip:sip.example.com SIP/2.0\r\n") {
		t.Errorf("invalid SIP request line: %s", str[:40])
	}

	if !strings.Contains(str, "User-Agent:") || !strings.Contains(str, "Content-Length: 0\r\n\r\n") {
		t.Errorf("missing standard SIP headers")
	}

	// Test default domain
	pktDef, err := GenSIP("")
	if err != nil {
		t.Fatalf("GenSIP default domain failed: %v", err)
	}
	if !strings.Contains(string(pktDef), "REGISTER sip:") {
		t.Errorf("missing SIP register in default domain generation")
	}
}

func TestCPSBlobConversion(t *testing.T) {
	raw := []byte{0xde, 0xad, 0xbe, 0xef}
	tag := ToCPS(raw)
	if tag != "<b 0xdeadbeef>" {
		t.Errorf("unexpected ToCPS output: %s", tag)
	}

	parsed, err := ParseCPSBlob(tag)
	if err != nil {
		t.Fatalf("ParseCPSBlob failed: %v", err)
	}
	if !bytes.Equal(parsed, raw) {
		t.Errorf("parsed bytes mismatch: expected %x, got %x", raw, parsed)
	}

	// Test empty tag
	empty, err := ParseCPSBlob("")
	if err != nil || empty != nil {
		t.Errorf("expected nil for empty tag, got %v, err: %v", empty, err)
	}

	// Test <r N> random prefix tag
	rTag := "<r 2><b 0x11223344>"
	rParsed, err := ParseCPSBlob(rTag)
	if err != nil {
		t.Fatalf("ParseCPSBlob with <r 2> failed: %v", err)
	}
	if len(rParsed) != 6 {
		t.Fatalf("expected 6 bytes, got %d", len(rParsed))
	}
	// Suffix should match original data bytes [0x11, 0x22, 0x33, 0x44]
	if !bytes.Equal(rParsed[2:], []byte{0x11, 0x22, 0x33, 0x44}) {
		t.Errorf("data suffix changed: expected [11 22 33 44], got %x", rParsed[2:])
	}

	// Invalid tags
	if _, err := ParseCPSBlob("invalid"); err == nil {
		t.Errorf("expected error for invalid tag format")
	}
	if _, err := ParseCPSBlob("<b 0xzzzz>"); err == nil {
		t.Errorf("expected error for invalid hex in tag")
	}
}

func TestParseCPSBlob_RandomPrefixBounds(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		wantLen int
	}{
		{
			name:    "max int64 overflow does not panic",
			input:   "<r 9223372036854775807><b 0x1122>",
			wantErr: true,
		},
		{
			name:    "exceeds 65535",
			input:   "<r 65536><b 0x1122>",
			wantErr: true,
		},
		{
			name:    "zero count",
			input:   "<r 0><b 0x1122>",
			wantErr: true,
		},
		{
			name:    "negative count",
			input:   "<r -1><b 0x1122>",
			wantErr: true,
		},
		{
			name:    "valid count 2",
			input:   "<r 2><b 0x11223344>",
			wantErr: false,
			wantLen: 6,
		},
		{
			name:    "non-numeric count",
			input:   "<r abc><b 0x1122>",
			wantErr: true,
		},
		{
			name:    "unclosed r tag",
			input:   "<r 2<b 0x1122>",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCPSBlob(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseCPSBlob(%q) expected error, got nil (len=%d)", tt.input, len(got))
				}
			} else {
				if err != nil {
					t.Fatalf("ParseCPSBlob(%q) unexpected error: %v", tt.input, err)
				}
				if len(got) != tt.wantLen {
					t.Errorf("ParseCPSBlob(%q) len = %d, want %d", tt.input, len(got), tt.wantLen)
				}
			}
		})
	}
}

func TestGenerateCPSPackets(t *testing.T) {
	// Lite
	litePackets, err := GenerateCPSPackets("lite", "example.com")
	if err != nil {
		t.Fatalf("GenerateCPSPackets(lite) failed: %v", err)
	}
	if !strings.HasPrefix(litePackets["i1"], "<r 2><b 0x") || litePackets["i2"] != "" {
		t.Errorf("unexpected lite packets: %+v", litePackets)
	}

	// Standard
	stdPackets, err := GenerateCPSPackets("standard", "example.com")
	if err != nil {
		t.Fatalf("GenerateCPSPackets(standard) failed: %v", err)
	}
	if !strings.HasPrefix(stdPackets["i1"], "<b 0x") || stdPackets["i2"] != "" {
		t.Errorf("unexpected standard packets: %+v", stdPackets)
	}

	// Pro
	proPackets, err := GenerateCPSPackets("pro", "example.com")
	if err != nil {
		t.Fatalf("GenerateCPSPackets(pro) failed: %v", err)
	}
	for _, k := range []string{"i1", "i2", "i3", "i4", "i5"} {
		if !strings.HasPrefix(proPackets[k], "<b 0x") {
			t.Errorf("expected pro packet for %s, got: %s", k, proPackets[k])
		}
	}
}

func TestGenerateMimicryPackets(t *testing.T) {
	ctx := context.Background()
	profiles := []string{"tls", "dns", "sip", "quic", "auto"}

	for _, proto := range profiles {
		packets, err := GenerateMimicryPackets(ctx, proto, "example.com", nil)
		if err != nil {
			t.Fatalf("GenerateMimicryPackets(%s) failed: %v", proto, err)
		}
		if packets["i1"] == "" {
			t.Errorf("expected non-empty i1 for profile %s", proto)
		}
	}
}

type mockCPSSSHClient struct {
	fail bool
}

func (m *mockCPSSSHClient) RunCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if m.fail {
		return "FAIL", "", 1, nil
	}
	return "OK", "", 0, nil
}
func (m *mockCPSSSHClient) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	return m.RunCommand(ctx, cmd)
}
func (m *mockCPSSSHClient) RunScript(ctx context.Context, script string) (string, string, int, error) {
	return "OK", "", 0, nil
}
func (m *mockCPSSSHClient) RunSudoScript(ctx context.Context, script string) (string, string, int, error) {
	return "OK", "", 0, nil
}
func (m *mockCPSSSHClient) UploadFile(ctx context.Context, remotePath string, content []byte, mode os.FileMode) error {
	return nil
}
func (m *mockCPSSSHClient) UploadSudoFile(ctx context.Context, remotePath string, content []byte, mode os.FileMode) error {
	return nil
}
func (m *mockCPSSSHClient) DownloadFile(ctx context.Context, remotePath string) ([]byte, error) {
	return []byte("test"), nil
}
func (m *mockCPSSSHClient) FileExists(ctx context.Context, remotePath string) (bool, error) {
	return true, nil
}
func (m *mockCPSSSHClient) TestConnection(ctx context.Context) (string, error) {
	return "Linux", nil
}
func (m *mockCPSSSHClient) Close() error {
	return nil
}
func (m *mockCPSSSHClient) IsAlive() bool {
	return true
}
func (m *mockCPSSSHClient) GetUnderlyingClient() *gossh.Client {
	return nil
}
func (m *mockCPSSSHClient) GetHost() string {
	return "127.0.0.1"
}
func (m *mockCPSSSHClient) GetPort() int {
	return 22
}
func (m *mockCPSSSHClient) GetUser() string {
	return "root"
}
func (m *mockCPSSSHClient) GetServerID() *int64 {
	return nil
}
func (m *mockCPSSSHClient) GetLastActive() time.Time {
	return time.Now()
}

func TestSelectMimicryDomain(t *testing.T) {
	ctx := context.Background()

	// Nil client -> fallback
	d, err := SelectMimicryDomain(ctx, nil, "tls")
	if err != nil || d != "www.google.com" {
		t.Errorf("expected www.google.com, got %s (err: %v)", d, err)
	}

	// Active client returning OK
	mockSuccess := &mockCPSSSHClient{fail: false}
	for _, proto := range []string{"tls", "quic", "dns", "sip", "unknown"} {
		d, err := SelectMimicryDomain(ctx, mockSuccess, proto)
		if err != nil || d == "" {
			t.Errorf("SelectMimicryDomain(%s) failed: %v", proto, err)
		}
	}

	// Active client returning FAIL -> fallback
	mockFail := &mockCPSSSHClient{fail: true}
	dFail, err := SelectMimicryDomain(ctx, mockFail, "sip")
	if err != nil || dFail != "sip.linphone.org" {
		t.Errorf("expected sip.linphone.org fallback, got %s", dFail)
	}

	// GenerateMimicryPackets with active SSH client auto profile
	mp, err := GenerateMimicryPackets(ctx, "auto", "", mockSuccess)
	if err != nil || mp["i1"] == "" {
		t.Errorf("GenerateMimicryPackets(auto) failed: %v", err)
	}
}

func TestGenerateMimicryPackets_AutoResolvesToSIP(t *testing.T) {
	ctx := context.Background()
	mockSuccess := &mockCPSSSHClient{fail: false}

	tests := []struct {
		name      string
		mimicry   string
		sshClient *mockCPSSSHClient
	}{
		{name: "empty_mimicry_nil_client", mimicry: "", sshClient: nil},
		{name: "auto_mimicry_nil_client", mimicry: "auto", sshClient: nil},
		{name: "empty_mimicry_with_client", mimicry: "", sshClient: mockSuccess},
		{name: "auto_mimicry_with_client", mimicry: "auto", sshClient: mockSuccess},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var client ssh.SSHClient
			if tt.sshClient != nil {
				client = tt.sshClient
			}
			pkts, err := GenerateMimicryPackets(ctx, tt.mimicry, "", client)
			if err != nil {
				t.Fatalf("GenerateMimicryPackets(%q) failed: %v", tt.mimicry, err)
			}
			i1 := pkts["i1"]
			if i1 == "" {
				t.Fatalf("expected non-empty i1")
			}
			raw, err := ParseCPSBlob(i1)
			if err != nil {
				t.Fatalf("ParseCPSBlob failed: %v", err)
			}
			rawStr := string(raw)
			if !strings.Contains(rawStr, "REGISTER sip:") {
				t.Errorf("expected I1 to contain 'REGISTER sip:', got: %s", rawStr)
			}
			if !strings.Contains(rawStr, "Content-Length: 0") {
				t.Errorf("expected I1 to contain 'Content-Length: 0', got: %s", rawStr)
			}
			for _, k := range []string{"i2", "i3", "i4", "i5"} {
				if pkts[k] != "" {
					t.Errorf("expected empty %s for SIP, got %q", k, pkts[k])
				}
			}
		})
	}
}

func TestGenerateCPSPackets_Protocols(t *testing.T) {
	tests := []struct {
		name      string
		profile   string
		domain    string
		protocol  []string
		wantProto string
		checkPkt  func(t *testing.T, pkts map[string]string)
	}{
		{
			name:      "sip_via_variadic",
			profile:   "standard",
			domain:    "sip.example.com",
			protocol:  []string{"sip"},
			wantProto: "sip",
			checkPkt: func(t *testing.T, pkts map[string]string) {
				t.Helper()
				raw, err := ParseCPSBlob(pkts["i1"])
				if err != nil {
					t.Fatalf("ParseCPSBlob(i1) failed: %v", err)
				}
				rawStr := string(raw)
				if !strings.Contains(rawStr, "REGISTER sip:") {
					t.Errorf("expected I1 to contain 'REGISTER sip:', got: %s", rawStr)
				}
				if !strings.Contains(rawStr, "Content-Length: 0") {
					t.Errorf("expected I1 to contain 'Content-Length: 0', got: %s", rawStr)
				}
				for _, k := range []string{"i2", "i3", "i4", "i5"} {
					if pkts[k] != "" {
						t.Errorf("expected empty %s for sip, got %q", k, pkts[k])
					}
				}
			},
		},
		{
			name:      "sip_via_profile_name",
			profile:   "sip",
			domain:    "sip.example.com",
			protocol:  nil,
			wantProto: "sip",
			checkPkt: func(t *testing.T, pkts map[string]string) {
				t.Helper()
				raw, err := ParseCPSBlob(pkts["i1"])
				if err != nil {
					t.Fatalf("ParseCPSBlob(i1) failed: %v", err)
				}
				rawStr := string(raw)
				if !strings.Contains(rawStr, "REGISTER sip:") {
					t.Errorf("expected I1 to contain 'REGISTER sip:', got: %s", rawStr)
				}
				if !strings.Contains(rawStr, "Content-Length: 0") {
					t.Errorf("expected I1 to contain 'Content-Length: 0', got: %s", rawStr)
				}
			},
		},
		{
			name:      "dns_via_variadic",
			profile:   "standard",
			domain:    "example.com",
			protocol:  []string{"dns"},
			wantProto: "dns",
			checkPkt: func(t *testing.T, pkts map[string]string) {
				t.Helper()
				if !strings.HasPrefix(pkts["i1"], "<r 2><b 0x") {
					t.Errorf("expected dns I1 to have '<r 2><b 0x' tag, got: %s", pkts["i1"])
				}
				raw, err := ParseCPSBlob(pkts["i1"])
				if err != nil {
					t.Fatalf("ParseCPSBlob(i1) failed: %v", err)
				}
				if len(raw) < 12 {
					t.Errorf("dns packet too short: %d bytes", len(raw))
				}
				for _, k := range []string{"i2", "i3", "i4", "i5"} {
					if pkts[k] != "" {
						t.Errorf("expected empty %s for dns, got %q", k, pkts[k])
					}
				}
			},
		},
		{
			name:      "dns_via_profile_name",
			profile:   "dns",
			domain:    "example.com",
			protocol:  nil,
			wantProto: "dns",
			checkPkt: func(t *testing.T, pkts map[string]string) {
				t.Helper()
				if !strings.HasPrefix(pkts["i1"], "<r 2><b 0x") {
					t.Errorf("expected dns I1 to have '<r 2><b 0x' tag, got: %s", pkts["i1"])
				}
			},
		},
		{
			name:      "quic_standard_via_variadic",
			profile:   "standard",
			domain:    "example.com",
			protocol:  []string{"quic"},
			wantProto: "quic",
			checkPkt: func(t *testing.T, pkts map[string]string) {
				t.Helper()
				if !strings.HasPrefix(pkts["i1"], "<b 0x") {
					t.Errorf("expected quic I1 to start with '<b 0x', got: %s", pkts["i1"])
				}
				for _, k := range []string{"i2", "i3", "i4", "i5"} {
					if pkts[k] != "" {
						t.Errorf("expected empty %s for standard quic, got %q", k, pkts[k])
					}
				}
			},
		},
		{
			name:      "quic_pro_via_variadic",
			profile:   "pro",
			domain:    "example.com",
			protocol:  []string{"quic"},
			wantProto: "quic",
			checkPkt: func(t *testing.T, pkts map[string]string) {
				t.Helper()
				for _, k := range []string{"i1", "i2", "i3", "i4", "i5"} {
					if !strings.HasPrefix(pkts[k], "<b 0x") {
						t.Errorf("expected pro quic %s to start with '<b 0x', got: %s", k, pkts[k])
					}
				}
			},
		},
		{
			name:      "quic_via_profile_name",
			profile:   "quic",
			domain:    "example.com",
			protocol:  nil,
			wantProto: "quic",
			checkPkt: func(t *testing.T, pkts map[string]string) {
				t.Helper()
				if !strings.HasPrefix(pkts["i1"], "<b 0x") {
					t.Errorf("expected quic I1 to start with '<b 0x', got: %s", pkts["i1"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkts, err := GenerateCPSPackets(tt.profile, tt.domain, tt.protocol...)
			if err != nil {
				t.Fatalf("GenerateCPSPackets failed: %v", err)
			}
			tt.checkPkt(t, pkts)
		})
	}
}
