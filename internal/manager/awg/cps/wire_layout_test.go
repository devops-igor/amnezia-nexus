package cps

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// simulateWire simulates upstream amneziawg-go tag concatenation on the wire.
// In amneziawg-go (device/obf.go, device/send.go), tags are processed sequentially:
// <r N> emits N random bytes, and <b 0xHEX> emits the decoded binary payload.
func simulateWire(tagStr string) ([]byte, error) {
	s := strings.TrimSpace(tagStr)
	if s == "" {
		return nil, nil
	}
	var wire []byte
	remaining := s
	for {
		start := strings.IndexByte(remaining, '<')
		if start == -1 {
			break
		}
		end := strings.IndexByte(remaining[start:], '>')
		if end == -1 {
			return nil, fmt.Errorf("missing '>' in tag: %s", remaining)
		}
		end += start
		tag := remaining[start+1 : end]
		parts := strings.Fields(tag)
		if len(parts) == 0 {
			remaining = remaining[end+1:]
			continue
		}
		switch parts[0] {
		case "b":
			if len(parts) < 2 {
				return nil, errors.New("empty hex in b tag")
			}
			hexStr := strings.TrimPrefix(parts[1], "0x")
			data, err := hex.DecodeString(hexStr)
			if err != nil {
				return nil, fmt.Errorf("invalid hex in wire simulation: %w", err)
			}
			wire = append(wire, data...)
		case "r":
			if len(parts) < 2 {
				return nil, errors.New("missing count in r tag")
			}
			n, err := strconv.Atoi(parts[1])
			if err != nil || n < 0 {
				return nil, fmt.Errorf("invalid count in r tag: %s", parts[1])
			}
			rnd := make([]byte, n)
			if _, err := rand.Read(rnd); err != nil {
				return nil, fmt.Errorf("failed to read random bytes: %w", err)
			}
			wire = append(wire, rnd...)
		default:
			return nil, fmt.Errorf("unknown tag %q in wire simulation", parts[0])
		}
		remaining = remaining[end+1:]
	}
	return wire, nil
}

func TestWireLayout_DNS_StrictFraming(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		genFunc        func() (map[string]string, error)
		expectedDomain string
	}{
		{
			name: "GenerateCPSPackets lite one.one.one.one",
			genFunc: func() (map[string]string, error) {
				return GenerateCPSPackets("lite", "one.one.one.one")
			},
			expectedDomain: "one.one.one.one",
		},
		{
			name: "GenerateCPSPackets lite icloud.com",
			genFunc: func() (map[string]string, error) {
				return GenerateCPSPackets("lite", "icloud.com")
			},
			expectedDomain: "icloud.com",
		},
		{
			name: "GenerateCPSPackets lite default domain",
			genFunc: func() (map[string]string, error) {
				return GenerateCPSPackets("lite", "")
			},
			expectedDomain: "icloud.com",
		},
		{
			name: "GenerateMimicryPackets dns one.one.one.one",
			genFunc: func() (map[string]string, error) {
				return GenerateMimicryPackets(ctx, "dns", "one.one.one.one", nil)
			},
			expectedDomain: "one.one.one.one",
		},
		{
			name: "GenerateMimicryPackets dns icloud.com",
			genFunc: func() (map[string]string, error) {
				return GenerateMimicryPackets(ctx, "dns", "icloud.com", nil)
			},
			expectedDomain: "icloud.com",
		},
		{
			name: "GenerateMimicryPackets dns default domain",
			genFunc: func() (map[string]string, error) {
				return GenerateMimicryPackets(ctx, "dns", "", nil)
			},
			expectedDomain: "one.one.one.one",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkts, err := tt.genFunc()
			if err != nil {
				t.Fatalf("packet generation failed: %v", err)
			}
			tagStr, ok := pkts["i1"]
			if !ok || tagStr == "" {
				t.Fatalf("expected non-empty i1 packet tag")
			}

			// Simulate upstream amneziawg-go wire serialization
			wire, err := simulateWire(tagStr)
			if err != nil {
				t.Fatalf("simulateWire failed: %v", err)
			}

			// Parse via cps.ParseCPSBlob
			parsed, err := ParseCPSBlob(tagStr)
			if err != nil {
				t.Fatalf("ParseCPSBlob failed: %v", err)
			}

			// 1. Assert len(wire) == len(ParseCPSBlob)
			if len(wire) != len(parsed) {
				t.Fatalf("wire length (%d) != ParseCPSBlob length (%d)", len(wire), len(parsed))
			}

			// 2. Strictly parse wire bytes using dnsmessage.Message.Unpack
			var msg dnsmessage.Message
			if err := msg.Unpack(wire); err != nil {
				t.Fatalf("strict dnsmessage.Unpack failed on wire bytes: %v", err)
			}

			// Assert !Header.Response (Query, QR=0)
			if msg.Header.Response {
				t.Errorf("expected DNS query (!Header.Response), got response")
			}

			// Assert QDCOUNT == 1
			if len(msg.Questions) != 1 {
				t.Errorf("expected QDCOUNT == 1, got %d questions", len(msg.Questions))
			}

			// Assert ANCOUNT == 0
			if len(msg.Answers) != 0 {
				t.Errorf("expected ANCOUNT == 0, got %d answers", len(msg.Answers))
			}

			// Assert valid question name matching target domain
			if len(msg.Questions) == 1 {
				qName := strings.TrimSuffix(msg.Questions[0].Name.String(), ".")
				if qName != tt.expectedDomain {
					t.Errorf("expected QNAME %q, got %q", tt.expectedDomain, qName)
				}
				if msg.Questions[0].Type != dnsmessage.TypeA {
					t.Errorf("expected TypeA (1), got %v", msg.Questions[0].Type)
				}
				if msg.Questions[0].Class != dnsmessage.ClassINET {
					t.Errorf("expected ClassINET (1), got %v", msg.Questions[0].Class)
				}
			}

			// 3. Also verify that ParseCPSBlob result unpacks cleanly as identical DNS query
			var parsedMsg dnsmessage.Message
			if err := parsedMsg.Unpack(parsed); err != nil {
				t.Fatalf("strict dnsmessage.Unpack failed on ParseCPSBlob bytes: %v", err)
			}
			if parsedMsg.Header.Response {
				t.Errorf("expected parsed DNS query (!Header.Response), got response")
			}
			if len(parsedMsg.Questions) != 1 {
				t.Errorf("expected parsed QDCOUNT == 1, got %d questions", len(parsedMsg.Questions))
			}
			if len(parsedMsg.Answers) != 0 {
				t.Errorf("expected parsed ANCOUNT == 0, got %d answers", len(parsedMsg.Answers))
			}
		})
	}
}

func TestWireLayout_AllProfiles_LengthEquivalence(t *testing.T) {
	ctx := context.Background()

	type profileCase struct {
		name    string
		genFunc func() (map[string]string, error)
	}

	cases := []profileCase{
		{"CPS_lite", func() (map[string]string, error) { return GenerateCPSPackets("lite", "example.com") }},
		{"CPS_standard", func() (map[string]string, error) { return GenerateCPSPackets("standard", "example.com") }},
		{"CPS_pro", func() (map[string]string, error) { return GenerateCPSPackets("pro", "example.com") }},
		{"Mimicry_tls", func() (map[string]string, error) { return GenerateMimicryPackets(ctx, "tls", "example.com", nil) }},
		{"Mimicry_dns", func() (map[string]string, error) { return GenerateMimicryPackets(ctx, "dns", "example.com", nil) }},
		{"Mimicry_sip", func() (map[string]string, error) { return GenerateMimicryPackets(ctx, "sip", "example.com", nil) }},
		{"Mimicry_quic", func() (map[string]string, error) { return GenerateMimicryPackets(ctx, "quic", "example.com", nil) }},
		{"Mimicry_auto", func() (map[string]string, error) { return GenerateMimicryPackets(ctx, "auto", "example.com", nil) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkts, err := tc.genFunc()
			if err != nil {
				t.Fatalf("generation failed for %s: %v", tc.name, err)
			}
			for _, k := range []string{"i1", "i2", "i3", "i4", "i5"} {
				tagStr := pkts[k]
				if tagStr == "" {
					continue
				}
				wire, err := simulateWire(tagStr)
				if err != nil {
					t.Fatalf("simulateWire failed for %s[%s]: %v", tc.name, k, err)
				}
				parsed, err := ParseCPSBlob(tagStr)
				if err != nil {
					t.Fatalf("ParseCPSBlob failed for %s[%s]: %v", tc.name, k, err)
				}
				if len(wire) != len(parsed) {
					t.Errorf("%s[%s]: wire length (%d) != ParseCPSBlob length (%d)", tc.name, k, len(wire), len(parsed))
				}
			}
		})
	}
}

func TestSimulateWire_Errors(t *testing.T) {
	tests := []struct {
		name    string
		tag     string
		wantErr bool
	}{
		{"empty string", "", false},
		{"valid blob", "<b 0x01020304>", false},
		{"valid random and blob", "<r 2><b 0x0102>", false},
		{"invalid hex", "<b 0xzz>", true},
		{"missing hex value", "<b >", true},
		{"unclosed tag", "<r 2", true},
		{"invalid r count non-numeric", "<r abc><b 0x01>", true},
		{"negative r count", "<r -1><b 0x01>", true},
		{"missing r count", "<r ><b 0x01>", true},
		{"unknown tag", "<unknown 123>", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := simulateWire(tt.tag)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for tag %q, got nil (wire=%x)", tt.tag, wire)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for tag %q: %v", tt.tag, err)
				}
			}
		})
	}
}
