package preflight

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/security"
	"golang.org/x/crypto/curve25519"
)

var auditTime = time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)

func testKeys(n byte) (string, string) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = n
	}
	pub, _ := curve25519.X25519(key, curve25519.Basepoint)
	return base64.StdEncoding.EncodeToString(key), base64.StdEncoding.EncodeToString(pub)
}

func testJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func fixture(t *testing.T) Snapshot {
	t.Helper()
	private, public := testKeys(17)
	encrypted, err := security.EncryptCredential(private, "test-secret")
	if err != nil {
		t.Fatal(err)
	}
	clientPrivate, clientPublic := testKeys(33)
	return Snapshot{
		Config: testJSON(map[string]any{"server_private_key": encrypted, "server_public_key": public,
			"subnet_cidr": "10.100.0.0/24", "listen_port": 51820, "h1": "100-200", "s4": 25}),
		Connections: []Connection{{ID: "a", UserID: "u", Protocol: "awg", PublicKey: clientPublic,
			ClientParams: testJSON(map[string]any{"assigned_ip": "10.100.0.2", "client_private_key": clientPrivate}),
			User:         &User{Enabled: true}}},
	}
}

func changeParam(c *Connection, name string, value any) {
	var params map[string]any
	_ = json.Unmarshal([]byte(c.ClientParams), &params)
	params[name] = value
	c.ClientParams = testJSON(params)
}

func changeConfig(s *Snapshot, name string, value any) {
	var cfg map[string]any
	_ = json.Unmarshal([]byte(s.Config), &cfg)
	cfg[name] = value
	s.Config = testJSON(cfg)
}

func TestValidatePreservesIdentityAndInput(t *testing.T) {
	s := fixture(t)
	before, _ := json.Marshal(s)
	r := Validate(s, "test-secret", auditTime)
	if !r.Ready || !r.PortalIdentity || len(r.Peers) != 1 {
		t.Fatalf("valid fixture rejected: %+v", r)
	}
	p := r.Peers[0]
	if p.PublicKey != s.Connections[0].PublicKey || p.AllowedIP != "10.100.0.2/32" || !strings.Contains(p.UAPI(), "replace_allowed_ips=true\nallowed_ip=10.100.0.2/32\n") {
		t.Fatal("peer definition changed durable identity")
	}
	after, _ := json.Marshal(s)
	if string(before) != string(after) {
		t.Fatal("validation mutated input")
	}
	encoded, _ := json.Marshal(r)
	private, _ := testKeys(33)
	portalPrivate, _ := testKeys(17)
	for _, secret := range []string{private, portalPrivate, "test-secret", "server_private_key", "client_private_key\""} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("report exposed secret input")
		}
	}
}

func TestInvalidConnectionsFailClosed(t *testing.T) {
	cases := []struct {
		name, code string
		change     func(*Connection)
	}{
		{"missing user", "missing_user", func(c *Connection) { c.User = nil }},
		{"bad expiry", "invalid_expiry", func(c *Connection) { c.User.ExpiresAt = "not-a-date" }},
		{"dummy key", "invalid_public_key", func(c *Connection) { c.PublicKey = "dummy-key" }},
		{"zero key", "invalid_public_key", func(c *Connection) { c.PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32)) }},
		{"low order", "invalid_public_key", func(c *Connection) {
			b := make([]byte, 32)
			b[0] = 1
			c.PublicKey = base64.StdEncoding.EncodeToString(b)
		}},
		{"key whitespace", "invalid_public_key", func(c *Connection) { c.PublicKey += "\n" }},
		{"bad JSON", "invalid_client_params", func(c *Connection) { c.ClientParams = "{broken" }},
		{"null JSON", "invalid_client_params", func(c *Connection) { c.ClientParams = "null" }},
		{"array JSON", "invalid_client_params", func(c *Connection) { c.ClientParams = "[]" }},
		{"missing IP", "invalid_assigned_ip", func(c *Connection) { changeParam(c, "assigned_ip", nil) }},
		{"IPv6", "invalid_assigned_ip", func(c *Connection) { changeParam(c, "assigned_ip", "::1") }},
		{"IPv4 mapped IPv6", "invalid_assigned_ip", func(c *Connection) { changeParam(c, "assigned_ip", "::ffff:10.100.0.2") }},
		{"prefix", "invalid_assigned_ip", func(c *Connection) { changeParam(c, "assigned_ip", "10.100.0.2/32") }},
		{"outside", "ip_outside_subnet", func(c *Connection) { changeParam(c, "assigned_ip", "10.101.0.2") }},
		{"network", "reserved_ip", func(c *Connection) { changeParam(c, "assigned_ip", "10.100.0.0") }},
		{"gateway", "reserved_ip", func(c *Connection) { changeParam(c, "assigned_ip", "10.100.0.1") }},
		{"broadcast", "reserved_ip", func(c *Connection) { changeParam(c, "assigned_ip", "10.100.0.255") }},
		{"private missing", "invalid_client_private_key", func(c *Connection) { changeParam(c, "client_private_key", "") }},
		{"private mismatch", "client_identity_mismatch", func(c *Connection) { key, _ := testKeys(44); changeParam(c, "client_private_key", key) }},
		{"bad flag", "invalid_quarantine_flag", func(c *Connection) { changeParam(c, "config_regeneration_required", "false") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := fixture(t)
			tc.change(&s.Connections[0])
			before, _ := json.Marshal(s)
			r := Validate(s, "test-secret", auditTime)
			if r.Ready || len(r.Peers) != 0 || r.Connections[0].Status != "invalid" || !hasCode(r.Connections[0].Problems, tc.code) {
				t.Fatalf("expected %s with no installable peer: %+v", tc.code, r)
			}
			after, _ := json.Marshal(s)
			if string(before) != string(after) {
				t.Fatal("invalid row was repaired")
			}
		})
	}
}

func hasCode(problems []Problem, code string) bool {
	for _, p := range problems {
		if p.Code == code {
			return true
		}
	}
	return false
}

func TestExclusionsAndProtocolScope(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Connection)
	}{
		{"disabled", func(c *Connection) { c.User.Enabled = false }},
		{"expired", func(c *Connection) { c.User.ExpiresAt = "2026-09-27T00:00:00Z" }},
		{"legacy expiry", func(c *Connection) { c.User.ExpirationDate = "2026-09-27" }},
		{"quota", func(c *Connection) { c.User.TrafficLimit = 1; c.User.TrafficUsed = 1 }},
		{"regeneration", func(c *Connection) { changeParam(c, "config_regeneration_required", true) }},
		{"collision", func(c *Connection) { changeParam(c, "quarantined_ip_collision", "10.100.0.2") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fixture(t)
			tc.change(&s.Connections[0])
			// Excluded rows may retain incomplete historical identity.
			s.Connections[0].PublicKey = ""
			r := Validate(s, "test-secret", auditTime)
			if !r.Ready || len(r.Peers) != 0 || r.Connections[0].Status != "excluded" {
				t.Fatalf("unexpected report: %+v", r)
			}
		})
	}
	for _, proto := range []string{"awg", "awg2", "awg_legacy", "xray", "unknown"} {
		s := fixture(t)
		s.Connections[0].Protocol = proto
		r := Validate(s, "test-secret", auditTime)
		want := 1
		if proto == "xray" || proto == "unknown" {
			want = 0
		}
		if len(r.Peers) != want {
			t.Fatalf("protocol %s produced %d peers", proto, len(r.Peers))
		}
		s.Connections[0].ServerID = 1
		if len(Validate(s, "test-secret", auditTime).Peers) != 0 {
			t.Fatal("remote connection installed")
		}
	}
}

func TestDuplicatesRejectEveryClaimantDeterministically(t *testing.T) {
	for _, sameKey := range []bool{true, false} {
		s := fixture(t)
		second := s.Connections[0]
		second.ID = "b"
		if sameKey {
			changeParam(&second, "assigned_ip", "10.100.0.3")
		} else {
			private, public := testKeys(55)
			second.PublicKey = public
			changeParam(&second, "client_private_key", private)
		}
		s.Connections = append(s.Connections, second)
		r := Validate(s, "test-secret", auditTime)
		if r.Ready || len(r.Peers) != 0 || r.Connections[0].Status != "invalid" || r.Connections[1].Status != "invalid" {
			t.Fatalf("duplicate claim accepted: %+v", r)
		}
		s.Connections[0], s.Connections[1] = s.Connections[1], s.Connections[0]
		if !reflect.DeepEqual(r, Validate(s, "test-secret", auditTime)) {
			t.Fatal("report depends on input row order")
		}
	}
}

func TestPortalConfigurationFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		change     func(*Snapshot)
	}{
		{"missing", "invalid_vpn_config", func(s *Snapshot) { s.Config = "" }},
		{"null", "invalid_vpn_config", func(s *Snapshot) { s.Config = " null " }},
		{"malformed", "invalid_vpn_config", func(s *Snapshot) { s.Config = "{secret" }},
		{"plaintext", "portal_key_decryption_failed", func(s *Snapshot) { key, _ := testKeys(17); changeConfig(s, "server_private_key", key) }},
		{"mismatch", "portal_identity_mismatch", func(s *Snapshot) { _, key := testKeys(55); changeConfig(s, "server_public_key", key) }},
		{"missing public", "portal_identity_mismatch", func(s *Snapshot) { changeConfig(s, "server_public_key", "") }},
		{"missing private", "invalid_portal_private_key", func(s *Snapshot) { changeConfig(s, "server_private_key", "") }},
		{"subnet", "invalid_subnet", func(s *Snapshot) { changeConfig(s, "subnet_cidr", "10.100.0.0/31") }},
		{"missing subnet", "invalid_subnet", func(s *Snapshot) { changeConfig(s, "subnet_cidr", "") }},
		{"port", "invalid_listen_port", func(s *Snapshot) { changeConfig(s, "listen_port", 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fixture(t)
			tc.change(&s)
			r := Validate(s, "test-secret", auditTime)
			if r.Ready || len(r.Peers) != 0 || !hasCode(r.Problems, tc.code) {
				t.Fatalf("expected %s: %+v", tc.code, r)
			}
		})
	}
	r := Validate(fixture(t), "wrong-secret", auditTime)
	if r.Ready || r.PortalIdentity || !hasCode(r.Problems, "portal_key_decryption_failed") {
		t.Fatal("wrong secret accepted")
	}
}

func TestPeerCannotUsePortalIdentity(t *testing.T) {
	s := fixture(t)
	private, public := testKeys(17)
	s.Connections[0].PublicKey = public
	changeParam(&s.Connections[0], "client_private_key", private)
	r := Validate(s, "test-secret", auditTime)
	if r.Ready || len(r.Peers) != 0 || !hasCode(r.Connections[0].Problems, "peer_is_portal") {
		t.Fatal("portal identity accepted as a client peer")
	}
}
