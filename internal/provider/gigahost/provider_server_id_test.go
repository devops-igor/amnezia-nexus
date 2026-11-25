package gigahost

// Identity state space for a provider server id.
//
// A server id is compared against durable rows and written into the panel's own records,
// so every shape the wire can carry has exactly one required outcome here, and the point of
// the table is that "unusable" is explicit rather than coerced into a neighbouring id.

import (
	"encoding/json"
	"math"
	"testing"
)

func TestDecodeProviderServerID_StateSpace(t *testing.T) {
	const maxInt64 = int64(math.MaxInt64)

	cases := []struct {
		name    string
		wire    string // raw JSON token as it appears in a payload
		wantID  int64
		wantErr bool
	}{
		{name: "integer in range", wire: `501`, wantID: 501},
		{name: "zero", wire: `0`, wantID: 0},
		{name: "largest exact integer", wire: `9223372036854775807`, wantID: maxInt64},
		{name: "integer out of range", wire: `9223372036854775808`, wantErr: true},
		{name: "negative integer", wire: `-5`, wantID: -5},
		{name: "fractional", wire: `501.5`, wantErr: true},
		{name: "tiny fraction", wire: `501.000001`, wantErr: true},
		{name: "whole number spelled with a decimal point", wire: `501.0`, wantID: 501},
		{name: "whole number spelled with an exponent", wire: `5.01e2`, wantID: 501},
		{name: "exponent that is not whole", wire: `5.015e2`, wantErr: true},
		{name: "numeric string", wire: `"501"`, wantID: 501},
		{name: "numeric string with padding", wire: `" 501 "`, wantID: 501},
		{name: "numeric string with a decimal point", wire: `"501.5"`, wantErr: true},
		{name: "non-numeric string", wire: `"not-a-server"`, wantErr: true},
		{name: "empty string", wire: `""`, wantErr: true},
		{name: "fraction syntax", wire: `"4/2"`, wantErr: true},
		{name: "hex spelling", wire: `"0x1f5"`, wantErr: true},
		{name: "boolean", wire: `true`, wantErr: true},
		{name: "object", wire: `{"id":501}`, wantErr: true},
		{name: "array", wire: `[501]`, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var val any
			if err := decodeJSONUseNumber([]byte(tc.wire), &val); err != nil {
				t.Fatalf("test token is not JSON: %v", err)
			}
			id, err := decodeProviderServerID(val)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("wire %s decoded to id %d; an unusable identity must be refused", tc.wire, id)
				}
				return
			}
			if err != nil {
				t.Fatalf("wire %s refused: %v", tc.wire, err)
			}
			if id != tc.wantID {
				t.Fatalf("wire %s decoded to %d, want %d", tc.wire, id, tc.wantID)
			}
		})
	}
}

// The decoded value is what every consumer of ServerInfo.ID sees: a listing entry with an
// unusable id must not decode into a neighbouring server.
func TestServerInfoUnmarshal_RejectsUnusableServerID(t *testing.T) {
	unusable := []string{
		`{"srv_id":501.5}`,
		`{"id":501.5}`,
		`{"srv_id":"501.5"}`,
		`{"srv_id":"abc"}`,
		`{"srv_id":9223372036854775808}`,
		`{"srv_id":true}`,
	}
	for _, payload := range unusable {
		t.Run(payload, func(t *testing.T) {
			var info ServerInfo
			if err := json.Unmarshal([]byte(payload), &info); err == nil {
				t.Fatalf("payload %s decoded to id %d; a lost identity must fail the decode", payload, info.ID)
			}
		})
	}

	// The documented shapes still decode, and they decode to the same identity.
	usable := map[string]int64{
		`{"srv_id":501}`:           501,
		`{"srv_id":"501"}`:         501,
		`{"id":501}`:               501,
		`{"srv_id":501.0}`:         501,
		`{"srv_id":null,"id":501}`: 501,
	}
	for payload, want := range usable {
		var info ServerInfo
		if err := json.Unmarshal([]byte(payload), &info); err != nil {
			t.Fatalf("payload %s refused: %v", payload, err)
		}
		if info.ID != want {
			t.Fatalf("payload %s decoded to %d, want %d", payload, info.ID, want)
		}
	}

	// A null or absent id names no server: the decode leaves it at zero and the identity
	// gate refuses it, which is a different outcome from "silently a valid id".
	for _, payload := range []string{`{"srv_id":null}`, `{}`} {
		var info ServerInfo
		if err := json.Unmarshal([]byte(payload), &info); err != nil {
			t.Fatalf("payload %s refused: %v", payload, err)
		}
		if info.ID != 0 {
			t.Fatalf("payload %s decoded to %d, want 0 (no server named)", payload, info.ID)
		}
	}
}

// A large integer must survive exactly: the float64 route would round it into a different
// server, which is the defect this table exists to prevent.
func TestServerInfoUnmarshal_LargeIDIsExact(t *testing.T) {
	var info ServerInfo
	if err := json.Unmarshal([]byte(`{"srv_id":9007199254740993}`), &info); err != nil {
		t.Fatalf("large exact id refused: %v", err)
	}
	if info.ID != 9007199254740993 {
		t.Fatalf("large id decoded to %d, want 9007199254740993", info.ID)
	}
}
