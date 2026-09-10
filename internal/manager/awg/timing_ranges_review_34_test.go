package awg

import (
	"encoding/json"
	"testing"
)

func TestProbe_SerializeRoundTrip(t *testing.T) {
	degen := DegenerateTimingRange(125)
	rng := NewTimingRange(100, 140)
	ud := AWGClientUserData{ClientName: "u", Enabled: true, RekeyAfterTime: degen, RejectAfterTime: rng, PersistentKeepalive: degen}
	b, err := json.Marshal(&ud)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("marshal: %s", b)

	var rt AWGClientUserData
	if err := json.Unmarshal(b, &rt); err != nil {
		t.Fatalf("round-trip unmarshal FAILED: %v", err)
	}
	t.Logf("round-trip: rat=%s rej=%s pk=%s", rt.RekeyAfterTime.String(), rt.RejectAfterTime.String(), rt.PersistentKeepalive.String())

	// huge float inside clientsTable JSON
	huge := `{"ClientName":"x","Enabled":true,"rekey_after_time":1e300}`
	var rt2 AWGClientUserData
	if err := json.Unmarshal([]byte(huge), &rt2); err != nil {
		t.Logf("huge float -> unmarshal ERR: %v", err)
	} else {
		t.Logf("huge float -> parsed rat=%s (Lo=%d Hi=%d)", rt2.RekeyAfterTime.String(), rt2.RekeyAfterTime.Lo, rt2.RekeyAfterTime.Hi)
	}

	// SerializeClientsTable full path
	s, err := SerializeClientsTable([]AWGClient{{ClientID: "k", UserData: ud}})
	if err != nil {
		t.Fatal(err)
	}
	clients, err := ParseClientsTable(s)
	t.Logf("table round-trip: err=%v n=%d rat0=%s", err, len(clients), func() string {
		if len(clients) > 0 && clients[0].UserData.RekeyAfterTime != nil {
			return clients[0].UserData.RekeyAfterTime.String()
		}
		return "nil"
	}())
}
