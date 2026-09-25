package endpoint

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

func TestResponderTransitionDiagnosticsAreBoundedAndSecretFree(t *testing.T) {
	el := issue328TestListener(t)
	peer := "peer-public-identifier"
	k1 := issue328TestKeys(t, 12345, 0x11)
	k1.Generation = 1
	k2 := issue328TestKeys(t, 23456, 0x22)
	k2.Generation = 2
	k2.SendKey = []byte("SECRET_SEND_KEY_BYTES_123456789012")
	k2.RecvKey = []byte("SECRET_RECV_KEY_BYTES_123456789012")

	var output bytes.Buffer
	previousOutput := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(previousOutput)

	stageIssue328ResponderKeys(t, el, peer, k1)
	if status, ok := el.confirmResponderTransportKey(peer, k1); !ok || status != "current" {
		t.Fatal("initial key did not confirm")
	}
	stageIssue328ResponderKeys(t, el, peer, k2)
	// Accelerate only the observation clock; no test needs to sleep a minute.
	k2.CreatedAt = time.Now().Add(-70 * time.Second)
	k2.ExpiresAt = time.Now().Add(2 * time.Minute)
	el.sweepExpiredKeypairs()
	firstWarning := output.String()
	if !strings.Contains(firstWarning, "event=next_unconfirmed") ||
		!strings.Contains(firstWarning, "outbound_gen=1 inbound_gen=1") {
		t.Fatalf("pending key/outbound diagnostics missing: %s", firstWarning)
	}
	el.sweepExpiredKeypairs()
	if output.String() != firstWarning {
		t.Fatal("pending next warning repeated during throttle window")
	}
	if status, ok := el.confirmResponderTransportKey(peer, k2); !ok || status != "current" {
		t.Fatal("next key did not promote")
	}
	promoted := output.String()
	for _, expected := range []string{
		"event=derived_next", "event=promoted", "old_gen=1 old_idx=12345", "new_gen=2 new_idx=23456",
		"inbound_gen=2 outbound_gen=2",
	} {
		if !strings.Contains(promoted, expected) {
			t.Errorf("missing %q in transition diagnostics: %s", expected, promoted)
		}
	}
	for _, secret := range []string{string(k2.SendKey), string(k2.RecvKey)} {
		if strings.Contains(promoted, secret) {
			t.Fatal("transport key bytes appeared in transition diagnostics")
		}
	}
	for i := 0; i < 10; i++ {
		el.confirmResponderTransportKey(peer, k2)
	}
	if output.String() != promoted {
		t.Fatal("repeated transport confirmation emitted per-packet diagnostics")
	}
}
