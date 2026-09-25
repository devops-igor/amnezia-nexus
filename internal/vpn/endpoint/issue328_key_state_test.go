package endpoint

import (
	"testing"
	"time"
)

func issue328TestKeys(t *testing.T, localIndex uint32, fill byte) *TransportKeys {
	t.Helper()
	send := make([]byte, 32)
	recv := make([]byte, 32)
	for i := range send {
		send[i] = fill
		recv[i] = fill + 1
	}
	keys := &TransportKeys{
		SendKey:    send,
		RecvKey:    recv,
		LocalIndex: localIndex,
		RemoteIndex: localIndex + 1000,
	}
	if err := keys.InitCiphers(); err != nil {
		t.Fatalf("InitCiphers: %v", err)
	}
	return keys
}

func issue328TestListener(t *testing.T) *Listener {
	t.Helper()
	el, err := NewListener(ListenerConfig{
		SubnetCIDR:      "10.100.0.0/24",
		RejectAfterTime: time.Minute,
	}, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	return el
}

func stageIssue328ResponderKeys(t *testing.T, el *Listener, peer string, keys *TransportKeys) {
	t.Helper()
	el.mu.Lock()
	defer el.mu.Unlock()
	el.stageResponderTransportKeysLocked(peer, keys)
}

func TestIssue328_InitialResponderKeyUsesNextSlot(t *testing.T) {
	el := issue328TestListener(t)
	peer := "issue328-initial"
	k1 := issue328TestKeys(t, 1001, 0x11)

	stageIssue328ResponderKeys(t, el, peer, k1)

	previous, current, next := el.PeerKeypairStateForTest(peer)
	if previous != nil {
		t.Fatalf("previous = %p, want nil", previous)
	}
	if current != nil {
		t.Fatalf("current = %p, want nil before responder confirmation", current)
	}
	if next != k1 {
		t.Fatalf("next = %p, want k1 %p", next, k1)
	}

	got, ok := el.LookupKeypairByIndexForTest(k1.LocalIndex)
	if !ok || got != k1 {
		t.Fatalf("receiver index %d did not resolve staged next key", k1.LocalIndex)
	}
	if status := el.keypairStatus(peer, k1); status != "next" {
		t.Fatalf("keypairStatus(k1) = %q, want next", status)
	}
}

func TestIssue328_ReplacingNextPreservesCurrentAndBoundsIndexes(t *testing.T) {
	el := issue328TestListener(t)
	peer := "issue328-replace-next"

	k1 := issue328TestKeys(t, 2001, 0x21)
	el.storeTransportKeys(peer, k1) // legacy confirmed-current setup

	k2 := issue328TestKeys(t, 2002, 0x31)
	stageIssue328ResponderKeys(t, el, peer, k2)

	previous, current, next := el.PeerKeypairStateForTest(peer)
	if previous != nil || current != k1 || next != k2 {
		t.Fatalf("unexpected state after first stage: previous=%p current=%p next=%p", previous, current, next)
	}

	k3 := issue328TestKeys(t, 2003, 0x41)
	stageIssue328ResponderKeys(t, el, peer, k3)

	previous, current, next = el.PeerKeypairStateForTest(peer)
	if previous != nil {
		t.Fatalf("previous changed while replacing unconfirmed next: %p", previous)
	}
	if current != k1 {
		t.Fatalf("current changed while replacing unconfirmed next: got %p want %p", current, k1)
	}
	if next != k3 {
		t.Fatalf("next = %p, want newest staged key %p", next, k3)
	}

	if _, ok := el.LookupKeypairByIndexForTest(k2.LocalIndex); ok {
		t.Fatalf("superseded next receiver index %d leaked", k2.LocalIndex)
	}
	if got, ok := el.LookupKeypairByIndexForTest(k1.LocalIndex); !ok || got != k1 {
		t.Fatalf("confirmed current receiver index %d was lost", k1.LocalIndex)
	}
	if got, ok := el.LookupKeypairByIndexForTest(k3.LocalIndex); !ok || got != k3 {
		t.Fatalf("new next receiver index %d was not registered", k3.LocalIndex)
	}
	if count := el.IndexTableCountForTest(); count != 2 {
		t.Fatalf("index table count = %d, want 2 (current + next)", count)
	}
}

func TestIssue328_ExpiryRetiresPreviousAndNextButKeepsCurrent(t *testing.T) {
	el := issue328TestListener(t)
	peer := "issue328-expiry"

	k0 := issue328TestKeys(t, 3000, 0x51)
	k1 := issue328TestKeys(t, 3001, 0x61)
	el.storeTransportKeys(peer, k0)
	el.storeTransportKeys(peer, k1) // k0 -> previous, k1 -> current

	k2 := issue328TestKeys(t, 3002, 0x71)
	stageIssue328ResponderKeys(t, el, peer, k2)

	k0.SetExpiresAt(time.Now().Add(-time.Second))
	k2.SetExpiresAt(time.Now().Add(-time.Second))
	el.sweepExpiredKeypairs()

	previous, current, next := el.PeerKeypairStateForTest(peer)
	if previous != nil {
		t.Fatalf("expired previous survived sweep: %p", previous)
	}
	if current != k1 {
		t.Fatalf("current changed during previous/next expiry sweep: got %p want %p", current, k1)
	}
	if next != nil {
		t.Fatalf("expired next survived sweep: %p", next)
	}

	if _, ok := el.LookupKeypairByIndexForTest(k0.LocalIndex); ok {
		t.Fatalf("expired previous index %d survived sweep", k0.LocalIndex)
	}
	if _, ok := el.LookupKeypairByIndexForTest(k2.LocalIndex); ok {
		t.Fatalf("expired next index %d survived sweep", k2.LocalIndex)
	}
	if got, ok := el.LookupKeypairByIndexForTest(k1.LocalIndex); !ok || got != k1 {
		t.Fatalf("current index %d was removed by sweep", k1.LocalIndex)
	}
}

func TestIssue328_PruneRemovesPreviousCurrentNextAndIndexes(t *testing.T) {
	el := issue328TestListener(t)
	peer := "issue328-prune"

	k0 := issue328TestKeys(t, 4000, 0x81)
	k1 := issue328TestKeys(t, 4001, 0x91)
	el.storeTransportKeys(peer, k0)
	el.storeTransportKeys(peer, k1)

	k2 := issue328TestKeys(t, 4002, 0xa1)
	stageIssue328ResponderKeys(t, el, peer, k2)

	if count := el.IndexTableCountForTest(); count != 3 {
		t.Fatalf("precondition: index table count = %d, want 3", count)
	}

	if !el.PrunePeerTransportState(peer) {
		t.Fatal("PrunePeerTransportState returned false")
	}

	previous, current, next := el.PeerKeypairStateForTest(peer)
	if previous != nil || current != nil || next != nil {
		t.Fatalf("key state survived prune: previous=%p current=%p next=%p", previous, current, next)
	}
	for _, idx := range []uint32{k0.LocalIndex, k1.LocalIndex, k2.LocalIndex} {
		if _, ok := el.LookupKeypairByIndexForTest(idx); ok {
			t.Fatalf("receiver index %d survived prune", idx)
		}
	}
	if _, ok := el.TransportKeysFor(peer); ok {
		t.Fatal("legacy transport-key alias survived prune")
	}
}

func TestIssue328_ReplayStateIsIndependentPerSlot(t *testing.T) {
	el := issue328TestListener(t)
	peer := "issue328-replay"

	current := issue328TestKeys(t, 5001, 0xb1)
	el.storeTransportKeys(peer, current)
	next := issue328TestKeys(t, 5002, 0xc1)
	stageIssue328ResponderKeys(t, el, peer, next)

	if !current.ValidateCounter(7) {
		t.Fatal("current counter 7 should be accepted initially")
	}
	if current.ValidateCounter(7) {
		t.Fatal("current duplicate counter 7 should be rejected")
	}
	if !next.ValidateCounter(7) {
		t.Fatal("next counter 7 should remain independently acceptable")
	}
	if next.ValidateCounter(7) {
		t.Fatal("next duplicate counter 7 should be rejected")
	}
}
