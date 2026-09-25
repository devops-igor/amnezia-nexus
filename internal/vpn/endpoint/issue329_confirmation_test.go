package endpoint

import (
	"net"
	"strings"
	"testing"
	"time"
)

func issue329TestKeys(t *testing.T, localIndex uint32, fill byte) *TransportKeys {
	t.Helper()
	send := make([]byte, 32)
	recv := make([]byte, 32)
	for i := range send {
		send[i] = fill
		recv[i] = fill + 1
	}
	keys := &TransportKeys{
		SendKey:     send,
		RecvKey:     recv,
		LocalIndex:  localIndex,
		RemoteIndex: localIndex + 1000,
	}
	if err := keys.InitCiphers(); err != nil {
		t.Fatalf("InitCiphers: %v", err)
	}
	return keys
}

func issue329TestListener(t *testing.T) *Listener {
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

func issue329Stage(t *testing.T, el *Listener, peer string, keys *TransportKeys) {
	t.Helper()
	el.mu.Lock()
	defer el.mu.Unlock()
	el.stageResponderTransportKeysLocked(peer, keys)
}

func TestIssue329_AuthenticatedNextPromotesAtomically(t *testing.T) {
	el := issue329TestListener(t)
	peer := "issue329-promote"
	sender := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 49001}

	k1 := issue329TestKeys(t, 7001, 0x11)
	k2 := issue329TestKeys(t, 7002, 0x21)
	el.storeTransportKeys(peer, k1)
	issue329Stage(t, el, peer, k2)

	datagram := craftClientTransportDatagram(t, k2, healthDefaultH4ForIssue329(), el.config.S4, nil, 0, nil)
	if !el.handleTransportData(datagram, sender) {
		t.Fatal("valid K2 transport was not recognized")
	}

	previous, current, next := el.PeerKeypairStateForTest(peer)
	if previous != k1 || current != k2 || next != nil {
		t.Fatalf("unexpected promoted state: previous=%p current=%p next=%p", previous, current, next)
	}
	if got, ok := el.confirmedTransportKeysFor(peer); !ok || got != k2 {
		t.Fatalf("confirmed outbound key = %p, %v; want K2 %p", got, ok, k2)
	}
}

func TestIssue329_InvalidAEADDoesNotPromoteNext(t *testing.T) {
	el := issue329TestListener(t)
	peer := "issue329-invalid-aead"
	sender := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 49002}

	k1 := issue329TestKeys(t, 7101, 0x31)
	k2 := issue329TestKeys(t, 7102, 0x41)
	el.storeTransportKeys(peer, k1)
	issue329Stage(t, el, peer, k2)

	forged := issue329TestKeys(t, k2.LocalIndex, 0x51)
	forged.RemoteIndex = k2.RemoteIndex
	datagram := craftClientTransportDatagram(t, forged, healthDefaultH4ForIssue329(), el.config.S4, nil, 0, []byte("forged"))
	if !el.handleTransportData(datagram, sender) {
		t.Fatal("forged transport was not classified as transport")
	}

	previous, current, next := el.PeerKeypairStateForTest(peer)
	if previous != nil || current != k1 || next != k2 {
		t.Fatalf("invalid AEAD changed key state: previous=%p current=%p next=%p", previous, current, next)
	}
}

func TestIssue329_ReplayRejectedNextDoesNotPromote(t *testing.T) {
	el := issue329TestListener(t)
	peer := "issue329-replay"
	sender := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 49003}

	k1 := issue329TestKeys(t, 7201, 0x61)
	k2 := issue329TestKeys(t, 7202, 0x71)
	el.storeTransportKeys(peer, k1)
	issue329Stage(t, el, peer, k2)

	const counter = uint64(9)
	if !k2.ValidateCounter(counter) {
		t.Fatal("precondition: counter should be accepted once")
	}
	datagram := craftClientTransportDatagram(t, k2, healthDefaultH4ForIssue329(), el.config.S4, nil, counter, nil)
	if !el.handleTransportData(datagram, sender) {
		t.Fatal("replayed transport was not classified as transport")
	}

	previous, current, next := el.PeerKeypairStateForTest(peer)
	if previous != nil || current != k1 || next != k2 {
		t.Fatalf("replay rejection changed key state: previous=%p current=%p next=%p", previous, current, next)
	}
}

func TestIssue329_ExpiredNextDoesNotPromote(t *testing.T) {
	el := issue329TestListener(t)
	peer := "issue329-expired"
	sender := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 49004}

	k1 := issue329TestKeys(t, 7301, 0x81)
	k2 := issue329TestKeys(t, 7302, 0x91)
	el.storeTransportKeys(peer, k1)
	issue329Stage(t, el, peer, k2)
	k2.SetExpiresAt(time.Now().Add(-time.Second))

	datagram := craftClientTransportDatagram(t, k2, healthDefaultH4ForIssue329(), el.config.S4, nil, 0, nil)
	if !el.handleTransportData(datagram, sender) {
		t.Fatal("expired transport was not classified as transport")
	}

	previous, current, next := el.PeerKeypairStateForTest(peer)
	if previous != nil || current != k1 || next != k2 {
		t.Fatalf("expired next changed key state: previous=%p current=%p next=%p", previous, current, next)
	}
}

func TestIssue329_SupersededNextCannotPromoteFromStalePacket(t *testing.T) {
	el := issue329TestListener(t)
	peer := "issue329-stale-next"
	sender := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 49005}

	k1 := issue329TestKeys(t, 7401, 0xa1)
	k2 := issue329TestKeys(t, 7402, 0xb1)
	k3 := issue329TestKeys(t, 7403, 0xc1)
	el.storeTransportKeys(peer, k1)
	issue329Stage(t, el, peer, k2)
	issue329Stage(t, el, peer, k3)
	el.rememberPeer(sender, peer, k3.RemoteIndex)

	datagram := craftClientTransportDatagram(t, k2, healthDefaultH4ForIssue329(), el.config.S4, nil, 0, nil)
	if !el.handleTransportData(datagram, sender) {
		t.Fatal("stale K2 packet should still be classified as transport")
	}

	previous, current, next := el.PeerKeypairStateForTest(peer)
	if previous != nil || current != k1 || next != k3 {
		t.Fatalf("stale superseded K2 changed state: previous=%p current=%p next=%p", previous, current, next)
	}
}

func TestIssue329_SendToPeerRejectsUnconfirmedInitialNext(t *testing.T) {
	el := issue329TestListener(t)
	peer := "issue329-unconfirmed-initial"
	k1 := issue329TestKeys(t, 7501, 0xd1)
	issue329Stage(t, el, peer, k1)

	err := el.SendToPeer(peer, []byte("must-not-use-next"))
	if err == nil || !strings.Contains(err.Error(), "no confirmed transport keys") {
		t.Fatalf("SendToPeer error = %v, want no confirmed transport keys", err)
	}

	previous, current, next := el.PeerKeypairStateForTest(peer)
	if previous != nil || current != nil || next != k1 {
		t.Fatalf("SendToPeer mutated unconfirmed state: previous=%p current=%p next=%p", previous, current, next)
	}
}

// Keep the tests independent from randomized H4 ranges while using the
// production default transport message type.
func healthDefaultH4ForIssue329() uint32 {
	return 2528465083
}
