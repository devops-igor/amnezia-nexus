package endpoint

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func issue329ListenerWithUDP(t *testing.T) (*Listener, *net.UDPConn) {
	t.Helper()
	el := issue328TestListener(t)
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP server: %v", err)
	}
	t.Cleanup(func() { _ = serverConn.Close() })

	el.mu.Lock()
	el.udpConn = serverConn
	el.mu.Unlock()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP client: %v", err)
	}
	t.Cleanup(func() { _ = clientConn.Close() })
	return el, clientConn
}

func issue329ReadOutbound(t *testing.T, conn *net.UDPConn, wantKeys *TransportKeys, wantPayload []byte) {
	t.Helper()
	buf := make([]byte, 2048)
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read outbound: %v", err)
	}
	datagram := buf[:n]
	s4 := 0
	if len(datagram) < transportDataHeaderLen+chacha20poly1305.Overhead {
		t.Fatalf("outbound datagram too short: %d", len(datagram))
	}

	receiverIdx := binary.LittleEndian.Uint32(datagram[s4+4 : s4+8])
	if receiverIdx != wantKeys.RemoteIndex {
		t.Fatalf("receiver index = %d, want %d", receiverIdx, wantKeys.RemoteIndex)
	}
	counter := binary.LittleEndian.Uint64(datagram[s4+8 : s4+16])

	aead, err := chacha20poly1305.New(wantKeys.SendKey)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	plain, err := aead.Open(nil, nonce[:], datagram[transportDataHeaderLen:], nil)
	if err != nil {
		t.Fatalf("decrypt outbound with expected key: %v", err)
	}
	if !bytes.Equal(plain, wantPayload) {
		t.Fatalf("payload = %q, want %q", plain, wantPayload)
	}
}

func TestIssue329_UnconfirmedNextKeepsCurrentOutbound(t *testing.T) {
	el, clientConn := issue329ListenerWithUDP(t)
	peer := "issue329-lost-response"

	k1 := issue328TestKeys(t, 6101, 0x11)
	k1.RemoteIndex = 7101
	el.storeTransportKeys(peer, k1)
	el.rememberPeer(clientConn.LocalAddr().(*net.UDPAddr), peer, k1.RemoteIndex)

	k2 := issue328TestKeys(t, 6102, 0x21)
	k2.RemoteIndex = 7102
	stageIssue328ResponderKeys(t, el, peer, k2)

	previous, current, next := el.PeerKeypairStateForTest(peer)
	if previous != nil || current != k1 || next != k2 {
		t.Fatalf("unexpected pending state: previous=%p current=%p next=%p", previous, current, next)
	}
	if effective, ok := el.TransportKeysFor(peer); !ok || effective != k1 {
		t.Fatalf("outbound alias changed before confirmation: got %p want K1 %p", effective, k1)
	}

	payload := []byte("reply-while-k2-unconfirmed")
	if err := el.SendToPeer(peer, payload); err != nil {
		t.Fatalf("SendToPeer: %v", err)
	}
	issue329ReadOutbound(t, clientConn, k1, payload)
}

func TestIssue329_AuthenticatedNextPromotesAndSwitchesOutbound(t *testing.T) {
	el, clientConn := issue329ListenerWithUDP(t)
	peer := "issue329-confirm"

	k1 := issue328TestKeys(t, 6201, 0x31)
	k1.RemoteIndex = 7201
	el.storeTransportKeys(peer, k1)
	el.rememberPeer(clientConn.LocalAddr().(*net.UDPAddr), peer, k1.RemoteIndex)

	k2 := issue328TestKeys(t, 6202, 0x41)
	k2.RemoteIndex = 7202
	stageIssue328ResponderKeys(t, el, peer, k2)

	packet := craftClientTransportDatagram(t, k2, el.config.H4.PickOne(), el.config.S4, nil, 1, []byte("confirm-k2"))
	if !el.handleTransportData(packet, clientConn.LocalAddr().(*net.UDPAddr)) {
		t.Fatal("K2 confirmation transport was not handled")
	}

	previous, current, next := el.PeerKeypairStateForTest(peer)
	if previous != k1 || current != k2 || next != nil {
		t.Fatalf("unexpected promoted state: previous=%p current=%p next=%p", previous, current, next)
	}
	if effective, ok := el.TransportKeysFor(peer); !ok || effective != k2 {
		t.Fatalf("outbound alias = %p, want confirmed K2 %p", effective, k2)
	}

	st, ok := el.peerByAddr(clientConn.LocalAddr().String())
	if !ok || st == nil {
		t.Fatal("confirmed endpoint was not recorded")
	}
	if got := st.receiverIdx.Load(); got != k2.RemoteIndex {
		t.Fatalf("confirmed endpoint receiver index = %d, want %d", got, k2.RemoteIndex)
	}

	payload := []byte("reply-after-k2-confirm")
	if err := el.SendToPeer(peer, payload); err != nil {
		t.Fatalf("SendToPeer: %v", err)
	}
	issue329ReadOutbound(t, clientConn, k2, payload)
}

func TestIssue329_InvalidReplayAndExpiredNextCannotPromote(t *testing.T) {
	el := issue328TestListener(t)
	peer := "issue329-no-false-promotion"
	sender := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43001}

	k1 := issue328TestKeys(t, 6301, 0x51)
	el.storeTransportKeys(peer, k1)

	// Invalid AEAD: next remains pending.
	k2 := issue328TestKeys(t, 6302, 0x61)
	stageIssue328ResponderKeys(t, el, peer, k2)
	bad := craftClientTransportDatagram(t, k2, el.config.H4.PickOne(), el.config.S4, nil, 2, []byte("bad"))
	bad[len(bad)-1] ^= 0xff
	if !el.handleTransportData(bad, sender) {
		t.Fatal("invalid K2 transport was not classified as transport")
	}
	_, current, next := el.PeerKeypairStateForTest(peer)
	if current != k1 || next != k2 {
		t.Fatalf("invalid AEAD promoted next: current=%p next=%p", current, next)
	}

	// Replay rejection: pre-consume the counter, then submit an otherwise
	// authenticated packet carrying the same counter.
	k3 := issue328TestKeys(t, 6303, 0x71)
	stageIssue328ResponderKeys(t, el, peer, k3)
	if !k3.ValidateCounter(7) {
		t.Fatal("precondition: counter 7 should be initially valid")
	}
	replay := craftClientTransportDatagram(t, k3, el.config.H4.PickOne(), el.config.S4, nil, 7, []byte("replay"))
	if !el.handleTransportData(replay, sender) {
		t.Fatal("replayed K3 transport was not classified as transport")
	}
	_, current, next = el.PeerKeypairStateForTest(peer)
	if current != k1 || next != k3 {
		t.Fatalf("replayed transport promoted next: current=%p next=%p", current, next)
	}

	// Expired next cannot promote even through the direct confirmation gate.
	k4 := issue328TestKeys(t, 6304, 0x81)
	stageIssue328ResponderKeys(t, el, peer, k4)
	k4.SetExpiresAt(time.Now().Add(-time.Second))
	if status, ok := el.ConfirmResponderTransportKeyForTest(peer, k4); ok || status != "expired" {
		t.Fatalf("expired next confirmation = (%q,%v), want (expired,false)", status, ok)
	}
	_, current, next = el.PeerKeypairStateForTest(peer)
	if current != k1 || next != k4 {
		t.Fatalf("expired next mutated state: current=%p next=%p", current, next)
	}
}

func TestIssue329_CommitHandshakeDoesNotAdoptUnconfirmedEndpoint(t *testing.T) {
	el := issue328TestListener(t)
	peer := "issue329-endpoint"
	oldAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 44001}
	newAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 44002}

	k1 := issue328TestKeys(t, 6401, 0x91)
	k1.RemoteIndex = 7401
	el.storeTransportKeys(peer, k1)
	el.rememberPeer(oldAddr, peer, k1.RemoteIndex)
	oldState, ok := el.peerByAddr(oldAddr.String())
	if !ok || oldState == nil {
		t.Fatal("precondition: old confirmed endpoint missing")
	}

	k2 := issue328TestKeys(t, 6402, 0xa1)
	k2.RemoteIndex = 7402
	if !el.CommitHandshake(peer, 2, k2, newAddr, k2.RemoteIndex) {
		t.Fatal("CommitHandshake rejected non-stale K2")
	}

	if _, ok := el.peerByAddr(newAddr.String()); ok {
		t.Fatal("unconfirmed handshake sender was adopted as peer endpoint")
	}
	_, current, next := el.PeerKeypairStateForTest(peer)
	if current != k1 || next != k2 {
		t.Fatalf("CommitHandshake state = current %p next %p, want K1/K2", current, next)
	}

	confirm := craftClientTransportDatagram(t, k2, el.config.H4.PickOne(), el.config.S4, nil, 1, []byte("confirm-new-endpoint"))
	if !el.handleTransportData(confirm, newAddr) {
		t.Fatal("confirmation transport not handled")
	}
	newState, ok := el.peerByAddr(newAddr.String())
	if !ok || newState == nil {
		t.Fatal("authenticated K2 transport did not adopt new endpoint")
	}
	if got := newState.receiverIdx.Load(); got != k2.RemoteIndex {
		t.Fatalf("new endpoint receiver index = %d, want %d", got, k2.RemoteIndex)
	}
}
