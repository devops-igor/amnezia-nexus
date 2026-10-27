package streambridge

import (
	"context"
	"encoding/binary"
	"math/rand"
	"net"
	"testing"
	"time"
)

// buildTCPPacket creates an IPv4 TCP SYN packet addressed to the given destination.
func buildTCPPacket(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8], pkt[9] = 64, 6
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(pkt[10:12], tcpChecksum(pkt[:20]))

	tcpHeader := pkt[20:]
	binary.BigEndian.PutUint16(tcpHeader[:2], srcPort)
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)
	binary.BigEndian.PutUint32(tcpHeader[4:8], 12345)
	tcpHeader[12], tcpHeader[13] = 0x50, 0x02 // SYN
	binary.BigEndian.PutUint16(tcpHeader[14:16], 65535)

	pseudo := append([]byte{}, pkt[12:20]...)
	pseudo = append(pseudo, 0, 6, 0, 20)
	pseudo = append(pseudo, tcpHeader...)
	binary.BigEndian.PutUint16(tcpHeader[16:18], tcpChecksum(pseudo))
	return pkt
}

// TestFlows_CloseDuringInFlightTCPHandshakeRegistration explicitly pauses execution
// at the endpoint-registration boundary (between the closed check and r.CreateEndpoint(&wq)),
// triggers Device.Close(), and verifies that Close() completes promptly without stalling
// when the client handshake ACK never arrives.
func TestFlows_CloseDuringInFlightTCPHandshakeRegistration(t *testing.T) {
	out, peer := net.Pipe()
	defer peer.Close()
	dev, err := New(Config{}, funcDialer(func(context.Context, string, string) (net.Conn, error) {
		return out, nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	hookEntered := make(chan struct{})
	hookRelease := make(chan struct{})

	dev.setBeforeCreateEndpointHookForTest(func() {
		close(hookEntered)
		<-hookRelease
	})

	pkt := buildTCPPacket(net.ParseIP("192.0.2.10"), 25000, net.ParseIP("198.51.100.1"), 8080)
	if _, err := dev.Write(pkt); err != nil {
		t.Fatal(err)
	}

	// Wait until onTCP has passed the closed check and paused at the registration boundary.
	select {
	case <-hookEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for hook entry at registration boundary")
	}

	// Trigger Device.Close() while onTCP is paused at the boundary.
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- dev.Close()
	}()

	// Allow Close() to execute d.cancel() and its initial RegisteredEndpoints snapshot.
	time.Sleep(30 * time.Millisecond)

	// Release onTCP to call r.CreateEndpoint(&wq); deliberately never send client ACK.
	close(hookRelease)

	// Close() must complete promptly without stalling.
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Close did not return promptly within 500ms when TCP handshake registered after shutdown began")
	}
}

// TestFlows_CloseDuringUnacknowledgedTCPHandshake_UncoordinatedRace runs multiple
// uncoordinated trials where Device.Close() races against an in-flight SYN packet
// whose client ACK is deliberately never sent.
func TestFlows_CloseDuringUnacknowledgedTCPHandshake_UncoordinatedRace(t *testing.T) {
	const iterations = 50
	rng := rand.New(rand.NewSource(633))

	for i := 0; i < iterations; i++ {
		out, peer := net.Pipe()
		dev, err := New(Config{}, funcDialer(func(context.Context, string, string) (net.Conn, error) {
			return out, nil
		}))
		if err != nil {
			peer.Close()
			t.Fatal(err)
		}

		pkt := buildTCPPacket(net.ParseIP("192.0.2.10"), uint16(20000+i), net.ParseIP("198.51.100.1"), 8080)
		if _, err := dev.Write(pkt); err != nil {
			dev.Close()
			peer.Close()
			t.Fatal(err)
		}

		if d := time.Duration(rng.Intn(300)) * time.Microsecond; d > 0 {
			time.Sleep(d)
		}

		done := make(chan error, 1)
		go func() {
			done <- dev.Close()
		}()

		select {
		case err := <-done:
			if err != nil {
				peer.Close()
				t.Fatalf("iteration %d: Close failed: %v", i, err)
			}
		case <-time.After(500 * time.Millisecond):
			peer.Close()
			t.Fatalf("iteration %d: Close stalled beyond 500ms during uncoordinated handshake race", i)
		}

		peer.Close()
	}
}
