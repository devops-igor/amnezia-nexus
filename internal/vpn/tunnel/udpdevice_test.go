package tunnel

import (
	"net"
	"testing"
	"time"
)



// backendSocket binds a local UDP socket standing in for a remote backend AWG
// endpoint. Embedding *net.UDPConn gives the test direct Read/Write access
// while Addr() exposes the bound address for NewUDPDevice's endpoint argument.
type backendSocket struct {
	*net.UDPConn
}

// Addr returns the socket's bound local address.
func (b backendSocket) Addr() net.Addr { return b.UDPConn.LocalAddr() }

// addrWithSocket creates the bound backend socket; closed via t.Cleanup.
func addrWithSocket(t *testing.T) backendSocket {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return backendSocket{UDPConn: c}
}

// TestUDPDeviceWriteToBackend proves the egress path: a UDP socket bound as
// the "backend" receives exactly what is written to the device.
func TestUDPDeviceWriteToBackend(t *testing.T) {
	backend := addrWithSocket(t)
	dev, err := NewUDPDevice("awg-be-test", backend.Addr().String(), 1420)
	if err != nil {
		t.Fatalf("NewUDPDevice failed: %v", err)
	}

	pkt := []byte("client-packet-to-backend")
	if n, err := dev.Write(pkt); err != nil || n != len(pkt) {
		t.Fatalf("Write mismatch: n=%d err=%v", n, err)
	}

	buf := make([]byte, 1500)
	if err := backend.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}
	n, err := backend.Read(buf)
	if err != nil {
		t.Fatalf("backend did not receive packet: %v", err)
	}
	if string(buf[:n]) != string(pkt) {
		t.Errorf("packet mismatch: got %q want %q", buf[:n], pkt)
	}

	if dev.Name() != "awg-be-test" || dev.MTU() != 1420 {
		t.Errorf("device property mismatch: name=%s mtu=%d", dev.Name(), dev.MTU())
	}

	if err := dev.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if _, err := dev.Write(pkt); err == nil {
		t.Error("expected error writing to closed device")
	}
}

// TestUDPDeviceReadFromBackend proves the ingress path: a datagram sent by
// the backend is delivered through Read.
func TestUDPDeviceReadFromBackend(t *testing.T) {
	backend := addrWithSocket(t)
	dev, err := NewUDPDevice("awg-be-test2", backend.Addr().String(), 1420)
	if err != nil {
		t.Fatalf("NewUDPDevice failed: %v", err)
	}
	defer func() { _ = dev.Close() }()

	// Reply from the backend to the device's source address (LocalAddr is
	// always a *net.UDPAddr for this UDP-connected socket).
	_, err = backend.WriteToUDP([]byte("backend-reply"), dev.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("backend WriteToUDP failed: %v", err)
	}

	buf := make([]byte, 1500)
	n, err := dev.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(buf[:n]) != "backend-reply" {
		t.Errorf("Read mismatch: got %q", buf[:n])
	}
}

// TestUDPDeviceInvalidEndpoint proves the constructor error surface.
func TestUDPDeviceInvalidEndpoint(t *testing.T) {
	if _, err := NewUDPDevice("x", "not-an-endpoint::", 1420); err == nil {
		t.Error("expected error for invalid endpoint")
	}
}
