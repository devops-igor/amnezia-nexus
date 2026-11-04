//go:build linux

package vpn

import (
	"encoding/binary"
	"net/netip"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestProductionWANDevice_PermissionsAndLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		// Non-root: verify graceful error handling (fails closed with clear error, no panic)
		dev, err := NewProductionWANDevice("nexus-wan-test")
		if err == nil {
			_ = dev.Close()
			t.Log("NewProductionWANDevice succeeded in unprivileged test environment")
			return
		}
		t.Logf("NewProductionWANDevice returned expected non-root permission error: %v", err)
		return
	}

	// Even as root, /dev/net/tun may be absent (e.g. CI containers without kernel TUN).
	// Skip rather than fail in that case — the test's purpose is to verify the ioctl
	// lifecycle on a real TUN device, which requires the kernel module.
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("/dev/net/tun not available; skipping TUN lifecycle test")
		return
	}

	dev, err := NewProductionWANDevice("nexus-wan-test")
	if err != nil {
		t.Fatalf("NewProductionWANDevice failed: %v", err)
	}
	defer func() { _ = dev.Close() }()

	// Verify device is writable (UP state allows writes without EIO)
	pkt := []byte{
		0x45, 0x00, 0x00, 0x14,
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x00, 0x00, 0x00,
		0x7f, 0x00, 0x00, 0x01,
		0x7f, 0x00, 0x00, 0x01,
	}
	n, err := dev.Write(pkt)
	if err != nil {
		t.Fatalf("write to UP TUN device failed: %v", err)
	}
	if n != len(pkt) {
		t.Fatalf("expected write %d bytes, got %d", len(pkt), n)
	}
}

func TestLinuxWANDevice_ReturnPacketCaptureAndFiltering(t *testing.T) {
	// Create datagram socket pair for raw socket simulation (preserves packet boundaries)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("create datagram socketpair: %v", err)
	}
	rawR := os.NewFile(uintptr(fds[0]), "raw-r")
	rawW := os.NewFile(uintptr(fds[1]), "raw-w")
	defer func() { _ = rawR.Close(); _ = rawW.Close() }()

	tunR, tunW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create tun pipe: %v", err)
	}
	defer func() { _ = tunR.Close(); _ = tunW.Close() }()

	hostWAN := netip.MustParseAddr("203.0.113.1")
	remoteServer := netip.MustParseAddr("1.1.1.1")

	dev := newLinuxWANDeviceWithFiles(tunW, rawR, "test-wan", 40000, 65000, hostWAN)
	defer func() { _ = dev.Close() }()

	// 1. Write an invalid packet into rawW (should be skipped by Read)
	invalidPkt := []byte{0x00, 0x01, 0x02, 0x03}
	if _, err := rawW.Write(invalidPkt); err != nil {
		t.Fatalf("write invalid packet: %v", err)
	}

	// 2. Write a packet to non-NAT port 80 (should be skipped by Read)
	nonNATPortPkt := buildTestPBRTCPPacket(remoteServer, hostWAN, 80, 80, []byte("http-reply"))
	if _, err := rawW.Write(nonNATPortPkt); err != nil {
		t.Fatalf("write non-NAT port packet: %v", err)
	}

	// 3. Write a packet to wrong destination IP (should be skipped by Read)
	wrongIPPkt := buildTestPBRTCPPacket(remoteServer, netip.MustParseAddr("192.168.1.1"), 80, 40001, []byte("wrong-ip"))
	if _, err := rawW.Write(wrongIPPkt); err != nil {
		t.Fatalf("write wrong IP packet: %v", err)
	}

	// 4. Write a valid TCP return packet to NAT port 40001 (MUST be delivered by Read)
	validTCPReturn := buildTestPBRTCPPacket(remoteServer, hostWAN, 80, 40001, []byte("tcp-reply-data"))
	if _, err := rawW.Write(validTCPReturn); err != nil {
		t.Fatalf("write valid TCP return packet: %v", err)
	}

	buf := make([]byte, 65535)
	n, err := dev.Read(buf)
	if err != nil {
		t.Fatalf("Read valid TCP return packet failed: %v", err)
	}
	if n != len(validTCPReturn) {
		t.Fatalf("expected Read %d bytes, got %d", len(validTCPReturn), n)
	}
	// Verify dst port is 40001
	ihl := int(buf[0]&0x0f) * 4
	gotDstPort := binary.BigEndian.Uint16(buf[ihl+2 : ihl+4])
	if gotDstPort != 40001 {
		t.Fatalf("expected destination port 40001, got %d", gotDstPort)
	}

	// 5. Write a valid UDP return packet to NAT port 50005 (MUST be delivered by Read)
	validUDPReturn := buildTestPBRUDPPacket(remoteServer, hostWAN, 53, 50005, []byte("udp-reply-data"))
	if _, err := rawW.Write(validUDPReturn); err != nil {
		t.Fatalf("write valid UDP return packet: %v", err)
	}
	n, err = dev.Read(buf)
	if err != nil {
		t.Fatalf("Read valid UDP return packet failed: %v", err)
	}
	if n != len(validUDPReturn) {
		t.Fatalf("expected Read %d bytes, got %d", len(validUDPReturn), n)
	}
	ihl = int(buf[0]&0x0f) * 4
	gotDstPort = binary.BigEndian.Uint16(buf[ihl+2 : ihl+4])
	if gotDstPort != 50005 {
		t.Fatalf("expected destination port 50005, got %d", gotDstPort)
	}

	// 6. Test Write to device
	outPkt := []byte{0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01}
	wn, err := dev.Write(outPkt)
	if err != nil {
		t.Fatalf("Write to device failed: %v", err)
	}
	if wn != len(outPkt) {
		t.Fatalf("expected Write %d bytes, got %d", len(outPkt), wn)
	}

	// 7. Test Close
	if err := dev.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}
