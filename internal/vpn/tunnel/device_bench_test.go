package tunnel

// Issue #93: hermetic packet-path benchmarks for the per-packet copies in
// the device Read/Write paths — BASELINE ONLY, no optimization.
//
//   - UDPDevice: Read copies each inbound datagram (per-datagram make+copy
//     in the read loop), Write sends to a real loopback UDP socket (the
//     syscalls are measured as-is; the socket binds 127.0.0.1 only —
//     hermetic, no external network).
//   - AWGClientDevice: Write copies each packet into an in-memory VirtualTUN
//     channel; Read copies each packet out. Built against a fake endpoint —
//     no handshake, no real peer, fully in-memory.
//
// Run: go test -bench=. -benchmem -run=^$ ./internal/vpn/tunnel/

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// benchPacket builds a synthetic packet of the given size.
func benchPacket(size int) []byte {
	pkt := make([]byte, size)
	pkt[0] = 0x40
	return pkt
}

// BenchmarkUDPDeviceWrite measures the per-packet cost of pushing packets
// toward the backend loopback socket (conn.Write).
func BenchmarkUDPDeviceWrite(b *testing.B) {
	sizes := []int{64, 512, 1420}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("packet_%dB", size), func(b *testing.B) {
			backend := mustBenchUDPListener(b)
			dev, err := NewUDPDevice("bench-udp", backend.LocalAddr().String(), 1420)
			if err != nil {
				b.Fatalf("NewUDPDevice: %v", err)
			}
			defer func() { _ = dev.Close() }()

			// Drain the socket so writes never block on a full receive buffer.
			done := make(chan struct{})
			go func() {
				buf := make([]byte, 2048)
				for {
					select {
					case <-done:
						return
					default:
					}
					_ = backend.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
					if _, _, err := backend.ReadFrom(buf); err != nil {
						if ne, ok := err.(net.Error); ok && ne.Timeout() {
							continue
						}
						return
					}
				}
			}()
			b.Cleanup(func() { close(done) })

			pkt := benchPacket(size)
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := dev.Write(pkt); err != nil {
					b.Fatalf("UDPDevice.Write: %v", err)
				}
			}
			b.StopTimer()
		})
	}
}

// BenchmarkUDPDeviceRead measures the per-packet cost of the inbound path:
// the read loop's make+copy per datagram plus the channel hop and the copy
// into the caller's buffer.
func BenchmarkUDPDeviceRead(b *testing.B) {
	sizes := []int{64, 512, 1420}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("packet_%dB", size), func(b *testing.B) {
			backend := mustBenchUDPListener(b)
			dev, err := NewUDPDevice("bench-udp-read", backend.LocalAddr().String(), 1420)
			if err != nil {
				b.Fatalf("NewUDPDevice: %v", err)
			}
			defer func() { _ = dev.Close() }()

			pkt := benchPacket(size)
			buf := make([]byte, 2048)
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Hermetic: the device reads from its own loopback socket.
				if _, err := backend.WriteTo(pkt, dev.LocalAddr()); err != nil {
					b.Fatalf("WriteTo: %v", err)
				}
				if _, err := dev.Read(buf); err != nil {
					b.Fatalf("UDPDevice.Read: %v", err)
				}
			}
			b.StopTimer()
		})
	}
}

// BenchmarkAWGDeviceWrite measures AWGClientDevice.Write: per-packet
// make+copy into the VirtualTUN inPackets channel (the packet path the
// forwarder feeds).
func BenchmarkAWGDeviceWrite(b *testing.B) {
	sizes := []int{64, 512, 1420}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("packet_%dB", size), func(b *testing.B) {
			dev, err := NewAWGClientDevice("bench-awg", "127.0.0.1:51820", benchPrivKey, benchPubKey, 1340, nil)
			if err != nil {
				b.Fatalf("NewAWGClientDevice: %v", err)
			}
			b.Cleanup(func() { _ = dev.Close() })

			// Consume inPackets so Write never hits the non-blocking drop path.
			done := make(chan struct{})
			go func() {
				for {
					select {
					case <-done:
						return
					case <-dev.InPacketsForTest():
					}
				}
			}()
			b.Cleanup(func() { close(done) })

			pkt := benchPacket(size)
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := dev.Write(pkt); err != nil {
					b.Fatalf("AWGClientDevice.Write: %v", err)
				}
			}
			b.StopTimer()
		})
	}
}

// benchVirtualTUN builds a standalone in-memory tun.Device (the exact type
// backing AWGClientDevice) primed with one packet per iteration.
func benchVirtualTUN(_ int) *VirtualTUN {
	return &VirtualTUN{
		inPackets:  make(chan []byte, 1024),
		outPackets: make(chan []byte, 1024),
		events:     make(chan tun.Event, 2),
		closed:     make(chan struct{}),
		mtu:        1340,
		name:       "bench-vtun",
	}
}

// BenchmarkVirtualTUNRead measures the AWG device read path's per-packet
// copy (VirtualTUN.Read → tun.Device consumer): channel hop + copy into the
// caller's buffer. Driven directly on the in-memory VirtualTUN — hermetic,
// no amneziawg-go engine, no handshake.
func BenchmarkVirtualTUNRead(b *testing.B) {
	sizes := []int{64, 512, 1420}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("packet_%dB", size), func(b *testing.B) {
			vt := benchVirtualTUN(size)
			b.Cleanup(func() { _ = vt.Close() })

			pkt := benchPacket(size)
			bufs := [][]byte{make([]byte, 2048)}
			sizesArr := []int{0}
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				select {
				case vt.inPackets <- pkt:
				default:
					b.Fatal("inPackets unexpectedly full")
				}
				if _, err := vt.Read(bufs, sizesArr, 0); err != nil {
					b.Fatalf("VirtualTUN.Read: %v", err)
				}
			}
			b.StopTimer()
		})
	}
}

// BenchmarkVirtualTUNWrite measures the AWG device write path's per-packet
// copy (VirtualTUN.Write): make+copy out of the caller's buffer into the
// outPackets channel.
func BenchmarkVirtualTUNWrite(b *testing.B) {
	sizes := []int{64, 512, 1420}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("packet_%dB", size), func(b *testing.B) {
			vt := benchVirtualTUN(size)
			b.Cleanup(func() { _ = vt.Close() })

			// Consume outPackets so the non-blocking send never drops.
			done := make(chan struct{})
			go func() {
				for {
					select {
					case <-done:
						return
					case <-vt.outPackets:
					}
				}
			}()
			b.Cleanup(func() { close(done) })

			buf := make([]byte, size+16) // offset 16 like a real tun consumer
			buf[16] = 0x40
			bufs := [][]byte{buf}
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := vt.Write(bufs, 16); err != nil {
					b.Fatalf("VirtualTUN.Write: %v", err)
				}
			}
			b.StopTimer()
		})
	}
}

// mustBenchUDPListener binds a loopback UDP socket acting as the backend.
func mustBenchUDPListener(b *testing.B) *net.UDPConn {
	b.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		b.Fatalf("ListenUDP: %v", err)
	}
	b.Cleanup(func() { _ = c.Close() })
	return c
}

const (
	benchPrivKey = "6AmMpNnPy7PpeT9e6tYdVCnJ+MKhMEl7EK6ccpcxk1w="
	benchPubKey  = "k5P1iBe1WgGZ4FqYjMGyO5tRFnlDgU9tMT0F4PXcZnc="
)
