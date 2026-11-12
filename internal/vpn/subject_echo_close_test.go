package vpn

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"runtime"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// subjectEchoDump returns every goroutine stack with frames and arguments. A growing
// buffer is never silently cut short, so an absent frame here is real absence.
func subjectEchoDump() string {
	var b bytes.Buffer
	_ = pprof.Lookup("goroutine").WriteTo(&b, 2)
	return b.String()
}

// waitSubjectEchoFrame polls the dump until one goroutine block matches, inside a
// single bounded observation deadline. It reports false when the deadline expires.
func waitSubjectEchoFrame(timeout time.Duration, match func(block string) bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		for _, block := range strings.Split(subjectEchoDump(), "\n\n") {
			if match(block) {
				return true
			}
		}
		if !time.Now().Before(deadline) {
			return false
		}
		runtime.Gosched()
	}
}

func subjectEchoIPv4Checksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// subjectEchoUDPDatagram builds the cold IPv4/UDP datagram injected into the backend
// netstack, including the IPv4 header checksum the stack verifies on receive.
func subjectEchoUDPDatagram(src, dst netip.AddrPort, payload []byte) []byte {
	p := make([]byte, 20+8+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[8] = 64
	p[9] = 17
	s4, d4 := src.Addr().As4(), dst.Addr().As4()
	copy(p[12:], s4[:])
	copy(p[16:], d4[:])
	binary.BigEndian.PutUint16(p[10:], subjectEchoIPv4Checksum(p[:20]))
	binary.BigEndian.PutUint16(p[20:], src.Port())
	binary.BigEndian.PutUint16(p[22:], dst.Port())
	binary.BigEndian.PutUint16(p[24:], uint16(8+len(payload)))
	copy(p[28:], payload)
	return p
}

// TestSubjectServerCloseJoinsEchoProducersBeforeDeviceClose pins the SubjectServer
// UDP echo producer inside netstack WriteNotify (blocked sending its reply on the
// unbuffered packet channel) and then closes the server while the backend return
// reader is still draining. Closing the device first is the CI failure: the echo
// producer's send races the channel close and the runtime panics on a send to a
// closed channel. Close must stop and join every echo worker before it closes the
// device, and the legitimate reply must still reach the reader.
func TestSubjectServerCloseJoinsEchoProducersBeforeDeviceClose(t *testing.T) {
	dest := netip.MustParseAddr("198.51.100.7")
	vt, stack, err := netstack.CreateNetTUN([]netip.Addr{dest}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	tcpL, err := stack.ListenTCPAddrPort(netip.AddrPortFrom(dest, 40001))
	if err != nil {
		t.Fatal(err)
	}
	udpC, err := stack.ListenUDPAddrPort(netip.AddrPortFrom(dest, 40001))
	if err != nil {
		t.Fatal(err)
	}

	adapter := &returnStackDevice{tun: vt}
	gate := make(chan struct{})
	backendDone := make(chan struct{})
	replies := make(chan []byte, 1)
	go func() { // stands in for pumpBackendReturns; it starts draining once the gate opens
		defer close(backendDone)
		<-gate
		buf := make([]byte, 2048)
		for {
			n, err := adapter.Read(buf)
			if err != nil {
				return
			}
			if n >= 20 && buf[9] == 17 { // UDP
				select {
				case replies <- append([]byte(nil), buf[:n]...):
				default:
				}
			}
		}
	}()

	sub := &SubjectServer{
		svc:         &Service{forwarder: forwarder.NewForwarder(nil, "")},
		adapter:     adapter,
		backendDone: backendDone,
		tcpListener: tcpL,
		udpConn:     udpC,
	}
	sub.startEchoWorkers()

	// Cold packet on a fresh stack. Like ExchangeUDP, a first datagram can be lost
	// before the endpoint is dispatchable, so the injection is bounded to five
	// attempts; the observation, not the retry, is what the assertions rest on.
	payload := []byte("subject-echo-close-payload")
	pinned := false
	for attempt := 0; attempt < 5 && !pinned; attempt++ {
		pkt := subjectEchoUDPDatagram(netip.MustParseAddrPort("10.100.0.2:5555"), netip.AddrPortFrom(dest, 40001), payload)
		if _, err := vt.Write([][]byte{pkt}, 0); err != nil {
			t.Fatalf("inject cold datagram: %v", err)
		}
		pinned = waitSubjectEchoFrame(2*time.Second, func(block string) bool {
			return strings.Contains(block, "startEchoWorkers.func2") &&
				strings.Contains(block, "netTun).WriteNotify") &&
				strings.Contains(block, "chan send")
		})
	}
	if !pinned {
		t.Fatal("echo producer never reached the netstack WriteNotify send, so the close ordering was not exercised")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- sub.Close() }()

	joining := waitSubjectEchoFrame(2*time.Second, func(block string) bool {
		return strings.Contains(block, "SubjectServer).Close") && strings.Contains(block, "WaitGroup).Wait")
	})
	// Open the reader either way: the production reader keeps draining, and a
	// close that never reaches the join must fail rather than hang the package.
	close(gate)
	if !joining {
		t.Fatal("Close never reached the echo producer join while that producer was still inside WriteNotify")
	}

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not complete after the echo producers were joined")
	}

	if err := sub.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	select {
	case reply := <-replies:
		if !bytes.HasSuffix(reply, payload) || reply[9] != 17 {
			t.Fatalf("echo reply payload mismatch: %x", reply)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("legitimate echo reply was not delivered to the backend return reader")
	}
}
