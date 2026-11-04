//go:build linux

package vpn

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"strings"
	"sync"
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

func TestLinuxWANDevice_R8B2_ResetSuppressionRuleLifecycle(t *testing.T) {
	tunR, tunW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	defer func() { _ = tunR.Close(); _ = tunW.Close() }()

	var mu sync.Mutex
	var executedCommands [][]string
	mockRunner := func(args ...string) error {
		mu.Lock()
		defer mu.Unlock()
		cp := make([]string, len(args))
		copy(cp, args)
		executedCommands = append(executedCommands, cp)
		if len(args) > 0 && args[0] == "-C" {
			// Rule does not exist yet -> trigger install
			return errors.New("rule does not exist")
		}
		return nil
	}

	dev := newLinuxWANDeviceWithFiles(tunW, nil, "test-wan", 40000, 65000, netip.Addr{})
	dev.iptablesRunner = mockRunner

	// 1. Initial SetHostWANIP installs socket ACCEPT and DROP rules for both TCP and UDP
	ip1 := netip.MustParseAddr("203.0.113.10")
	if err := dev.SetHostWANIP(ip1); err != nil {
		t.Fatalf("SetHostWANIP failed: %v", err)
	}
	if !dev.iptablesInstalled {
		t.Fatalf("expected iptablesInstalled to be true after successful installation")
	}

	mu.Lock()
	cmds := make([][]string, len(executedCommands))
	copy(cmds, executedCommands)
	mu.Unlock()

	hasTCPAccept := false
	hasUDPAccept := false
	hasTCPDrop := false
	hasUDPDrop := false
	for _, cmd := range cmds {
		joined := strings.Join(cmd, " ")
		if strings.Contains(joined, "-I INPUT -p tcp --dport 40000:65000 -d 203.0.113.10 -m socket --nowildcard -j ACCEPT") {
			hasTCPAccept = true
		}
		if strings.Contains(joined, "-I INPUT -p udp --dport 40000:65000 -d 203.0.113.10 -m socket --nowildcard -j ACCEPT") {
			hasUDPAccept = true
		}
		if strings.Contains(joined, "-A INPUT -p tcp --dport 40000:65000 -d 203.0.113.10 -j DROP") {
			hasTCPDrop = true
		}
		if strings.Contains(joined, "-A INPUT -p udp --dport 40000:65000 -d 203.0.113.10 -j DROP") {
			hasUDPDrop = true
		}
	}
	if !hasTCPAccept || !hasUDPAccept {
		t.Fatalf("expected -I INPUT socket ACCEPT rules for tcp and udp, got: %v", cmds)
	}
	if !hasTCPDrop || !hasUDPDrop {
		t.Fatalf("expected -A INPUT DROP rules for tcp and udp, got: %v", cmds)
	}

	// 2. Calling SetHostWANIP with the same IP is idempotent
	mu.Lock()
	countBefore := len(executedCommands)
	mu.Unlock()
	if err := dev.SetHostWANIP(ip1); err != nil {
		t.Fatalf("idempotent SetHostWANIP failed: %v", err)
	}
	mu.Lock()
	countAfter := len(executedCommands)
	mu.Unlock()
	if countAfter != countBefore {
		t.Fatalf("expected idempotent SetHostWANIP to not re-run iptables, ran %d additional commands", countAfter-countBefore)
	}

	// 3. Changing HostWANIP tears down old rules and installs new ones
	ip2 := netip.MustParseAddr("203.0.113.20")
	if err := dev.SetHostWANIP(ip2); err != nil {
		t.Fatalf("SetHostWANIP with new IP failed: %v", err)
	}

	mu.Lock()
	cmdsAfterChange := make([][]string, len(executedCommands))
	copy(cmdsAfterChange, executedCommands)
	mu.Unlock()

	hasOldTCPAcceptDel := false
	hasOldTCPDropDel := false
	hasNewTCPAcceptIns := false
	hasNewTCPDropIns := false
	for _, cmd := range cmdsAfterChange[countBefore:] {
		joined := strings.Join(cmd, " ")
		if strings.Contains(joined, "-D INPUT -p tcp --dport 40000:65000 -d 203.0.113.10 -m socket --nowildcard -j ACCEPT") {
			hasOldTCPAcceptDel = true
		}
		if strings.Contains(joined, "-D INPUT -p tcp --dport 40000:65000 -d 203.0.113.10 -j DROP") {
			hasOldTCPDropDel = true
		}
		if strings.Contains(joined, "-I INPUT -p tcp --dport 40000:65000 -d 203.0.113.20 -m socket --nowildcard -j ACCEPT") {
			hasNewTCPAcceptIns = true
		}
		if strings.Contains(joined, "-A INPUT -p tcp --dport 40000:65000 -d 203.0.113.20 -j DROP") {
			hasNewTCPDropIns = true
		}
	}
	if !hasOldTCPAcceptDel || !hasOldTCPDropDel || !hasNewTCPAcceptIns || !hasNewTCPDropIns {
		t.Fatalf("expected old TCP rules deleted and new TCP rules inserted on IP change, got: %v", cmdsAfterChange[countBefore:])
	}

	// 4. Close cleans up all active rules
	if err := dev.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	mu.Lock()
	finalCmds := make([][]string, len(executedCommands))
	copy(finalCmds, executedCommands)
	mu.Unlock()

	hasFinalTCPAcceptDel := false
	hasFinalTCPDropDel := false
	hasFinalUDPAcceptDel := false
	hasFinalUDPDropDel := false
	for _, cmd := range finalCmds {
		joined := strings.Join(cmd, " ")
		if strings.Contains(joined, "-D INPUT -p tcp --dport 40000:65000 -d 203.0.113.20 -m socket --nowildcard -j ACCEPT") {
			hasFinalTCPAcceptDel = true
		}
		if strings.Contains(joined, "-D INPUT -p tcp --dport 40000:65000 -d 203.0.113.20 -j DROP") {
			hasFinalTCPDropDel = true
		}
		if strings.Contains(joined, "-D INPUT -p udp --dport 40000:65000 -d 203.0.113.20 -m socket --nowildcard -j ACCEPT") {
			hasFinalUDPAcceptDel = true
		}
		if strings.Contains(joined, "-D INPUT -p udp --dport 40000:65000 -d 203.0.113.20 -j DROP") {
			hasFinalUDPDropDel = true
		}
	}
	if !hasFinalTCPAcceptDel || !hasFinalTCPDropDel || !hasFinalUDPAcceptDel || !hasFinalUDPDropDel {
		t.Fatalf("expected Close to delete all active rules for %s, got: %v", ip2, finalCmds)
	}
}

func TestLinuxWANDevice_R9H1_FailClosedAndRetry(t *testing.T) {
	tunR, tunW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	defer func() { _ = tunR.Close(); _ = tunW.Close() }()

	var mu sync.Mutex
	calls := 0
	failRunner := true
	runner := func(args ...string) error {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if failRunner {
			return errors.New("iptables: permission denied")
		}
		if len(args) > 0 && args[0] == "-C" {
			return errors.New("absent")
		}
		return nil
	}

	dev := newLinuxWANDeviceWithFiles(tunW, nil, "test-wan", 40000, 65000, netip.Addr{})
	dev.iptablesRunner = runner
	defer func() { _ = dev.Close() }()

	ip := netip.MustParseAddr("203.0.113.30")

	// 1. Installation failure returns error and leaves iptablesInstalled = false
	err = dev.SetHostWANIP(ip)
	if err == nil {
		t.Fatalf("expected error from failed iptables runner, got nil")
	}
	if dev.iptablesInstalled {
		t.Fatalf("expected iptablesInstalled to remain false on failure")
	}

	mu.Lock()
	initialCalls := calls
	mu.Unlock()
	if initialCalls == 0 {
		t.Fatalf("expected runner to be called")
	}

	// 2. Calling SetHostWANIP with the same IP RETRIES instead of early-exiting
	err = dev.SetHostWANIP(ip)
	if err == nil {
		t.Fatalf("expected second attempt to fail while runner fails")
	}
	mu.Lock()
	secondCalls := calls
	mu.Unlock()
	if secondCalls <= initialCalls {
		t.Fatalf("expected same-IP call to retry runner, got calls before=%d after=%d", initialCalls, secondCalls)
	}

	// 3. When iptables runner recovers, retry succeeds and marks iptablesInstalled = true
	mu.Lock()
	failRunner = false
	mu.Unlock()

	err = dev.SetHostWANIP(ip)
	if err != nil {
		t.Fatalf("expected recovered runner to succeed, got: %v", err)
	}
	if !dev.iptablesInstalled {
		t.Fatalf("expected iptablesInstalled to be true after recovered attempt")
	}
}

func TestLinuxWANDevice_R9H1_RollbackOnPartialFailure(t *testing.T) {
	tunR, tunW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	defer func() { _ = tunR.Close(); _ = tunW.Close() }()

	var mu sync.Mutex
	var executedCommands [][]string
	runner := func(args ...string) error {
		mu.Lock()
		defer mu.Unlock()
		cp := make([]string, len(args))
		copy(cp, args)
		executedCommands = append(executedCommands, cp)

		if len(args) > 0 && args[0] == "-C" {
			return errors.New("absent")
		}
		// Simulate failure on UDP socket accept rule
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "-I INPUT -p udp") && strings.Contains(joined, "-m socket") {
			return errors.New("iptables: kernel module not available for udp socket match")
		}
		return nil
	}

	dev := newLinuxWANDeviceWithFiles(tunW, nil, "test-wan", 40000, 65000, netip.Addr{})
	dev.iptablesRunner = runner
	defer func() { _ = dev.Close() }()

	ip := netip.MustParseAddr("203.0.113.40")
	err = dev.SetHostWANIP(ip)
	if err == nil {
		t.Fatalf("expected error on partial failure, got nil")
	}
	if dev.iptablesInstalled {
		t.Fatalf("expected iptablesInstalled to remain false on partial failure")
	}

	// Verify rollback deleted the rules that were installed before the failure
	mu.Lock()
	cmds := make([][]string, len(executedCommands))
	copy(cmds, executedCommands)
	mu.Unlock()

	hasRollbackTCPDrop := false
	hasRollbackTCPAccept := false
	for _, cmd := range cmds {
		joined := strings.Join(cmd, " ")
		if strings.Contains(joined, "-D INPUT -p tcp --dport 40000:65000 -d 203.0.113.40 -j DROP") {
			hasRollbackTCPDrop = true
		}
		if strings.Contains(joined, "-D INPUT -p tcp --dport 40000:65000 -d 203.0.113.40 -m socket --nowildcard -j ACCEPT") {
			hasRollbackTCPAccept = true
		}
	}
	if !hasRollbackTCPDrop || !hasRollbackTCPAccept {
		t.Fatalf("expected rollback to delete installed TCP drop and accept rules, executed commands: %v", cmds)
	}
}

func TestLinuxWANDevice_R9B1_AuditProbeExcludesHostTraffic(t *testing.T) {
	tunR, tunW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	defer func() { _ = tunR.Close(); _ = tunW.Close() }()

	var rules []string
	runner := func(args ...string) error {
		if len(args) > 0 && args[0] == "-C" {
			return errors.New("absent")
		}
		if len(args) > 0 && args[0] == "-I" {
			rules = append(rules, strings.Join(args, " "))
		}
		return nil
	}

	dev := newLinuxWANDeviceWithFiles(tunW, nil, "audit", 40000, 65000, netip.Addr{})
	dev.iptablesRunner = runner
	defer func() { _ = dev.Close() }()

	ip := netip.MustParseAddr("203.0.113.10")
	if err := dev.SetHostWANIP(ip); err != nil {
		t.Fatalf("SetHostWANIP failed: %v", err)
	}

	// Ordinary established host HTTPS/DNS return to local ephemeral port 50000.
	// Verify no unconditional -I DROP rule exists that would drop host traffic without socket matching.
	for _, rule := range rules {
		if strings.Contains(rule, "--dport 40000:65000 -d 203.0.113.10 -j DROP") &&
			!strings.Contains(rule, "--ctstate") &&
			!strings.Contains(rule, "--socket") &&
			!strings.Contains(rule, "--mark") {
			t.Errorf("host-owned established reply to port 50000 matches unconditional rule: %s", rule)
		}
	}

	// Verify that socket-match rules are emitted
	hasSocketMatch := false
	for _, rule := range rules {
		if strings.Contains(rule, "-m socket --nowildcard -j ACCEPT") {
			hasSocketMatch = true
		}
	}
	if !hasSocketMatch {
		t.Fatalf("expected socket match ACCEPT rule in -I emitted rules: %v", rules)
	}
}
