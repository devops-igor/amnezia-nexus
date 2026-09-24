package forwarder

import "testing"

// Superseded sessions have already lost their routes during registration;
// they do not necessarily produce a matching unregister call. The current
// session's teardown must still retire the route after any number of rekeys.
func TestCurrentSessionTeardownAfterRepeatedRekeys(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 64)
	defer f.StopPumps()

	const peer = "peer-a"
	const ip = "10.100.0.3"
	dev := newGatedDevice()
	defer dev.Close()
	f.AttachPeerDevice(peer, dev)
	f.StartPumps(t.Context())

	for _, id := range []string{"s1", "s2", "s3", "s4"} {
		f.RegisterSession(id, "conn", peer, ip, 1)
	}
	if got := f.RouteSessionID(peer); got != "s4" {
		t.Fatalf("active route = %q, want s4", got)
	}

	// An old teardown can arrive after the latest registration.
	f.BeginUnregisterSession(peer, "s1").Wait()
	f.BeginUnregisterSession(peer, "s2").Wait()
	if got := f.RouteSessionID(peer); got != "s4" {
		t.Fatalf("old teardown removed current session: %q", got)
	}

	f.BeginUnregisterSession(peer, "s4").Wait()
	f.mu.RLock()
	_, byPeer := f.routesByPeer[peer]
	_, byIP := f.routesByIP[ip]
	_, device := f.clientDevices[peer]
	f.mu.RUnlock()
	if byPeer || byIP || device {
		t.Fatalf("current teardown left state: byPeer=%v byIP=%v device=%v", byPeer, byIP, device)
	}
	if err := f.RouteBackendToClient(1, ipv4Packet([4]byte{10, 100, 0, 3}), ip); err != ErrSessionNotRegistered {
		t.Fatalf("return traffic after teardown = %v, want ErrSessionNotRegistered", err)
	}
	if got := dev.count(); got != 0 {
		t.Fatalf("client device received %d writes after teardown", got)
	}

	// A duplicate teardown cannot consume credit from a future session.
	f.BeginUnregisterSession(peer, "s4").Wait()
	f.RegisterSession("s5", "conn", peer, ip, 1)
	f.BeginUnregisterSession(peer, "s3").Wait()
	if got := f.RouteSessionID(peer); got != "s5" {
		t.Fatalf("old teardown removed a future route: %q", got)
	}
}

func TestSessionTeardownRejectsMissingIdentity(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 64)
	f.RegisterSession("s1", "conn", "peer", "10.100.0.3", 1)
	f.BeginUnregisterSession("peer", "").Wait()
	if got := f.RouteSessionID("peer"); got != "s1" {
		t.Fatalf("teardown without session ID removed route: %q", got)
	}
}
