package vpn

import (
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	mdns "github.com/miekg/dns"
)

// dnsCachePairRetirementBarrier holds the route cache's own mutex as a scheduling
// barrier: it reads and writes no cache state, it only keeps a concurrent scope
// retirement between publishing its retired flag and invalidating the scope long
// enough for the test to admit a worker that prefetched that scope. That
// interleaving is the subject under test, not an artifact of the fixture.
//
// The field is reached by name with a type check, so a cache that renames or
// retypes its mutex fails loudly instead of silently scheduling nothing.
func dnsCachePairRetirementBarrier(t *testing.T, cache *policy.RouteCache) (release func()) {
	t.Helper()
	field := reflect.ValueOf(cache).Elem().FieldByName("mu")
	if !field.IsValid() || field.Type() != reflect.TypeOf(sync.Mutex{}) {
		t.Fatalf("fixture: route cache mutex changed; cannot schedule the retirement overlap")
	}
	// The address is taken from the field reflect resolved above, so the
	// conversion points at the cache's real mutex; only lock/unlock are used.
	mu := (*sync.Mutex)(unsafe.Pointer(field.UnsafeAddr())) // #nosec G103 -- scheduling barrier on the cache's own mutex, no cache state is read or written
	mu.Lock()
	var once sync.Once
	return func() { once.Do(mu.Unlock) }
}

// dnsCachePairChecksum is the standard internet checksum over b.
func dnsCachePairChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 != 0 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// dnsCachePairSYN builds a valid IPv4/TCP SYN from the session's own client
// address to the gateway's DNS port, checksums included, so the gateway's real
// netstack transport accepts it as a connection attempt and answers it. The
// answer is the reply whose write the test fails.
func dnsCachePairSYN(t *testing.T, src, dst netip.Addr, srcPort uint16) []byte {
	t.Helper()
	pkt := buildTestPBRTCPPacket(src, dst, srcPort, 53, nil)
	binary.BigEndian.PutUint16(pkt[10:12], 0)
	binary.BigEndian.PutUint16(pkt[10:12], dnsCachePairChecksum(pkt[:20]))
	pseudo := make([]byte, 0, 12+len(pkt)-20)
	srcBytes := src.As4()
	dstBytes := dst.As4()
	pseudo = append(pseudo, srcBytes[:]...)
	pseudo = append(pseudo, dstBytes[:]...)
	pseudo = append(pseudo, 0, 6) // protocol TCP
	pseudo = append(pseudo, byte((len(pkt)-20)>>8), byte(len(pkt)-20))
	pseudo = append(pseudo, pkt[20:]...)
	binary.BigEndian.PutUint16(pkt[36:38], 0)
	binary.BigEndian.PutUint16(pkt[36:38], dnsCachePairChecksum(pseudo))
	return pkt
}

// dnsCachePairTCPAnswer proves TCP DNS is usable through a fresh connection. It
// retries for a bounded time because a connection attempt can be swallowed by the
// retired runtime's transport while that transport is being torn down; once the
// session owns live authority the exchange completes.
func dnsCachePairTCPAnswer(t *testing.T, f *dnsRecoveryFixture, client *dnsRecoveryClient, id uint16) *mdns.Msg {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if resp := dnsCachePairTCPAttempt(client, f.gatewayAddr, id); resp != nil {
			return resp
		}
	}
	t.Fatalf("TCP gateway DNS was not usable after the runtime recovered")
	return nil
}

func dnsCachePairTCPAttempt(client *dnsRecoveryClient, gateway netip.AddrPort, id uint16) *mdns.Msg {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	conn, err := client.tnet.DialContextTCPAddrPort(ctx, gateway)
	cancel()
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()

	req := new(mdns.Msg)
	req.SetQuestion("unlisted.example.", mdns.TypeA)
	req.Id = id
	body, err := req.Pack()
	if err != nil {
		return nil
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(body)))
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return nil
	}
	if _, err := conn.Write(body); err != nil {
		return nil
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil
	}
	respBody := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, respBody); err != nil {
		return nil
	}
	resp := new(mdns.Msg)
	if err := resp.Unpack(respBody); err != nil {
		return nil
	}
	return resp
}

// dnsCachePairRetireRuntime produces the real retirement the defect needs: a reply
// the session's gateway transport cannot write to its client retires the
// session's scope handle, while the authenticated session and its route stay live.
func dnsCachePairRetireRuntime(t *testing.T, f *dnsRecoveryFixture, handle *gatewaydns.ScopeHandle, srcPort uint16) {
	t.Helper()
	f.failNext.Store(true)
	syn := dnsCachePairSYN(t, netip.MustParseAddr(f.assignedIP), netip.MustParseAddr("10.100.0.1"), srcPort)
	if handled, err := f.gw.TrySubmit(handle, syn); !handled || err != nil {
		t.Fatalf("gateway did not accept the session's own TCP SYN: handled=%v err=%v", handled, err)
	}
	waitForCondition(t, "the injected queue-full to be produced by the real reply path", func() bool {
		return f.injected.Load() == 1
	})
	ctx := handle.Context()
	waitForCondition(t, "the real reply failure to retire the scope handle", func() bool {
		return ctx.Err() != nil
	})
	if !f.fwd.HasLiveSession(f.sessionID) {
		t.Fatal("a recoverable reply-write failure retired the authenticated route")
	}
}

// TestDNSRuntimeCacheRecovery_OverlappingRetirementKeepsLiveScope drives the real
// handler, route cache, gateway, netstack transport and final dispatcher through
// a reply-write failure that retires a session's DNS runtime while a worker has
// already prefetched that session's cache scope.
//
// The reply-write failure is a recoverable output error, so the authenticated
// session and its route stay live. After the error clears this test requires what
// a client actually depends on: usable UDP and TCP DNS, live DIRECT policy
// evidence from those answers, and a new public flow that the real dispatcher
// sends through the ingress WAN with direct accounting and no proxied byte. A
// session that answers DNS but records no evidence keeps new flows UNKNOWN and
// proxies them forever, which is the state this case must not leave behind.
//
// The completed-retirement control reaches the same recovery from a retirement
// that has already finished; it must keep passing. The overlapping case must end
// with the recovered runtime paired to the scope the live route owns now, and
// must still refuse authority once the session really retires.
func TestDNSRuntimeCacheRecovery_OverlappingRetirementKeepsLiveScope(t *testing.T) {
	for _, overlap := range []bool{false, true} {
		name := "completed-retirement-control"
		if overlap {
			name = "prefetched-scope-during-retirement"
		}
		t.Run(name, func(t *testing.T) {
			f := newDNSRecoveryFixture(t)
			defer func() { _ = f.handler.Close() }()
			defer func() { _ = f.gw.Close() }()

			// The final egress decision is made by the real manager/dispatcher over
			// the session's route evidence; the WAN and backend sinks are fixtures.
			wan := &mockPBRDevice{}
			dem := forwarder.NewDirectEgressManager(forwarder.DirectEgressConfig{
				HostWANIP:    netip.MustParseAddr("198.51.200.1"),
				GatewayDNSIP: netip.MustParseAddr("10.100.0.1"),
				WANDevice:    wan,
			}, f.fwd)
			defer dem.Close()
			f.fwd.SetDirectEgress(dem)
			f.fwd.SetPBREnabled(true)
			f.fwd.SetPolicyMatcher(f.cache.PolicyMatcher())
			f.fwd.SetGatewayDNSIP(netip.MustParseAddr("10.100.0.1"))
			f.fwd.AttachBackendDevice(1, &mockPBRDevice{})

			client := f.start(t)
			defer client.Close()

			job := dnsJob{
				sessionID:  f.sessionID,
				peerKey:    f.peerKey,
				assignedIP: f.assignedIP,
				path:       f.path,
				packet:     dnsRuntimeTestPacket(t, 17),
			}
			answerIP := netip.MustParseAddr("93.184.216.34")

			// Positive control: a live session's own answer is DIRECT evidence.
			f.handler.processJob(job)
			if got := f.cache.Lookup(f.sessionID, answerIP); got != policy.Direct {
				t.Fatalf("live positive control recorded %v want DIRECT", got)
			}
			oldHandle, present := f.runtimeHandle()
			if !present {
				t.Fatal("live session owns no DNS runtime after its first query")
			}

			// A worker resolves the session's cache scope before it is admitted.
			prefetched := f.handler.sessionScope(f.sessionID)
			if prefetched == nil {
				t.Fatal("live session resolved no cache scope to prefetch")
			}

			var release func()
			if overlap {
				// Keep the retirement inside its invalidate phase, so admitting the
				// prefetched scope happens exactly in the window the defect needs.
				release = dnsCachePairRetirementBarrier(t, f.cache.RouteCache())
			}
			dnsCachePairRetireRuntime(t, f, oldHandle, 40001)

			if overlap {
				// The worker the defect needs: the prefetched scope is still not
				// retired because the old handle has not finished invalidating it.
				if prefetched.Retired() {
					release()
					t.Fatal("fixture: retirement was already complete before the overlap was admitted")
				}
				if rt := f.handler.sessionRuntime(job, prefetched); rt == nil {
					release()
					t.Fatal("recovery refused a live session whose cache invalidation was still in flight")
				}
				release()
			}
			waitForCondition(t, "the retired handle to finish invalidating its scope", prefetched.Retired)

			// The failure has cleared: ordinary UDP DNS must be usable again and
			// must rebuild live evidence for the answer it just delivered.
			before := f.udpReplies.Load()
			for i := 0; i < 3; i++ {
				f.handler.processJob(job)
			}
			if got := f.udpReplies.Load() - before; got != 3 {
				t.Fatalf("later UDP gateway DNS delivered %d/3 replies after the output error cleared", got)
			}
			if got := f.cache.Lookup(f.sessionID, answerIP); got != policy.Direct {
				t.Fatalf("recovered session recorded %v after 3 valid answers; want DIRECT evidence", got)
			}

			// The recovered runtime must own the scope the live route resolves to,
			// not the scope that the old handle was retiring.
			liveScope := f.cache.SessionScope(f.sessionID)
			if liveScope == nil || liveScope.Retired() {
				t.Fatal("live session owns no usable cache scope after recovery")
			}
			recovered, present := f.runtimeHandle()
			if !present {
				t.Fatal("recovered live session owns no DNS runtime")
			}
			if recovered.IsRetired() {
				t.Fatal("recovered runtime is still the canceled handle")
			}
			if recovered.SessionCache != liveScope {
				t.Fatal("recovered runtime is paired with a cache scope the live route no longer owns")
			}

			// ... and a fresh public flow is really sent DIRECT through the ingress
			// WAN, with direct accounting and nothing proxied.
			pkt := buildTestPBRTCPPacket(netip.MustParseAddr(f.assignedIP), answerIP, 45002, 443, []byte("new-flow-after-recovery"))
			if err := f.fwd.RouteClientToBackend(f.peerKey, pkt); err != nil {
				t.Fatalf("dispatch of a fresh flow after recovery: %v", err)
			}
			if written := len(wan.getWritten()); written != 1 {
				t.Fatalf("fresh flow emitted %d WAN packets want 1", written)
			}
			if f.fwd.DirectBytes() == 0 || f.fwd.ProxiedBytes() != 0 {
				t.Fatalf("fresh flow accounting direct=%d proxied=%d want direct>0 proxied=0",
					f.fwd.DirectBytes(), f.fwd.ProxiedBytes())
			}

			// TCP DNS must be usable again on a fresh connection, which needs a live
			// transport owned by the recovered runtime.
			if resp := dnsCachePairTCPAnswer(t, f, client, 6101); len(resp.Answer) != 1 {
				t.Fatalf("later TCP DNS answer carries %d records want 1", len(resp.Answer))
			}

			if n := f.handler.ActiveSessionRuntimes(); n != 1 {
				t.Fatalf("live session owns %d DNS runtimes want 1", n)
			}
			waitForCondition(t, "recovery to leave at most one gateway transport", func() bool {
				return f.gw.ActiveTransports() <= 1
			})
			waitForCondition(t, "recovery to leave at most one limiter scope", func() bool {
				return f.gw.ActiveSessionLimiters() <= 1
			})

			// A genuinely retired session must still be refused, even with a scope
			// that was resolved while its route was live.
			finalScope := f.handler.sessionScope(f.sessionID)
			f.fwd.BeginUnregisterSession(f.peerKey, f.sessionID).Wait()
			if n := f.handler.ActiveSessionRuntimes(); n != 0 {
				t.Fatalf("real retirement left %d DNS runtime(s)", n)
			}
			if rt := f.handler.sessionRuntime(job, finalScope); rt != nil {
				t.Fatal("real retirement regained DNS runtime authority from a stale scope")
			}
		})
	}
}

// TestDNSRuntimeCacheRecovery_RepeatedOverlapsStayBounded repeats the
// prefetched-scope/retirement overlap: each cycle may discard one runtime, but the
// live session must keep a working runtime paired to its current scope, keep
// answering UDP DNS, and never accumulate runtimes, transports or limiters.
func TestDNSRuntimeCacheRecovery_RepeatedOverlapsStayBounded(t *testing.T) {
	f := newDNSRecoveryFixture(t)
	defer func() { _ = f.handler.Close() }()
	defer func() { _ = f.gw.Close() }()
	defer func() { f.fwd.BeginUnregisterSession(f.peerKey, f.sessionID).Wait() }()

	if client := f.start(t); client != nil {
		defer client.Close()
	}

	job := dnsJob{
		sessionID:  f.sessionID,
		peerKey:    f.peerKey,
		assignedIP: f.assignedIP,
		path:       f.path,
		packet:     dnsRuntimeTestPacket(t, 17),
	}
	answerIP := netip.MustParseAddr("93.184.216.34")
	f.handler.processJob(job)

	const cycles = 2
	for i := 0; i < cycles; i++ {
		oldHandle, present := f.runtimeHandle()
		if !present {
			t.Fatalf("cycle %d: live session owns no DNS runtime", i)
		}
		prefetched := f.handler.sessionScope(f.sessionID)
		if prefetched == nil {
			t.Fatalf("cycle %d: live session resolved no cache scope", i)
		}
		release := dnsCachePairRetirementBarrier(t, f.cache.RouteCache())
		dnsCachePairRetireRuntime(t, f, oldHandle, uint16(40002+i))
		if prefetched.Retired() {
			release()
			t.Fatalf("cycle %d: fixture retirement completed before the overlap was admitted", i)
		}
		if rt := f.handler.sessionRuntime(job, prefetched); rt == nil {
			release()
			t.Fatalf("cycle %d: recovery refused a live session", i)
		}
		release()
		waitForCondition(t, "the retired handle to finish invalidating its scope", prefetched.Retired)

		base := f.udpReplies.Load()
		for j := 0; j < 2; j++ {
			f.handler.processJob(job)
		}
		if got := f.udpReplies.Load() - base; got != 2 {
			t.Fatalf("cycle %d: UDP delivered %d/2 replies after recovery", i, got)
		}
		if got := f.cache.Lookup(f.sessionID, answerIP); got != policy.Direct {
			t.Fatalf("cycle %d: recovered session recorded %v want DIRECT", i, got)
		}
		liveScope := f.cache.SessionScope(f.sessionID)
		rt, present := f.runtimeHandle()
		if !present {
			t.Fatalf("cycle %d: recovered session owns no runtime", i)
		}
		if rt.IsRetired() || rt.SessionCache != liveScope {
			t.Fatalf("cycle %d: recovered runtime is not paired with the session's live scope", i)
		}
		if n := f.handler.ActiveSessionRuntimes(); n != 1 {
			t.Fatalf("cycle %d: live session owns %d DNS runtime(s) want 1", i, n)
		}
	}
	waitForCondition(t, "overlaps to leave at most one gateway transport", func() bool {
		return f.gw.ActiveTransports() <= 1
	})
	waitForCondition(t, "overlaps to leave at most one limiter scope", func() bool {
		return f.gw.ActiveSessionLimiters() <= 1
	})
}
