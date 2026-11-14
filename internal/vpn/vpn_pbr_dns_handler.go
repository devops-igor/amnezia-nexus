package vpn

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// Intercepted gateway DNS: the queued per-query work and the per-session
// runtime authority that owns it. A session's DNS handle, reply writer and
// gateway transport are retired together with the session's route.

type dnsJob struct {
	sessionID  string
	peerKey    string
	assignedIP string
	path       *forwarder.ReturnPath
	packet     []byte
}

// errDNSSessionRetired fences an intercepted DNS reply whose authenticated
// session retired while the reply was being produced.
var errDNSSessionRetired = errors.New("vpn: intercepted dns session retired")

// dnsSessionRuntime is the intercepted-DNS authority of one authenticated
// session. Every queued query of the session is submitted through the same
// ScopeHandle, so a session owns exactly one cancellable scope, one reply
// writer and (for TCP) one gateway transport, rather than one of each per
// query, and retiring the session retires all of them.
type dnsSessionRuntime struct {
	handle *gatewaydns.ScopeHandle
	writer *pbrReplyWriter
}

type pbrDNSHandler struct {
	gw          *gatewaydns.Gateway
	rc          forwarder.RouteCache
	sessionLive func(sessionID string) bool
	queue       chan dnsJob
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	closed      atomic.Bool
	dropped     atomic.Uint64
	retired     atomic.Uint64

	// mu guards sessions, the live per-session DNS runtimes. It is only ever
	// acquired after the forwarder and route-cache locks (see sessionRuntime
	// and RetireSessionRuntime); those never acquire it while holding theirs.
	mu       sync.Mutex
	sessions map[string]*dnsSessionRuntime
}

const (
	defaultDNSWorkerCount = 8
	defaultDNSQueueCap    = 256
)

func newPBRDNSHandler(gw *gatewaydns.Gateway, rc forwarder.RouteCache, sessionLive func(sessionID string) bool) *pbrDNSHandler {
	ctx, cancel := context.WithCancel(context.Background())
	h := &pbrDNSHandler{
		gw:          gw,
		rc:          rc,
		sessionLive: sessionLive,
		queue:       make(chan dnsJob, defaultDNSQueueCap),
		ctx:         ctx,
		cancel:      cancel,
		sessions:    make(map[string]*dnsSessionRuntime),
	}
	// The route cache is the session-scope authority that every route-removal
	// path already retires through, so attach this handler's runtime to it: a
	// released session scope then releases the DNS work that scope authorized.
	if cache, ok := rc.(*MemoryRouteCache); ok {
		cache.setSessionRuntime(h)
	}
	h.wg.Add(defaultDNSWorkerCount)
	for i := 0; i < defaultDNSWorkerCount; i++ {
		go h.worker()
	}
	return h
}

func (h *pbrDNSHandler) Close() error {
	if h == nil {
		return nil
	}
	if h.closed.CompareAndSwap(false, true) {
		h.cancel()
		h.retireAllRuntimes()
		if cache, ok := h.rc.(*MemoryRouteCache); ok {
			cache.clearSessionRuntime(h)
		}
		h.wg.Wait()
	}
	return nil
}

func (h *pbrDNSHandler) worker() {
	defer h.wg.Done()
	for {
		select {
		case <-h.ctx.Done():
			return
		case job, ok := <-h.queue:
			if !ok {
				return
			}
			h.processJob(job)
		}
	}
}

func (h *pbrDNSHandler) processJob(job dnsJob) {
	if h.gw == nil {
		return
	}
	// The cache scope is resolved first: its liveness fence takes the forwarder
	// lock, which sits above the handler lock in the lock order.
	sc := h.sessionScope(job.sessionID)
	if sc == nil {
		// The session retired (or was never admitted) before this queued job
		// ran. Its cache scope was released with its route and must not be
		// recreated: a resurrected scope would refill the bounded cache with
		// evidence no live session owns.
		h.retired.Add(1)
		return
	}
	rt := h.sessionRuntime(job, sc)
	if rt == nil {
		// The handler closed or the session retired while this job was being
		// admitted; either way the work has no owner left to answer for it.
		h.retired.Add(1)
		return
	}
	_, _ = h.gw.TrySubmit(rt.handle, job.packet)
}

// sessionRuntime returns the DNS runtime authority of the job's session,
// creating it on that session's first intercepted query.
//
// Creation is published under h.mu and re-fenced against the cache scope's
// retirement inside the same critical section: a retirement that interleaved
// with the liveness fence above either already invalidated the scope (so no
// runtime is created) or deletes the runtime this call published.
func (h *pbrDNSHandler) sessionRuntime(job dnsJob, sc *policy.SessionCache) *dnsSessionRuntime {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed.Load() || sc.Retired() {
		return nil
	}
	if rt := h.sessions[job.sessionID]; rt != nil {
		rt.writer.setTarget(job)
		return rt
	}
	writer := &pbrReplyWriter{}
	writer.setTarget(job)
	handle := gatewaydns.NewScopeHandle(
		h.ctx,
		policy.Scope{SessionID: job.sessionID, OwnershipEpoch: 1},
		sc,
		writer,
	)
	writer.handle.Store(handle)
	rt := &dnsSessionRuntime{handle: handle, writer: writer}
	h.sessions[job.sessionID] = rt
	return rt
}

// RetireSessionRuntime retires the intercepted-DNS authority of a session whose
// route is being removed: its live scope handle is retired, which cancels the
// in-flight resolver and the transport context, and its per-session limiter
// bookkeeping is released.
//
// It is called from the forwarder's route-removal critical section (through the
// route cache's session-scope retirement), so it must stay memory-only and
// non-blocking and must never call back into the forwarder. Gateway transports
// are owned by their scope context and are torn down by the existing watcher as
// soon as that context is canceled.
func (h *pbrDNSHandler) RetireSessionRuntime(sessionID string) {
	if h == nil || sessionID == "" {
		return
	}
	h.mu.Lock()
	rt := h.sessions[sessionID]
	if rt != nil {
		delete(h.sessions, sessionID)
	}
	h.mu.Unlock()
	h.retireRuntime(rt)
}

// retireRuntime releases one session's runtime authority. Retire is
// memory-only: it fences the writer, cancels the scope context and invalidates
// the session cache.
func (h *pbrDNSHandler) retireRuntime(rt *dnsSessionRuntime) {
	if rt == nil {
		return
	}
	rt.handle.Retire()
	if h.gw != nil {
		h.gw.RetireScope(rt.handle.Scope)
	}
}

func (h *pbrDNSHandler) retireAllRuntimes() {
	h.mu.Lock()
	runtimes := make([]*dnsSessionRuntime, 0, len(h.sessions))
	for sessionID, rt := range h.sessions {
		delete(h.sessions, sessionID)
		runtimes = append(runtimes, rt)
	}
	h.mu.Unlock()
	for _, rt := range runtimes {
		h.retireRuntime(rt)
	}
}

// ActiveSessionRuntimes returns the number of sessions currently holding
// intercepted-DNS runtime state. A retired session owns none, so this is the
// bounded-state invariant for the handler.
func (h *pbrDNSHandler) ActiveSessionRuntimes() int {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.sessions)
}

// liveSessionScopeSource is implemented by route caches that can expose a
// session's scope without allocating one for a session that no longer owns a
// route.
type liveSessionScopeSource interface {
	SessionScopeForLiveSession(sessionID string, live func(sessionID string) bool) *policy.SessionCache
}

// sessionScope resolves the cache scope for a queued DNS job. Delayed work may
// run after its session retired, so allocation is fenced by session liveness
// instead of by the absence of an entry alone.
func (h *pbrDNSHandler) sessionScope(sessionID string) *policy.SessionCache {
	if resolver, ok := h.rc.(liveSessionScopeSource); ok {
		return resolver.SessionScopeForLiveSession(sessionID, h.sessionLive)
	}
	if opener, ok := h.rc.(interface {
		Open(policy.Scope) (*policy.SessionCache, error)
	}); ok {
		sc, _ := opener.Open(policy.Scope{SessionID: sessionID, OwnershipEpoch: 1})
		return sc
	}
	return nil
}

func (h *pbrDNSHandler) HandleDNSPacket(sessionID, peerKey, assignedIP string, path *forwarder.ReturnPath, packet []byte) (bool, error) {
	if h == nil || h.gw == nil || h.closed.Load() {
		return false, nil
	}
	if len(packet) < 20 {
		return false, nil
	}
	ihl := int(packet[0]&0x0f) * 4
	if len(packet) < ihl+8 {
		return false, nil
	}
	proto := packet[9]
	if proto != 17 && proto != 6 {
		return false, nil
	}
	dstPort := binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
	if dstPort != 53 {
		return false, nil
	}

	pktCopy := make([]byte, len(packet))
	copy(pktCopy, packet)

	job := dnsJob{
		sessionID:  sessionID,
		peerKey:    peerKey,
		assignedIP: assignedIP,
		path:       path,
		packet:     pktCopy,
	}

	select {
	case h.queue <- job:
		return true, nil
	default:
		h.dropped.Add(1)
		return true, nil
	}
}

// dnsReplyTarget is the return destination of one queued DNS job: the return
// path of the route that carried the query and the peer/assigned IP the reply is
// addressed to. A same-session rekey may replace that path, so the target is
// refreshed for every job instead of being frozen into the session runtime.
type dnsReplyTarget struct {
	path       *forwarder.ReturnPath
	peerKey    string
	assignedIP string
}

// pbrReplyWriter is the single DNS reply writer of an authenticated session. The
// gateway TCP transport keeps using it across packets, so the per-job target is
// published atomically and the retirement fence reads the session's scope handle
// at write time.
type pbrReplyWriter struct {
	target atomic.Pointer[dnsReplyTarget]
	handle atomic.Pointer[gatewaydns.ScopeHandle]
}

func (w *pbrReplyWriter) setTarget(job dnsJob) {
	w.target.Store(&dnsReplyTarget{
		path:       job.path,
		peerKey:    job.peerKey,
		assignedIP: job.assignedIP,
	})
}

// WritePacket is the final writer fence for intercepted DNS: a reply whose
// authenticated session retired is refused here as well as at the gateway's own
// pre-write check, because retirement can complete between that check and this
// write.
func (w *pbrReplyWriter) WritePacket(_ policy.Scope, packet []byte) error {
	if handle := w.handle.Load(); handle != nil && handle.IsRetired() {
		return errDNSSessionRetired
	}
	target := w.target.Load()
	if target == nil || target.path == nil {
		return forwarder.ErrReturnPathClosed
	}
	_, err := target.path.Write(target.peerKey, target.assignedIP, packet)
	return err
}
