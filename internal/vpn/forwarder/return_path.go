package forwarder

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
)

var ErrReturnRouteMismatch = errors.New("forwarder: backend return route mismatch")
var ErrReturnPathClosed = errors.New("forwarder: upstream return path closed")

type packetWriter interface{ Write([]byte) (int, error) }

// ReturnPath identifies one client engine lifetime. Routes retain this owner
// after Close, so they can never silently fall back to legacy encryption.
// The callback must be bounded and nonblocking; packets are owned by the pump.
type ReturnPath struct {
	mu     sync.RWMutex
	closed bool
	write  func(peerKey, assignedIP string, packet []byte) (int, error)
}

func NewReturnPath(write func(peerKey, assignedIP string, packet []byte) (int, error)) *ReturnPath {
	return &ReturnPath{write: write}
}

// Close rejects future writes and joins writes already admitted to the callback.
func (p *ReturnPath) Close()       { p.mu.Lock(); p.closed = true; p.mu.Unlock() }
func (p *ReturnPath) Closed() bool { p.mu.RLock(); defer p.mu.RUnlock(); return p.closed }

// Write attempts to write a return packet to peerKey and assignedIP. If the path
// is nil, closed, or uninitialized, ErrReturnPathClosed is returned.
func (p *ReturnPath) Write(peerKey, assignedIP string, packet []byte) (int, error) {
	if p == nil {
		return 0, ErrReturnPathClosed
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed || p.write == nil {
		return 0, ErrReturnPathClosed
	}
	return p.write(peerKey, assignedIP, packet)
}

type routeWriter struct {
	path                *ReturnPath
	peerKey, assignedIP string
}

func (w routeWriter) Write(packet []byte) (int, error) {
	if !validReturnDestination(packet, w.assignedIP) {
		return 0, ErrReturnRouteMismatch
	}
	return w.path.Write(w.peerKey, w.assignedIP, packet)
}

func validReturnDestination(packet []byte, destination string) bool {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return false
	}
	header := int(packet[0]&15) * 4
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if header < 20 || header > len(packet) || total < header || total > len(packet) {
		return false
	}
	actual := netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
	return actual.String() == destination
}

// BindSessionReturnPath replaces only the matching route generation when its
// engine owner changes. Repeated admission for the same owner leaves queues,
// token buckets and protocol-independent routing session intact.
// Wait on the returned retirement after releasing caller serialization locks.
func (f *Forwarder) BindSessionReturnPath(sessionID, connectionID, peerKey, assignedIP string, backendID int64, path *ReturnPath) (Retirement, error) {
	if path != nil && path.Closed() {
		return Retirement{}, ErrReturnPathClosed
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	old := f.routesByPeer[peerKey]
	if old == nil || old.sessionID != sessionID || old.connectionID != connectionID || old.assignedIP != assignedIP || old.backendTunnelID != backendID {
		return Retirement{}, ErrSessionNotRegistered
	}
	if old.returnPath == path {
		return Retirement{}, nil
	}
	retired, err := f.registerSessionLocked(sessionID, connectionID, peerKey, assignedIP, backendID, old.limitDownBps, old.limitUpBps, path)
	if err == nil {
		current := f.routesByPeer[peerKey]
		current.tbDown, current.tbUp = old.tbDown, old.tbUp
	}
	return retired, err
}

// ReturnRejectReason classifies a packet rejected by the forwarder's
// production return-path filters before any per-route handling. The ingress
// engine folds these rejections into its MalformedDrops/UnmappedDrops
// counters via SetUnroutedReturnClassifier; see Forwarder.unroutedReturnClassifier
// for the single-owner rule per drop reason.
type ReturnRejectReason int

const (
	// ReturnRejectedUnrouted: no session route was registered for the
	// reply's destination IP (routesByIP lookup missed).
	ReturnRejectedUnrouted ReturnRejectReason = iota
	// ReturnRejectedMalformed: the reply failed the return-path shape filter
	// (validReturnDestination) for a route that owns a ReturnPath.
	ReturnRejectedMalformed
	// ReturnRejectedMismatch: the reply arrived on a backend tunnel that the
	// destination route does not own — an ownership mismatch, rejected by the
	// same filter as the malformed shape. It maps to the engine's
	// OwnershipMismatchDrops so each reason keeps exactly one owner.
	ReturnRejectedMismatch
)

// SetReturnRejectClassifier registers exactly one service-level callback
// invoked for every return packet rejected by RouteBackendToClient's
// production filters. The callback must be bounded and nonblocking (it runs
// in the backend reader's goroutine); it is called OUTSIDE f.mu.
//
// Classification is owned by the rejection site, never by the engine's write
// callback, so a packet is counted exactly once per drop reason:
//   - an UNROUTED reply is rejected at the routesByIP lookup before any
//     route (and therefore any ReturnPath writer) exists — only the
//     classifier can count it;
//   - a MALFORMED or BACKEND-MISMATCHED reply for an owned route is
//     rejected by the shape filter, which returns before path.write — the
//     engine's write callback never sees the packet, so only the classifier
//     counts it.
//
// In production the ingress engine registers its classifier once during
// construction and never swaps it; later calls overwrite the previous
// callback (test convenience), which intentionally re-targets subsequent
// classifications.
func (f *Forwarder) SetReturnRejectClassifier(classify func(reason ReturnRejectReason)) {
	if classify == nil {
		return
	}
	f.mu.Lock()
	f.returnRejectClassifier = classify
	f.mu.Unlock()
}

// classifyReturnReject snapshots the registered classifier under RLock and
// invokes it without holding f.mu (the callback is arbitrary user code, e.g.
// the engine's atomic counter bumps — never lock-ordered with f.mu).
func (f *Forwarder) classifyReturnReject(reason ReturnRejectReason) {
	f.mu.RLock()
	classify := f.returnRejectClassifier
	f.mu.RUnlock()
	if classify != nil {
		classify(reason)
	}
}

// HasSessionRouteWithReturnPath includes engine ownership in the router's memo
// validity check. A same-session legacy replacement cannot preserve that memo.
func (f *Forwarder) HasSessionRouteWithReturnPath(peerKey, sessionID, connectionID, assignedIP string, backendID int64, path *ReturnPath) bool {
	if path == nil || path.Closed() {
		return false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	r := f.routesByPeer[peerKey]
	return r != nil && !r.stopped && r.sessionID == sessionID && r.connectionID == connectionID && r.assignedIP == assignedIP && r.backendTunnelID == backendID && r.returnPath == path && f.routesByIP[assignedIP] == r
}
