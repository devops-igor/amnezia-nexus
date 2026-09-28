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

type routeWriter struct {
	path                *ReturnPath
	peerKey, assignedIP string
}

func (w routeWriter) Write(packet []byte) (int, error) {
	w.path.mu.RLock()
	defer w.path.mu.RUnlock()
	if w.path.closed || w.path.write == nil {
		return 0, ErrReturnPathClosed
	}
	if !validReturnDestination(packet, w.assignedIP) {
		return 0, ErrReturnRouteMismatch
	}
	return w.path.write(w.peerKey, w.assignedIP, packet)
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

// HasSessionRouteWithReturnPath includes engine ownership in the router's memo
// validity check. A same-session legacy replacement cannot preserve that memo.
func (f *Forwarder) HasSessionRouteWithReturnPath(peerKey, sessionID, connectionID, assignedIP string, backendID int64, path *ReturnPath) bool {
	if path == nil || path.Closed() {
		return false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	r := f.routesByPeer[peerKey]
	return r != nil && !r.stopped && r.sessionID == sessionID && r.connectionID == connectionID && r.assignedIP == assignedIP && r.backendTunnelID == backendID && r.returnPath == path
}
