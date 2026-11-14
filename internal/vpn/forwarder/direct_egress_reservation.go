package forwarder

import (
	"errors"
	"fmt"
)

var (
	// ErrHostTupleOwnershipUnavailable is returned when exclusive kernel
	// ownership of a host WAN tuple cannot be established, so direct egress must
	// refuse the flow instead of risking a cross-owner mapping.
	ErrHostTupleOwnershipUnavailable = errors.New("forwarder: host WAN tuple ownership unavailable")
	// errHostTupleInUse reports a candidate port that another local socket
	// already owns. The allocator skips such a candidate: it is provably not
	// ours, and taking it over is exactly the host/VPN crossover this ownership
	// check exists to prevent.
	errHostTupleInUse = errors.New("forwarder: host WAN tuple owned by another socket")
)

const (
	// defaultMaxHostReservations bounds the number of tuples held at once. Every
	// reservation is one file descriptor, so an authenticated peer cannot drive
	// the panel into EMFILE (which would break unrelated descriptor users such as
	// listeners and database connections) by opening direct flows. Reaching the
	// bound refuses direct egress for new flows: fail closed, drop and count.
	defaultMaxHostReservations = 4096
)

// reserveHostPortLocked makes the direct-NAT port exclusively ours in the kernel
// for the whole binding lifetime. Callers hold m.mu.
//
// It is idempotent: a port that this manager already reserves is kept.
func (m *DirectEgressManager) reserveHostPortLocked(proto uint8, port uint16) error {
	if m.reservations[port] != nil {
		return nil
	}
	if limit := m.maxReservations; limit > 0 && len(m.reservations) >= limit {
		return fmt.Errorf("%w: %d reservations held", ErrHostTupleOwnershipUnavailable, len(m.reservations))
	}
	reservation, err := reserveHostPort(proto, port)
	if err != nil {
		return err
	}
	m.reservations[port] = reservation
	return nil
}

// releaseHostPortLocked gives up kernel ownership of a port. Callers hold m.mu
// and have already removed the port from every userspace table, so nothing can
// still route a reply to it.
func (m *DirectEgressManager) releaseHostPortLocked(port uint16) {
	reservation, ok := m.reservations[port]
	if !ok {
		return
	}
	delete(m.reservations, port)
	if reservation != nil {
		_ = reservation.Close()
	}
}

// releaseAllHostPortsLocked drops every reservation, used when the manager
// discards all NAT state or closes.
func (m *DirectEgressManager) releaseAllHostPortsLocked() {
	for port := range m.reservations {
		m.releaseHostPortLocked(port)
	}
}

// HostReservationCount returns the number of host tuples currently held
// exclusively by this manager (useful for tests and diagnostics).
func (m *DirectEgressManager) HostReservationCount() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.reservations)
}

// clampMaxReservations resolves the reservation bound for a configured value and
// port pool size.
func clampMaxReservations(configured, poolSize int) int {
	limit := configured
	if limit <= 0 {
		limit = defaultMaxHostReservations
	}
	if poolSize > 0 && limit > poolSize {
		limit = poolSize
	}
	if limit < 1 {
		limit = 1
	}
	return limit
}
