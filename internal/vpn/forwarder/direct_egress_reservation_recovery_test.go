//go:build linux

package forwarder

import (
	"errors"
	"testing"
	"time"
)

// The tests in this file cover the reservation-lifetime rule for DIRECT
// admission: the exclusive-ownership bound is one kernel socket per binding
// lifetime, including the port-cooldown window after a flow retires, so a bound
// reached by flows that already expired must be reclaimed by the allocation path
// itself instead of pinning every later DIRECT flow forever.
//
// Everything below runs through the authentic dispatcher: Forwarder session
// registration and policy evidence, the real direct-NAT allocator, real kernel
// host-tuple reservations and the real WAN reply demultiplexer. Only the WAN
// packet device and the return-path sink are fixtures.

// reservationFillPort is the client source port of the fill flows. Each fill flow
// differs only in its remote port, so every one is a distinct 5-tuple.
const reservationFillPort = 12345

// reservationFillState reports the tracked flow count and how many of them are
// already past their configured timeout.
func (h *sessionQuarantineHarness) reservationFillState() (total, expired int) {
	h.dem.mu.RLock()
	defer h.dem.mu.RUnlock()
	now := time.Now()
	for k, f := range h.dem.flows {
		if h.dem.isFlowExpiredLocked(f, k.Protocol, now) {
			expired++
		}
	}
	return len(h.dem.flows), expired
}

// fillReservationCap admits count DIRECT flows through the dispatcher and returns
// the NAT port each one used, in admission order.
func (h *sessionQuarantineHarness) fillReservationCap(count int) []uint16 {
	h.t.Helper()
	ports := make([]uint16, 0, count)
	for i := 0; i < count; i++ {
		if err := h.dispatchUDP(reservationFillPort, uint16(53+i), "fill"); err != nil {
			h.t.Fatalf("fill flow %d was refused: %v", i, err)
		}
		ports = append(ports, h.lastNATPort())
	}
	return ports
}

// TestDirectEgressReservationCapRefusesAllLiveFlows is the negative control of the
// audited finding: a bound held by live flows still refuses new DIRECT admission,
// retires nothing, keeps every kernel tuple and keeps serving active traffic.
func TestDirectEgressReservationCapRefusesAllLiveFlows(t *testing.T) {
	const reservationCap = 8
	base := freeNATRange(t, reservationCap+2)
	h := newDirectEgressHarness(t, DirectEgressConfig{
		MinPort:             base,
		MaxPort:             base + reservationCap + 1,
		UDPTimeout:          2 * time.Second,
		MaxHostReservations: reservationCap,
	})
	sink := h.register("session-one")
	ports := h.fillReservationCap(reservationCap)

	if got := h.dem.HostReservationCount(); got != reservationCap {
		t.Fatalf("precondition: want %d held reservations, got %d", reservationCap, got)
	}

	err := h.dispatchUDP(reservationFillPort, uint16(53+reservationCap), "all-live")
	if !errors.Is(err, ErrHostTupleOwnershipUnavailable) {
		t.Fatalf("all-live cap: want ErrHostTupleOwnershipUnavailable, got %v", err)
	}
	if total, expired := h.reservationFillState(); total != reservationCap || expired != 0 {
		t.Fatalf("all-live cap must not retire live flows: total=%d expired=%d", total, expired)
	}
	if got := h.dem.HostReservationCount(); got != reservationCap {
		t.Fatalf("all-live cap changed ownership: reservations=%d, want %d", got, reservationCap)
	}
	if got := len(h.wanDev.getPackets()); got != reservationCap {
		t.Fatalf("refused flow wrote %d WAN packet(s)", got-reservationCap)
	}
	h.requireDelivered(sink, ports[0], 53, "fill-reply", "active flow reply under a live cap")
}

// TestDirectEgressReservationCapRecoversAfterExpiry is the audited regression: the
// allocation path must reclaim a bound held by flows that already expired, without
// any explicit sweep or route teardown, and must still respect the ordinary
// cooldown before the kernel tuples are reusable.
func TestDirectEgressReservationCapRecoversAfterExpiry(t *testing.T) {
	const reservationCap = 8
	base := freeNATRange(t, reservationCap+2)
	cooldown := 40 * time.Millisecond
	flowTimeout := 5 * time.Millisecond
	h := newDirectEgressHarness(t, DirectEgressConfig{
		MinPort:             base,
		MaxPort:             base + reservationCap + 1,
		UDPTimeout:          flowTimeout,
		MaxHostReservations: reservationCap,
	})
	h.dem.SetPortCooldown(cooldown)
	h.dem.SetQuarantineDurations(cooldown, cooldown)
	sink := h.register("session-one")
	ports := h.fillReservationCap(reservationCap)

	// Let every fill flow expire. Nothing has retired them yet, and the pool still
	// has spare ports, so only the reservation bound can end admission.
	time.Sleep(8 * flowTimeout)
	total, expired := h.reservationFillState()
	if total != reservationCap || expired != reservationCap {
		t.Fatalf("precondition: want %d expired flows, got expired=%d total=%d", reservationCap, expired, total)
	}

	// The next admission attempt must reclaim them by itself. Retired tuples stay
	// kernel-owned for the ordinary cooldown, so this attempt is legitimately
	// refused and no ownership is dropped early to manufacture capacity.
	err := h.dispatchUDP(reservationFillPort, uint16(53+reservationCap), "after-expiry")
	if !errors.Is(err, ErrHostTupleOwnershipUnavailable) {
		t.Fatalf("attempt inside the cooldown: want ErrHostTupleOwnershipUnavailable, got %v", err)
	}
	if total, expired := h.reservationFillState(); total != 0 || expired != 0 {
		t.Fatalf("expired flows were not reclaimed by the allocation path: total=%d expired=%d", total, expired)
	}
	if got := h.dem.HostReservationCount(); got != reservationCap {
		t.Fatalf("reclamation dropped kernel ownership before the cooldown elapsed: reservations=%d, want %d", got, reservationCap)
	}
	if retired := h.bindingState(ports[0], 53); !retired.found || retired.active || !retired.quarantined {
		t.Fatalf("retired tuple is not quarantined: %+v", retired)
	}

	// Once the ordinary cooldown elapses, one new DIRECT flow is admitted through
	// the dispatcher and works end to end, with no test-only reclamation step.
	time.Sleep(3 * cooldown)
	if err := h.dispatchUDP(reservationFillPort, uint16(53+reservationCap+1), "recovered"); err != nil {
		t.Fatalf("DIRECT admission did not recover after the ordinary cooldown: %v", err)
	}
	recoveredPort := h.lastNATPort()
	if got := h.dem.HostReservationCount(); got != 1 {
		t.Fatalf("recovered flow holds %d reservations, want 1", got)
	}
	h.requireDelivered(sink, recoveredPort, uint16(53+reservationCap+1), "recovered-reply", "recovered flow reply")

	// Recovery is durable, not a single reclaimed slot.
	if err := h.dispatchUDP(reservationFillPort, uint16(53+reservationCap+2), "recovered-next"); err != nil {
		t.Fatalf("subsequent DIRECT admission after recovery failed: %v", err)
	}
}

// TestDirectEgressReservationCapRecoversAtDefaultBound drives the same recovery at
// the production defaults: the default 4096-tuple bound and the default 25001-port
// pool, through the real dispatcher and real kernel reservations.
func TestDirectEgressReservationCapRecoversAtDefaultBound(t *testing.T) {
	cooldown := 40 * time.Millisecond
	flowTimeout := 5 * time.Millisecond
	h := newDirectEgressHarness(t, DirectEgressConfig{UDPTimeout: flowTimeout})
	h.dem.SetPortCooldown(cooldown)
	h.dem.SetQuarantineDurations(cooldown, cooldown)
	sink := h.register("session-one")
	ports := h.fillReservationCap(defaultMaxHostReservations)

	if got := h.dem.HostReservationCount(); got != defaultMaxHostReservations {
		t.Fatalf("precondition: want the default bound %d fully held, got %d", defaultMaxHostReservations, got)
	}
	time.Sleep(8 * flowTimeout)
	if _, expired := h.reservationFillState(); expired != defaultMaxHostReservations {
		t.Fatalf("precondition: want %d expired flows, got %d", defaultMaxHostReservations, expired)
	}

	err := h.dispatchUDP(reservationFillPort, uint16(53+defaultMaxHostReservations), "after-expiry")
	if !errors.Is(err, ErrHostTupleOwnershipUnavailable) {
		t.Fatalf("attempt inside the cooldown: want ErrHostTupleOwnershipUnavailable, got %v", err)
	}
	if total, _ := h.reservationFillState(); total != 0 {
		t.Fatalf("expired flows were not reclaimed at the default bound: %d still tracked", total)
	}
	if got := h.dem.HostReservationCount(); got != defaultMaxHostReservations {
		t.Fatalf("default bound ownership dropped before the cooldown elapsed: reservations=%d", got)
	}
	if retired := h.bindingState(ports[0], 53); !retired.quarantined {
		t.Fatalf("retired tuple is not quarantined: %+v", retired)
	}

	time.Sleep(3 * cooldown)
	recoveryPort := uint16(53 + defaultMaxHostReservations + 1) // #nosec G115 -- fixed small bound
	if err := h.dispatchUDP(reservationFillPort, recoveryPort, "recovered"); err != nil {
		t.Fatalf("DIRECT admission did not recover at the default bound: %v", err)
	}
	h.requireDelivered(sink, h.lastNATPort(), recoveryPort, "recovered-reply", "recovered flow reply at the default bound")
}
