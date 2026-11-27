package handlers

// The repair evidence is the inventory observation's own instant, not the moment the
// detail answer that contradicted it was processed.
//
// A list request takes its inventory snapshot at one instant and then asks each order's
// detail. The provider can remove the VPS while that request is still in flight, so a
// detail answer can carry a deletion whose evidence time is after the snapshot. That
// listing cannot contradict an event that happened later than it. Stamping the repair
// with the processing time of the detail answer claimed exactly that: the durable repair
// landed after the real deletion, so every later complete omission was rejected as
// "older than the repair" and a genuinely removed deployment stayed Ready with Setup and
// Approve offered for good.
//
// The latency below is what makes the two instants distinguishable inside one request.
// The deletion evidence is placed between the snapshot and the detail answer, which is
// the reported sequence; no other timing is involved and no wall-clock assumption is
// made beyond monotonic time.

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// repairInFlightLatency is how long the inventory answer stays in flight after its own
// instant. It only has to be longer than the deletion offset below so that evidence
// dated inside the request is in the past by the time the answer is processed.
const repairInFlightLatency = 1100 * time.Millisecond

// TestDeletionAfterTheRepairingInventoryObservationIsRecorded is the reported sequence:
// a live inventory snapshot, a deletion that postdates it, then a complete omission.
func TestDeletionAfterTheRepairingInventoryObservationIsRecorded(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const (
		orderID  = "ord_995_07_after_snapshot"
		address  = "198.51.100.219"
		serverID = int64(6219)
	)
	seedUnonboardedOrder(t, h, orderID, address)

	// A genuinely repaired order: the durable repair predates the request this test is about.
	// The provider identity is already on the row, so this first listing changes nothing and
	// the request goes on to read the order detail - the sequence being reproduced.
	previousRepair := time.Now().UTC().Add(-time.Hour)
	order, found, err := h.db.GetGigahostOrder(context.Background(), orderID)
	if err != nil || !found {
		t.Fatalf("seed order: found=%t err=%v", found, err)
	}
	order.Status = DeployStatusReady
	order.ServerID = serverID
	order.LiveRepairedAt = &previousRepair
	if err := h.db.UpdateGigahostOrderObservation(context.Background(), order, nil); err != nil {
		t.Fatalf("record the earlier repair: %v", err)
	}

	listed := true
	var snapshotAt time.Time
	var deletionEvidence time.Time
	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			if !listed {
				// The provider removed the VPS: a complete listing that answers and omits it.
				return nil, nil
			}
			snapshotAt = time.Now().UTC()
			time.Sleep(repairInFlightLatency)
			return []gigahost.ServerInfo{{ID: serverID, OrderID: orderID, IPv4: address, Status: gigahost.StatusReady}}, nil
		},
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			if deletionEvidence.IsZero() {
				// The provider removed the VPS after the snapshot above: later than what the
				// listing saw, earlier than the moment this request processes the answer.
				deletionEvidence = snapshotAt.Add(repairInFlightLatency / 2)
			}
			return &gigahost.DeployStatusResponse{
				OrderID: orderID, ServerID: serverID,
				Status: deletedProviderStatus, UpdatedAt: deletionEvidence.Format(time.RFC3339Nano),
			}, nil
		},
	})

	// Read one: the inventory still lists the server and the detail carries the newer
	// deletion. The listing must not claim a repair after the event it contradicts.
	readOrderStatusList(t, h, orderID)
	if snapshotAt.IsZero() || deletionEvidence.IsZero() {
		t.Fatalf("fixture premise: the listing and the detail must both be answered")
	}
	afterSnapshot, found, err := h.db.GetGigahostOrder(context.Background(), orderID)
	if err != nil || !found {
		t.Fatalf("reload after the snapshot read: found=%t err=%v", found, err)
	}
	if afterSnapshot.Status != DeployStatusReady {
		t.Fatalf("the listing's own answer must stand on this read, got %q", afterSnapshot.Status)
	}
	if afterSnapshot.LiveRepairedAt != nil && afterSnapshot.LiveRepairedAt.After(deletionEvidence) {
		t.Errorf("the repair was stamped with the processing time of the detail answer (%s), later than "+
			"the deletion it claims to contradict (%s): that deletion can never be recorded again",
			afterSnapshot.LiveRepairedAt.Format(time.RFC3339Nano), deletionEvidence.Format(time.RFC3339Nano))
	}

	// Read two onwards: the provider's inventory answers completely and omits the VPS
	// while the detail repeats the same deletion. That deletion is now the newest evidence.
	listed = false
	for attempt := 1; attempt <= 2; attempt++ {
		read := readOrderStatusList(t, h, orderID)
		stored, found, err := h.db.GetGigahostOrder(context.Background(), orderID)
		if err != nil || !found {
			t.Fatalf("attempt %d: reload the ledger row: found=%t err=%v", attempt, found, err)
		}
		if stored.Status != deletedProviderStatus {
			t.Fatalf("attempt %d: a deletion newer than the repairing observation must be recorded, ledger says %q",
				attempt, stored.Status)
		}
		row := renderedRowFor(t, renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, read, orderID)), orderID)
		if row.Stage != deletedProviderStatus {
			t.Fatalf("attempt %d: the view must present the recorded deletion, got %q", attempt, row.Stage)
		}
		if len(row.Actions) != 0 {
			t.Fatalf("attempt %d: a deleted deployment must offer no contact action, got %v", attempt, row.Actions)
		}
	}
}

// TestInventoryRepairIsStampedWithTheObservationInstant covers the other writer of the
// same fact: an affirmative listing repairing a recorded deletion.
func TestInventoryRepairIsStampedWithTheObservationInstant(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const (
		orderID  = "ord_995_07_repair_instant"
		address  = "198.51.100.220"
		serverID = int64(6220)
	)
	seedUnonboardedOrder(t, h, orderID, address)
	order, found, err := h.db.GetGigahostOrder(context.Background(), orderID)
	if err != nil || !found {
		t.Fatalf("seed order: found=%t err=%v", found, err)
	}
	order.Status = deletedProviderStatus
	if err := h.db.UpdateGigahostOrder(context.Background(), order); err != nil {
		t.Fatalf("record the deletion: %v", err)
	}

	listed := true
	var snapshotAt time.Time
	var deletionEvidence time.Time
	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			if !listed {
				return nil, nil
			}
			snapshotAt = time.Now().UTC()
			time.Sleep(repairInFlightLatency)
			return []gigahost.ServerInfo{{ID: serverID, OrderID: orderID, IPv4: address, Status: gigahost.StatusReady}}, nil
		},
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			if deletionEvidence.IsZero() {
				deletionEvidence = snapshotAt.Add(repairInFlightLatency / 2)
			}
			return &gigahost.DeployStatusResponse{
				OrderID: orderID, ServerID: serverID,
				Status: deletedProviderStatus, UpdatedAt: deletionEvidence.Format(time.RFC3339Nano),
			}, nil
		},
	})

	// The affirmative listing repairs the deletion. Its evidence is the listing's own
	// request instant, so it may not be stamped after the listing it rests on.
	readOrderStatusList(t, h, orderID)
	repaired, found, err := h.db.GetGigahostOrder(context.Background(), orderID)
	if err != nil || !found {
		t.Fatalf("reload after the repair read: found=%t err=%v", found, err)
	}
	if repaired.Status != DeployStatusReady {
		t.Fatalf("an affirmative listing must repair the recorded deletion, got %q", repaired.Status)
	}
	if repaired.LiveRepairedAt == nil {
		t.Fatalf("the repair has no durable evidence: %+v", repaired)
	}
	if repaired.LiveRepairedAt.After(snapshotAt) {
		t.Errorf("the repair (%s) was stamped after the listing it rests on (%s): "+
			"a removal during that request could never be recorded",
			repaired.LiveRepairedAt.Format(time.RFC3339Nano), snapshotAt.Format(time.RFC3339Nano))
	}

	// The removal the provider performed during that request is newer evidence.
	listed = false
	read := readOrderStatusList(t, h, orderID)
	stored, found, err := h.db.GetGigahostOrder(context.Background(), orderID)
	if err != nil || !found {
		t.Fatalf("reload after the omission read: found=%t err=%v", found, err)
	}
	if stored.Status != deletedProviderStatus {
		t.Fatalf("a deletion newer than the repairing observation must be recorded, ledger says %q", stored.Status)
	}
	row := renderedRowFor(t, renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, read, orderID)), orderID)
	if row.Stage != deletedProviderStatus || len(row.Actions) != 0 {
		t.Fatalf("the recorded deletion must render with no contact action, got stage %q actions %v", row.Stage, row.Actions)
	}
}

// TestDeletionAtOrBeforeTheRepairingObservationStaysContradicted is the negative direction:
// evidence the listing already answered cannot undo the repair. The evidence time is taken
// before the request, so it is at or before the observation by construction.
func TestDeletionAtOrBeforeTheRepairingObservationStaysContradicted(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const (
		orderID  = "ord_995_07_before_snapshot"
		address  = "198.51.100.221"
		serverID = int64(6221)
	)
	seedUnonboardedOrder(t, h, orderID, address)
	previousRepair := time.Now().UTC().Add(-time.Hour)
	order, found, err := h.db.GetGigahostOrder(context.Background(), orderID)
	if err != nil || !found {
		t.Fatalf("seed order: found=%t err=%v", found, err)
	}
	order.Status = DeployStatusReady
	order.ServerID = serverID
	order.LiveRepairedAt = &previousRepair
	if err := h.db.UpdateGigahostOrderObservation(context.Background(), order, nil); err != nil {
		t.Fatalf("record the earlier repair: %v", err)
	}
	// Captured before the request is made, so it cannot postdate the listing.
	evidenceBeforeRequest := time.Now().UTC().Add(-time.Second)

	listed := true
	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			if !listed {
				return nil, nil
			}
			return []gigahost.ServerInfo{{ID: serverID, OrderID: orderID, IPv4: address, Status: gigahost.StatusReady}}, nil
		},
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{
				OrderID: orderID, ServerID: serverID,
				Status: deletedProviderStatus, UpdatedAt: evidenceBeforeRequest.Format(time.RFC3339Nano),
			}, nil
		},
	})

	readOrderStatusList(t, h, orderID)
	repaired, found, err := h.db.GetGigahostOrder(context.Background(), orderID)
	if err != nil || !found || repaired.LiveRepairedAt == nil {
		t.Fatalf("the contradiction has no durable evidence: %+v %v", repaired, err)
	}
	if !repaired.LiveRepairedAt.After(evidenceBeforeRequest) {
		t.Fatalf("the repair (%s) must postdate the contradiction it records (%s)",
			repaired.LiveRepairedAt.Format(time.RFC3339Nano), evidenceBeforeRequest.Format(time.RFC3339Nano))
	}
	observedRepair := *repaired.LiveRepairedAt

	listed = false
	for attempt := 1; attempt <= 2; attempt++ {
		read := readOrderStatusList(t, h, orderID)
		stored, found, err := h.db.GetGigahostOrder(context.Background(), orderID)
		if err != nil || !found {
			t.Fatalf("attempt %d: reload the ledger row: found=%t err=%v", attempt, found, err)
		}
		if stored.Status != DeployStatusReady {
			t.Fatalf("attempt %d: a contradiction the listing answered re-deleted the row as %q", attempt, stored.Status)
		}
		if stored.LiveRepairedAt == nil || !stored.LiveRepairedAt.Equal(observedRepair) {
			t.Fatalf("attempt %d: the repair moved on a repeated contradicted answer: %+v", attempt, stored.LiveRepairedAt)
		}
		row := renderedRowFor(t, renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, read, orderID)), orderID)
		if row.Stage != DeployStatusReady {
			t.Fatalf("attempt %d: the repaired row must still render ready, got %q", attempt, row.Stage)
		}
	}
}

// TestRememberContradictedDetailObservationBoundary pins the comparison itself: evidence
// at or before the observation is contradicted, evidence after it is left recordable.
func TestRememberContradictedDetailObservationBoundary(t *testing.T) {
	const orderID = "ord_995_07_boundary"
	// An observation in the past, so a detail exactly at it is admissible evidence rather
	// than a future-dated timestamp.
	observedAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	previous := observedAt.Add(-time.Hour)
	after := observedAt.Add(time.Minute)

	for _, tc := range []struct {
		name     string
		repair   *time.Time
		evidence string
		identity string
		wantNil  bool
		want     time.Time
	}{
		{"at_observation_is_contradicted", &previous, observedAt.Format(time.RFC3339Nano), orderID, false, observedAt},
		{"before_observation_is_contradicted", &previous, observedAt.Add(-time.Second).Format(time.RFC3339Nano), orderID, false, observedAt},
		{"after_observation_is_not_contradicted", &previous, after.Format(time.RFC3339Nano), orderID, false, previous},
		{"after_observation_without_repair_stays_recordable", nil, after.Format(time.RFC3339Nano), orderID, true, time.Time{}},
		{"no_repair_and_answered_evidence_records_it", nil, observedAt.Format(time.RFC3339Nano), orderID, false, observedAt},
		{"unreadable_evidence_cannot_postdate", &previous, "", orderID, false, previous},
		{"another_order_is_not_evidence", &previous, after.Format(time.RFC3339Nano), "ord_somebody_else", false, previous},
	} {
		t.Run(tc.name, func(t *testing.T) {
			order := &GigahostOrderRecord{OrderID: orderID, ServerID: 7}
			if tc.repair != nil {
				repair := *tc.repair
				order.LiveRepairedAt = &repair
			}
			rememberContradictedDetail(order, &gigahost.DeployStatusResponse{
				OrderID: tc.identity, ServerID: 7, Status: deletedProviderStatus, UpdatedAt: tc.evidence,
			}, observedAt)
			if tc.wantNil {
				if order.LiveRepairedAt != nil {
					t.Fatalf("a deletion newer than the observation must stay recordable, repair became %s",
						order.LiveRepairedAt.Format(time.RFC3339Nano))
				}
				return
			}
			if order.LiveRepairedAt == nil || !order.LiveRepairedAt.Equal(tc.want) {
				t.Fatalf("repair = %v, want %s", order.LiveRepairedAt, tc.want.Format(time.RFC3339Nano))
			}
		})
	}
}
