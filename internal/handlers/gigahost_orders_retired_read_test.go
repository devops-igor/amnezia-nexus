package handlers

// A list read whose observation write is retired still answers with the panel's durable
// absence record.
//
// Two Settings views can overlap slow provider reads: the per-view single flight does not
// coordinate separate HTTP requests, so a newer list request can commit its own repair
// while an older read is still awaiting the provider. The existing fence correctly refuses
// the older write, but the reload that replaces the retired row has to carry the identity
// the existence question is asked about - the panel server the order registered. A row that
// loses it is reported as not recorded absent, so the row returns to Ready with the setup
// actions the deleted state suppresses, and when it is older than the five-row window it
// disappears from the list altogether.
//
// These tests drive the real handler through that exact overlap: the provider callback the
// list handler is waiting on performs the newer request's write first, so the fence, the
// reread and the absence query all run on the retired path. The first phase has every
// per-order detail request failing, which is the sequence that lost the ending; the controls
// are the same retired read with its details succeeding, and the plain list read after the
// winning write has settled.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// retiredObservationFixture is one Recent Deployments surface: six orders, two of them
// with a ledger-only registration whose panel server the reconciliation has recorded as
// gone, and a provider read the test can interleave a newer request with.
type retiredObservationFixture struct {
	h          *Handlers
	ctx        context.Context
	headID     string
	tailID     string
	orderIDs   []string
	identities map[string]gigahost.DeployStatusResponse
	retire     bool
	detailRead int
}

// newRetiredObservationFixture seeds the rows the list reads. Seeding is oldest first and
// the list answers newest first, so one recorded deletion heads the list and the other is
// older than the five rows the view shows by default - the two positions in which the lost
// identity is visible as two different defects.
func newRetiredObservationFixture(t *testing.T) *retiredObservationFixture {
	t.Helper()
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 27, 11, 0, 0, 0, time.UTC)

	f := &retiredObservationFixture{
		h:          h,
		ctx:        ctx,
		headID:     "ord_986_retired_head",
		tailID:     "ord_986_retired_tail",
		identities: map[string]gigahost.DeployStatusResponse{},
	}

	rows := []struct {
		orderID string
		address string
	}{
		{f.tailID, "198.51.100.62"},
		{"ord_986_r1", "198.51.100.11"},
		{"ord_986_r2", "198.51.100.12"},
		{"ord_986_r3", "198.51.100.13"},
		{"ord_986_r4", "198.51.100.14"},
		{f.headID, "198.51.100.61"},
	}
	for _, row := range rows {
		if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
			OrderID: row.orderID, Status: DeployStatusDeploying, AssignedIP: row.address,
			CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("seed order %s: %v", row.orderID, err)
		}
		f.orderIDs = append(f.orderIDs, row.orderID)
	}
	f.orderIDs = []string{f.headID, "ord_986_r4", "ord_986_r3", "ord_986_r2", "ord_986_r1", f.tailID}

	// The two registered deployments: a server row the panel created, mirrored onto the
	// ledger by the onboarding journal, with no saved approval - which is what makes the
	// ledger the only place the identity can come from.
	for _, marked := range []struct {
		orderID    string
		address    string
		providerID int64
	}{
		{f.tailID, "198.51.100.62", 6105},
		{f.headID, "198.51.100.61", 6104},
	} {
		serverID := createPresentationServer(t, h, models.Server{
			Name:      "Gigahost-" + marked.orderID,
			Host:      marked.address,
			Protocols: map[string]any{"provider": "gigahost", "provider_server_id": marked.providerID},
		})
		if err := h.updateDeployOrderStatus(ctx, marked.orderID, DeployStatusDeploying, DeployStatusDeploying,
			"", marked.providerID, serverID, marked.address); err != nil {
			t.Fatalf("journal %s: %v", marked.orderID, err)
		}
		markServerProviderAbsent(t, h, serverID)
		f.identities[marked.orderID] = gigahost.DeployStatusResponse{
			OrderID: marked.orderID, ServerID: marked.providerID, AssignedIP: marked.address,
		}
	}

	// The provider's inventory no longer lists either registered server: that complete
	// omission is what the reconciliation recorded absence from.
	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) { return nil, nil },
		getDeployStatusFn: func(_ context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
			f.detailRead++
			answer := gigahost.DeployStatusResponse{OrderID: orderID, Status: gigahost.StatusReady}
			if identity, ok := f.identities[orderID]; ok {
				answer.ServerID, answer.AssignedIP = identity.ServerID, identity.AssignedIP
			}
			if f.retire {
				// The newer list request commits its own repair here, while this request
				// is still awaiting the provider. Its write must survive, and this read's
				// later write must be refused by the same fence.
				f.commitNewerRepair(t, orderID)
			}
			return &answer, nil
		},
	})
	return f
}

// commitNewerRepair records what the newer list request commits while an older read is
// awaiting the provider. It is the row the retired read reloads, so a control can also
// start from it directly instead of racing two requests.
func (f *retiredObservationFixture) commitNewerRepair(t *testing.T, orderID string) {
	t.Helper()
	winner := &models.GigahostOrder{OrderID: orderID, Status: gigahost.StatusReady}
	if identity, ok := f.identities[orderID]; ok {
		winner.ServerID, winner.AssignedIP = identity.ServerID, identity.AssignedIP
	}
	repair := time.Now().UTC()
	winner.LiveRepairedAt = &repair
	if err := f.h.db.UpdateGigahostOrderObservation(f.ctx, winner, nil); err != nil {
		t.Fatalf("commit the newer repair for %s: %v", orderID, err)
	}
}

// list reads the order list through the production handler, optionally with one detail body
// per row. Without them every per-order status request fails, which is the sequence that
// returned a recorded deletion to the ordinary treatment.
func (f *retiredObservationFixture) list(t *testing.T, withDetails bool) gigahostOrderStatusResponses {
	t.Helper()
	responses := gigahostOrderStatusRead(t, f.h, "")
	if !withDetails {
		return responses
	}
	responses.Details = make(map[string]string, len(f.orderIDs))
	for _, id := range f.orderIDs {
		responses.Details[id] = readGigahostOrderStatusDetail(t, f.h, id)
	}
	return responses
}

// absentOrdersOf reads the list response's durable absence record. A missing key fails the
// test rather than reading as "nothing was recorded", because the key is exactly the fact
// under test.
func absentOrdersOf(t *testing.T, body string) map[string]bool {
	t.Helper()
	var parsed struct {
		Orders []map[string]any `json:"orders"`
		Absent map[string]bool  `json:"provider_absent_orders"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("the orders response is not JSON: %v", err)
	}
	if parsed.Absent == nil {
		t.Fatalf("the list response carries no absence record at all: %s", body)
	}
	return parsed.Absent
}

// observationsOf reads the list response's per-order provider observations.
func observationsOf(t *testing.T, body string) map[string]map[string]any {
	t.Helper()
	var parsed struct {
		Observations map[string]map[string]any `json:"provider_observations"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("the orders response is not JSON: %v", err)
	}
	if parsed.Observations == nil {
		t.Fatalf("the list response carries no provider observations: %s", body)
	}
	return parsed.Observations
}

// assertRetiredPath proves the read really was retired rather than passing for want of an
// attempt. Two durable facts say so, and neither can hold if this read's observation was
// accepted: the newer repair is still stored (an accepted write would clear it, because it
// carries no repair of its own), and the row's observation is reported unavailable because
// the commit was refused - the provider answered, so nothing else can produce that outcome.
func (f *retiredObservationFixture) assertRetiredPath(t *testing.T, ordersBody string) {
	t.Helper()
	if f.detailRead != len(f.orderIDs) {
		t.Fatalf("the fixture must reach the provider once per row, got %d detail reads", f.detailRead)
	}
	observations := observationsOf(t, ordersBody)
	for _, id := range []string{f.headID, f.tailID} {
		stored, found, err := f.h.db.GetGigahostOrder(f.ctx, id)
		if err != nil || !found || stored == nil {
			t.Fatalf("read back %s: found=%v err=%v", id, found, err)
		}
		if stored.LiveRepairedAt == nil {
			t.Fatalf("the fixture did not retire this read's observation for %s: the fence accepted it and cleared the newer repair", id)
		}
		if outcome := observations[id]["outcome"]; outcome != gigahostObservationUnavailable {
			t.Fatalf("the row %s must report that its observation could not be committed, got %v", id, outcome)
		}
	}
}

// assertBothRecordedDeletionsPresent is the rendering claim: both marked orders are listed,
// read DELETED and offer no control whose only effect would be to contact a gone server.
func (f *retiredObservationFixture) assertBothRecordedDeletionsPresent(t *testing.T, responses gigahostOrderStatusResponses) {
	t.Helper()
	rendered := renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, responses, ""))
	if len(rendered.Rows) != len(f.orderIDs) {
		t.Fatalf("both recorded deletions must still be listed, got %d of %d rows: %+v",
			len(rendered.Rows), len(f.orderIDs), rendered.Rows)
	}
	for _, position := range []struct {
		index int
		id    string
	}{
		{0, f.headID},
		{len(f.orderIDs) - 1, f.tailID},
	} {
		row := rendered.Rows[position.index]
		if row.OrderID != position.id {
			t.Fatalf("row %d must be %s, got %+v", position.index, position.id, rendered.Rows)
		}
		if row.Stage != "deleted" {
			t.Fatalf("a recorded deletion at row %d must read DELETED, got stage %q: %+v", position.index, row.Stage, row)
		}
		if len(row.Actions) != 0 {
			t.Fatalf("a deleted deployment at row %d must offer no contact action, got %v", position.index, row.Actions)
		}
		if !strings.Contains(row.Identity, "#"+position.id) {
			t.Fatalf("the deleted row at %d lost its order identity: %q", position.index, row.Identity)
		}
	}
	// The negative direction: the rows nobody recorded absent keep the ordinary treatment,
	// so the assertions above are about the record rather than about the rows failing.
	for _, row := range rendered.Rows[1 : len(f.orderIDs)-1] {
		if row.Stage == "deleted" {
			t.Fatalf("an order nobody recorded absent must not borrow the deleted stage: %+v", row)
		}
	}
	if len(rendered.Rows[1].Actions) == 0 {
		t.Fatalf("an unrecorded deployment must keep the controls a deletion removes, got %+v", rendered.Rows[1])
	}
}

// TestRetiredOrderObservationKeepsTheRecordedDeletion is the defect itself: the read whose
// observation the fence refused must answer the durable absence record it reloaded with.
func TestRetiredOrderObservationKeepsTheRecordedDeletion(t *testing.T) {
	f := newRetiredObservationFixture(t)
	f.retire = true

	responses := f.list(t, false)
	f.assertRetiredPath(t, responses.Orders)

	absent := absentOrdersOf(t, responses.Orders)
	if len(absent) != 2 || !absent[f.headID] || !absent[f.tailID] {
		t.Fatalf("a retired read must still answer the durable absence record for both registered orders, got %v in %s",
			absent, responses.Orders)
	}
	f.assertBothRecordedDeletionsPresent(t, responses)
}

// TestOrderListKeepsRecordedDeletionsAfterANewerRepair is the winning read: the newer
// request has already committed its repair for every row, which is exactly the state the
// retired read reloads into. An ordinary list read with the same failing detail requests
// must still answer both endings, so the assertion above measures the reread rather than
// the absence of an attempt.
func TestOrderListKeepsRecordedDeletionsAfterANewerRepair(t *testing.T) {
	f := newRetiredObservationFixture(t)
	for _, id := range f.orderIDs {
		f.commitNewerRepair(t, id)
	}

	responses := f.list(t, false)
	absent := absentOrdersOf(t, responses.Orders)
	if len(absent) != 2 || !absent[f.headID] || !absent[f.tailID] {
		t.Fatalf("the settled read must keep both absence marks, got %v in %s", absent, responses.Orders)
	}
	f.assertBothRecordedDeletionsPresent(t, responses)
}

// TestRetiredOrderObservationKeepsTheRecordedDeletionWithDetails is the control for the same
// retired read with its per-order detail requests succeeding: the detail channel already
// carried this fact, so the treatment must be the one it always had.
func TestRetiredOrderObservationKeepsTheRecordedDeletionWithDetails(t *testing.T) {
	f := newRetiredObservationFixture(t)
	f.retire = true

	responses := f.list(t, true)
	f.assertRetiredPath(t, responses.Orders)
	f.assertBothRecordedDeletionsPresent(t, responses)

	// The detail bodies are the ones the handler produced after the retirement, so the
	// merged row really carries the durable fact rather than a fixture-supplied mark.
	for _, id := range []string{f.headID, f.tailID} {
		body, ok := responses.Details[id]
		if !ok {
			t.Fatalf("the fixture must supply a detail body for %s", id)
		}
		if !strings.Contains(body, `"provider_absent":true`) {
			t.Fatalf("the detail read for %s must report the recorded absence: %s", id, body)
		}
	}
}
