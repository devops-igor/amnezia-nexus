package web

// The polling stop, measured rather than read off the source.
//
// Every order in the list has the same provider history; only its recorded state differs.
// The refresh performs one status request per row it believes the provider can still say
// something about, so the request log is the observation: a retired row must not appear in
// it, on the first tick or on any later one, and no control may be offered for it either.

import "testing"

func TestRetiredOrdersIssueNoStatusRequest(t *testing.T) {
	runGigahostOrderStatusScenario(t, "GIGAHOST_STATUS_RETIRED_NO_POLL_OK", `

 const statusCalls = () => calls
   .filter(c => /\/orders\/[^/]+\/status$/.test(c.url))
   .map(c => decodeURIComponent(c.url.replace('/api/admin/hosting/gigahost/orders/', '').replace('/status', '')));
 const stagesByOrder = () => {
   const stages = {};
   cells().forEach(c => { stages[c.getAttribute('data-order-id')] = c.getAttribute('data-stage'); });
   return stages;
 };

 const row = (id, extra) => Object.assign({order_id:id, status:'ready'}, extra || {});
 orders = [
   row('ord_live_ready'),
   row('ord_live_deploying', {status:'deploying'}),
   row('ord_recorded_absent'),
   row('ord_cancelled', {status:'cancelled'}),
   row('ord_deleted', {status:'deleted'}),
   row('ord_terminated', {status:'terminated'})
 ];
 // The panel's durable absence record for one row, and nothing else.
 absenceByOrder = {'ord_recorded_absent': true};
 observationByOrder = {'ord_live_ready': {outcome:'confirmed', status:'ready'}};
 deployByOrder = {}; intents = []; backends = [];

 await w.loadRecentOrders();

 // DEAD-TAIL: exactly the rows the provider can still be asked about were asked about.
 assert.deepEqual(statusCalls(), ['ord_live_ready', 'ord_live_deploying'],
   'a retired order must not be polled at all, got ' + JSON.stringify(statusCalls()));

 const stages = stagesByOrder();
 ['ord_recorded_absent', 'ord_cancelled', 'ord_deleted', 'ord_terminated'].forEach(id => {
   assert.equal(stages[id], 'deleted', id + ' must render as the deletion it is, got ' + stages[id]);
 });
 assert.equal(stages['ord_live_ready'], 'ready');
 assert.equal(stages['ord_live_deploying'], 'deploying');

 // Not counted or described as awaiting setup, and offering nothing: the row is finished.
 const retired = ['ord_recorded_absent', 'ord_cancelled', 'ord_deleted', 'ord_terminated'];
 Array.from(container().querySelectorAll('.gigahost-order-row')).forEach(row => {
   const id = row.querySelector('.gigahost-order-status').getAttribute('data-order-id');
   if (retired.indexOf(id) === -1) return;
   assert.deepEqual(
     Array.from(row.querySelectorAll('button:not(.gigahost-order-status-toggle)')).map(b => b.textContent), [],
     id + ' must offer no setup, retry or approval control');
   assert.match(flat(row.querySelector('.gigahost-order-status-details')), /gigahost_status_next_action_none/,
     id + ' must advise nothing to do');
 });

 // A second tick is the same answer: the count does not grow for a retired row.
 const before = statusCalls().length;
 await w.loadRecentOrders();
 assert.deepEqual(statusCalls().slice(before), ['ord_live_ready', 'ord_live_deploying'],
   'a later tick must not start polling a retired order, got ' + JSON.stringify(statusCalls()));
`)
}
