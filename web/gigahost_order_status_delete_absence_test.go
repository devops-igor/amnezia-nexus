package web

// The two ways a recorded deletion could stop being presented as one.
//
// The first is a second request: the stage and its action suppression used to come
// only from the per-order deploy read, so a failing detail request returned a deleted
// deployment to the ordinary treatment - and, because the list renders an older row
// only when it reads as deleted, dropped it from the list entirely. The list response
// now carries the panel's durable absence record, and these tests hold the per-order
// read to being genuinely failed while the row is still DELETED with nothing to click.
//
// The second is a spelling: the backend treats `deleted` and `terminated` as one fact,
// so the client has to as well, while `cancelled` and `failed` stay the distinct
// outcomes they already were.

import "testing"

// TestRecentDeploymentsKeepsARecordedAbsenceAcrossAFailedDetailRead pins the list's own
// absence record as the source of the deleted presentation.
func TestRecentDeploymentsKeepsARecordedAbsenceAcrossAFailedDetailRead(t *testing.T) {
	runGigahostOrderStatusScenario(t, "GIGAHOST_STATUS_LISTED_ABSENCE_OK", `

 // Six orders, newest first, so the recorded deletion is older than the five the list
 // shows by default. Each is a journaled install failure, which is the state that
 // offers a Retry control - so "no action" is measured against a row that would
 // otherwise have one. The step is carried on the ROW, which is where the list response
 // serves it: that column is what distinguishes an install this panel ran from a
 // provider that ended provisioning, and the retry belongs to the former.
 const recent = i => ({order_id:'ord_recent_' + i, status:'failed', step:'installing_protocol', assigned_ip:'198.51.100.' + (10 + i)});
 orders = [recent(1), recent(2), recent(3), recent(4), recent(5),
           {order_id:'ord_gone', status:'failed', step:'installing_protocol', assigned_ip:'198.51.100.9'}];
 // The panel recorded the deletion in the durable record the inventory pass writes,
 // and the list response carries it. Nothing is claimed about the provider here.
 absenceByOrder = {'ord_gone': true};
 observationByOrder = {};
 deployByOrder = {'ord_gone': {status:'failed', step:'installing_protocol', error:'install failed'}};
 intents = []; backends = [];

 // PHASE 1 - the per-order status request fails for every row.
 failList = true;
 await w.loadRecentOrders();
 // The recorded deletion is not asked about at all, so the fixture requests one detail
 // for each of the five rows the panel still holds an open question about.
 assert.deepEqual(calls.filter(c => /\/status$/.test(c.url)).map(c => c.url).length, orders.length - 1,
   'the fixture must actually request a detail per live order, got ' + JSON.stringify(calls.map(c => c.url)));
 assert.deepEqual(calls.map(c => c.url).filter(u => u.indexOf('ord_gone') !== -1 && /\/status$/.test(u)), [],
   'a recorded deletion must not be asked about at the provider');
 const failedRows = Array.from(container().querySelectorAll('.gigahost-order-row'));
 assert.equal(failedRows.length, 6,
   'a recorded deletion older than the five shown must still be listed while the detail read fails, got ' +
   JSON.stringify(failedRows.map(r => r.querySelector('.gigahost-order-status').getAttribute('data-order-id'))));

 const failedGone = failedRows[5];
 const failedCell = failedGone.querySelector('.gigahost-order-status');
 assert.equal(failedCell.getAttribute('data-stage'), 'deleted',
   'a failing detail read must not undo the recorded deletion');
 const failedActions = Array.from(failedGone.querySelectorAll('button:not(.gigahost-order-status-toggle)')).map(b => b.textContent);
 assert.deepEqual(failedActions, [],
   'a deleted deployment must offer no contact action even when the detail read failed, got ' +
   JSON.stringify(failedActions));
 // The negative direction: the rows nobody recorded as absent keep their ordinary
 // treatment, so the assertion above is about the record rather than about failure.
 failedRows.slice(0, 5).forEach(row => {
   const stage = row.querySelector('.gigahost-order-status').getAttribute('data-stage');
   assert.equal(stage, 'failed', 'an unrecorded order must not borrow the deleted stage, got ' + stage);
 });
 assert.deepEqual(
   Array.from(failedRows[0].querySelectorAll('button:not(.gigahost-order-status-toggle)')).map(b => b.textContent),
   ['deploy_retry_btn'], 'an unrecorded failure keeps its retry control');

 // PHASE 2 - the same orders with every detail read succeeding. The treatment must be
 // unchanged, so the correction cannot have moved the positive case.
 failList = false;
 await w.loadRecentOrders();
 const okRows = Array.from(container().querySelectorAll('.gigahost-order-row'));
 assert.equal(okRows.length, 6, 'the recorded deletion must be listed when the detail read succeeds too');
 const okCell = okRows[5].querySelector('.gigahost-order-status');
 assert.equal(okCell.getAttribute('data-stage'), 'deleted');
 assert.deepEqual(
   Array.from(okRows[5].querySelectorAll('button:not(.gigahost-order-status-toggle)')).map(b => b.textContent), [],
   'a deleted deployment offers no contact action when the detail read succeeds either');

 // PHASE 3 - the durable record is corrected (the provider lists the server again).
 // The row returns to its ordinary treatment, which for an order older than the five
 // shown means the list's ordinary five-row window: no row reads deleted, so the
 // presentation follows the record rather than the traversal.
 absenceByOrder = {};
 await w.loadRecentOrders();
 const corrected = Array.from(container().querySelectorAll('.gigahost-order-row'));
 assert.deepEqual(corrected.map(r => r.querySelector('.gigahost-order-status').getAttribute('data-stage')),
   ['failed','failed','failed','failed','failed'],
   'a corrected record must restore the ordinary list, got ' +
   JSON.stringify(corrected.map(r => r.querySelector('.gigahost-order-status').getAttribute('data-stage'))));
`)
}

// TestTerminatedOrdersReachTheDeletedStage pins the client vocabulary against the
// backend's, which already treats both provider spellings as a deletion.
func TestTerminatedOrdersReachTheDeletedStage(t *testing.T) {
	runGigahostOrderStatusScenario(t, "GIGAHOST_STATUS_TERMINATED_OK", `

 // Four rows: the provider's "terminated" answer, the ledger's "terminated" spelling
 // where no provider read was attempted, and the two outcomes that must stay distinct.
 orders = [
   {order_id:'ord_term_provider', status:'ready', assigned_ip:'198.51.100.21'},
   {order_id:'ord_term_ledger', status:'terminated', assigned_ip:'198.51.100.22'},
   {order_id:'ord_cancel', status:'cancelled'},
   // The step rides on the row, which is where the list response serves the panel's own
   // install journal. That column is what makes this a recoverable setup failure rather
   // than a provider-final one, which is the distinction the retry control now follows.
   {order_id:'ord_fail', status:'failed', step:'installing_protocol'}
 ];
 observationByOrder = {
   'ord_term_provider': {outcome:'confirmed', status:'terminated'},
   'ord_term_ledger': {outcome:'not_checked'},
   'ord_cancel': {outcome:'confirmed', status:'cancelled'},
   'ord_fail': {outcome:'confirmed', status:'failed'}
 };
 // The provider-terminated row carries the failed journal that offers a Retry control,
 // and the ledger-terminated row carries an address, which offers Setup Backend - so
 // "no contact action" distinguishes the deleted stage from a row that would otherwise
 // have one. The ledger row has no journal evidence, because the status column is only
 // readable as a provider state when onboarding did not write it.
 deployByOrder = {
   'ord_term_provider': {status:'failed', step:'installing_protocol', error:'install failed'},
   'ord_term_ledger': {},
   'ord_cancel': {},
   'ord_fail': {status:'failed', step:'installing_protocol', error:'install failed'}
 };
 intents = []; backends = [];
 await w.loadRecentOrders();

 const stages = cells().map(c => c.getAttribute('data-stage'));
 assert.deepEqual(stages, ['deleted','deleted','deleted','failed'],
   'both terminal provider spellings and a cancellation are deletions, and a failure stays the distinct outcome it was, got ' +
   JSON.stringify(stages));

 cells().slice(0, 3).forEach((cell, index) => {
   const actions = Array.from(cell.parentNode.querySelectorAll('button:not(.gigahost-order-status-toggle)')).map(b => b.textContent);
   assert.deepEqual(actions, [],
     'a ' + ['provider-terminated','ledger-terminated','cancelled'][index] + ' order must offer no contact action, got ' +
     JSON.stringify(actions));
   const chain = Array.from(cell.querySelectorAll('.gigahost-order-status-stage'))
     .map(s => s.getAttribute('data-stage') + ':' + s.getAttribute('data-state'));
   assert.deepEqual(chain, ['requested:done','deleted:current'],
     'a terminated order must not claim it ever deployed, got ' + JSON.stringify(chain));
   assert.match(flat(cell.querySelector('.gigahost-order-status-details')),
     /gigahost_status_stage_deleted/, 'the row must name the deleted stage');
 });

 // The failure that is not a recorded ending keeps the retry its state allows, so the
 // assertion above is about the ending rather than about every terminal outcome.
 assert.deepEqual(
   Array.from(cells()[3].parentNode.querySelectorAll('button:not(.gigahost-order-status-toggle)')).map(b => b.textContent),
   ['deploy_retry_btn'], 'a failed order keeps its retry control');
`)
}
