// VPN Forwarder Health Problems, Normalization, Disclosures & Diagnostic Cards
// Extracted from web/templates/vpn.html per #496 (Epic #475 Phase 3).

let vpnLastActiveProblemKeys = null;
let vpnLastActiveProblemCount = 0;

function vpnFormatTime(val) {
    if (!val) return '';
    try {
        const d = new Date(val);
        if (!isNaN(d.getTime())) {
            const y = d.getUTCFullYear();
            const m = String(d.getUTCMonth() + 1).padStart(2, '0');
            const day = String(d.getUTCDate()).padStart(2, '0');
            const h = String(d.getUTCHours()).padStart(2, '0');
            const min = String(d.getUTCMinutes()).padStart(2, '0');
            const sec = String(d.getUTCSeconds()).padStart(2, '0');
            return y + '-' + m + '-' + day + ' ' + h + ':' + min + ':' + sec + ' UTC';
        }
        return String(val);
    } catch (_) {
        return String(val);
    }
}

function vpnFormatPeerKey(key) {
    if (!key) return '-';
    if (typeof key !== 'string') return String(key);
    if (key.length <= 12) return key;
    return key.slice(0, 8) + '...' + key.slice(-4);
}

function vpnDiagText(key, values) {
    const parameters = values || {};
    return _(key).replace(/\{([a-z0-9_]+)\}/g, function(match, name) {
        return Object.prototype.hasOwnProperty.call(parameters, name) ? String(parameters[name]) : match;
    });
}

function vpnLossReasonLabels() {
    return {
        backend_device_unattributed: 'vpn_diag_loss_backend_device_unattributed',
        client_backend_device_external: 'vpn_diag_loss_client_backend_device_external',
        client_backend_device_oversized: 'vpn_diag_loss_client_backend_device_oversized',
        client_backend_device_queue_full: 'vpn_diag_loss_client_backend_device_queue_full',
        client_backend_device_shutdown: 'vpn_diag_loss_client_backend_device_shutdown',
        client_backend_queue_full: 'vpn_diag_loss_client_backend_queue_full',
        client_malformed: 'vpn_diag_loss_client_malformed',
        client_mismatch: 'vpn_diag_loss_client_mismatch',
        client_no_healthy_backend: 'vpn_diag_loss_client_no_healthy_backend',
        client_rate_limited: 'vpn_diag_loss_client_rate_limited',
        client_rejected: 'vpn_diag_loss_client_rejected',
        client_unmapped_source: 'vpn_diag_loss_client_unmapped_source',
        client_virtualtun_drops: 'vpn_diag_loss_client_virtualtun_drops',
        return_backend_device_queue_full: 'vpn_diag_loss_return_backend_device_queue_full',
        return_backend_device_shutdown: 'vpn_diag_loss_return_backend_device_shutdown',
        return_injection_errors: 'vpn_diag_loss_return_injection_errors',
        return_malformed: 'vpn_diag_loss_return_malformed',
        return_mismatch: 'vpn_diag_loss_return_mismatch',
        return_packet_too_large: 'vpn_diag_loss_return_packet_too_large',
        return_queue_full: 'vpn_diag_loss_return_queue_full',
        return_unmapped: 'vpn_diag_loss_return_unmapped',
        return_virtualtun_drops: 'vpn_diag_loss_return_virtualtun_drops'
    };
}

function createSeverityBadge(sev) {
    const sevBadge = document.createElement('span');
    sevBadge.style.fontSize = '0.7rem';
    sevBadge.style.padding = '1px 6px';
    sevBadge.style.borderRadius = 'var(--radius-sm, 4px)';
    sevBadge.style.fontWeight = '600';
    const upperSev = String(sev || '').toUpperCase();
    if (upperSev === 'CRITICAL' || upperSev === 'DOWN') {
        sevBadge.className = 'badge badge-danger';
    } else if (upperSev === 'DEGRADED') {
        sevBadge.className = 'badge badge-warn';
    } else {
        sevBadge.className = 'badge badge-info';
    }
    sevBadge.textContent = upperSev === 'CRITICAL' ? _('vpn_forwarder_critical') :
        upperSev === 'DOWN' ? (_('vpn_forwarder_down') || 'Down') :
        upperSev === 'DEGRADED' ? _('vpn_forwarder_degraded') :
        upperSev === 'HEALTHY' ? _('vpn_forwarder_healthy') :
        (!upperSev || upperSev === 'WARN' || upperSev === 'WARNING') ? _('vpn_forwarder_warning') : upperSev;
    return { badge: sevBadge, upperSev: upperSev };
}

function deriveStableConditionCode(msg) {
    return parseConditionMessage(msg).normalizedCode;
}

function parseConditionMessage(msg) {
    if (!msg || typeof msg !== 'string') return { normalizedCode: '', ips: [] };

    // 1. Identify complete IP spans: match full/mixed IPv6 FIRST, then isolated IPv4
    const preservedIps = [];
    const ips = [];

    const mixedIPv6 = '(?:[0-9a-fA-F]{1,4}:){1,6}(?:\\d{1,3}\\.){3}\\d{1,3}|::(?:[0-9a-fA-F]{1,4}:)*(?:\\d{1,3}\\.){3}\\d{1,3}|(?:[0-9a-fA-F]{1,4}:)+:(?:[0-9a-fA-F]{1,4}:)*(?:\\d{1,3}\\.){3}\\d{1,3}';
    const pureIPv6 = '(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:)+(?::[0-9a-fA-F]{1,4})+|(?:[0-9a-fA-F]{1,4}:)+:|::(?:[0-9a-fA-F]{1,4})(?::[0-9a-fA-F]{1,4})*|::';
    const ipv6Pattern = mixedIPv6 + '|' + pureIPv6;
    const ipv6Regex = new RegExp('(?:^|(?<=[^0-9a-fA-F:]))(?:' + ipv6Pattern + ')(?:$|(?=[^0-9a-fA-F:.]|\\.(?!\\d)))', 'g');

    let s = msg.replace(ipv6Regex, function(m) {
        preservedIps.push(m);
        if (!ips.includes(m)) ips.push(m);
        return '__PRESERVED_IP_' + (preservedIps.length - 1) + '__';
    });

    s = s.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, function(m) {
        preservedIps.push(m);
        if (!ips.includes(m)) ips.push(m);
        return '__PRESERVED_IP_' + (preservedIps.length - 1) + '__';
    });

    // 2. Strip volatile cumulative telemetry and incident metadata BEFORE count protection
    // Strip cumulative clauses: e.g. "(10 sync, 0 enqueue cumulative)" or "(... cumulative)"
    s = s.replace(/\(\s*[^)]*cumulative\s*\)/gi, '');
    s = s.replace(/;\s*[^;)]*cumulative\s*/gi, '');
    s = s.replace(/\b\d+\s+sync,\s+\d+\s+enqueue\s+cumulative\b/gi, '');

    // For unresolved peer sync failures, the incident identity is the error message itself;
    // volatile telemetry (last successful reconcile duration/timestamp, recent window activity, cumulative totals)
    // must not alter the stable condition signature.
    if (/\bUnresolved peer sync failure:/i.test(s)) {
        s = s.replace(/(\bUnresolved peer sync failure:\s*[\s\S]*?)(?:\s*\(\s*(?:last successful reconcile|recent activity)[^)]*\))\s*$/gi, '$1');
        s = s.replace(/;\s*(?:recent activity|last successful reconcile)[^;)]*/gi, '');
        s = s.replace(/\brecent activity:\s*\d+\s+sync,\s*\d+\s+enqueue(?:failures)?(?:\s+in\s+the\s+last\s+[^;)]+)?/gi, '');
        s = s.replace(/\blast successful reconcile\s+[^;)]+/gi, '');
    }

    // Strip duration windows ("in the last 30.0s", "for 10s") as volatile data
    s = s.replace(/\b(?:in the last|in last)\s+\d+(?:\.\d+)?\s*(?:hours?|hour|h|minutes?|minute|min|m|seconds?|second|sec|s|milliseconds?|millisecond|ms|microseconds?|microsecond|µs|us|nanoseconds?|nanosecond|ns|d|days?)\b/gi, '');
    s = s.replace(/\bfor\s+\d+(?:\.\d+)?\s*(?:hours?|hour|h|minutes?|minute|min|m|seconds?|second|sec|s|milliseconds?|millisecond|ms|microseconds?|microsecond|µs|us|nanoseconds?|nanosecond|ns|d|days?)\b/gi, '');

    // Protect ratio patterns representing incident scale/identity (e.g. \b\d+\s+of\s+\d+\b)
    const preservedRatios = [];
    s = s.replace(/\b\d+\s+of\s+\d+\b/gi, function(m) {
        preservedRatios.push(m.replace(/\s+/g, ' '));
        return '__PRESERVED_RATIO_' + (preservedRatios.length - 1) + '__';
    });

    // Protect affected entity/population count phrases representing incident scale
    const preservedCounts = [];
    function preserveCountPhrase(m) {
        preservedCounts.push(m.replace(/\s+/g, ' '));
        return '__PRESERVED_COUNT_' + (preservedCounts.length - 1) + '__';
    }

    s = s.replace(/\b\d+\s+desired\s+vs\s+\d+\s+actual(?:\s+peers?)?\b/gi, preserveCountPhrase);
    if (!/\bUnresolved peer sync failure:/i.test(s)) {
        s = s.replace(/\b\d+\s+sync,\s+\d+\s+enqueue(?:\s+failures)?\b/gi, preserveCountPhrase);
    }
    s = s.replace(/\b\d+\s+(?:active\s+)?(?:live\s+)?sessions?(?:\(s\))?(?!\w)/gi, preserveCountPhrase);
    s = s.replace(/\b\d+\s+(?:invalid\s+)?(?:durable\s+)?(?:peer\s+)?rows?(?:\(s\))?(?!\w)/gi, preserveCountPhrase);
    s = s.replace(/\b\d+\s+(?:peers?|sessions?|users?|backends?|configs?|nodes?|rows?|interfaces?)(?:\(s\))?(?!\w)/gi, preserveCountPhrase);

    // 3. Strip volatile timestamps, time clocks, and telemetry metrics ONLY outside protected IP spans
    s = s
        .replace(/\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/gi, '')
        .replace(/(?<!:)\b(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?\b(?!:)/g, '')
        .replace(/\b\d+(?:\.\d+)?\s*(?:drops\/sec|drops\/s|drops\/window|errors\/sec|stalls\/sec|stalls|pps|bps|Kbps|Mbps|Gbps|B\/s|KB\/s|MB\/s)\b/gi, '')
        .replace(/\b(?:\d+(?:\.\d+)?\s*(?:hours?|hour|h|minutes?|minute|min|m|seconds?|second|sec|s|milliseconds?|millisecond|ms|microseconds?|microsecond|µs|us|nanoseconds?|nanosecond|ns|d|days?))+\b/gi, '')
        .replace(/\b\d+(?:\.\d+)?\s*%/g, '')
        .replace(/\(\s*>?\s*\d+(?:\.\d+)?\s*(?:recent|drops|errors|stalls|samples|events|packets)?\s*\)/gi, '')
        .replace(/\b\d+(?:\.\d+)?\s*(?:recent|drops|errors|stalls|events|samples|packets)\b/gi, '')
        .replace(/\b\d+(?:\.\d+)?\b/g, '')
        .replace(/\(\s*>?\s*\)/g, '')
        .replace(/\(\s*\)/g, '')
        .replace(/\s+/g, ' ')
        .trim();

    // 4. Restore protected placeholders for normalized stable condition code
    let normalizedCode = s.replace(/__PRESERVED_IP_(\d+)__/g, function(_, idx) {
        return preservedIps[Number(idx)] || '';
    });
    normalizedCode = normalizedCode.replace(/__PRESERVED_RATIO_(\d+)__/g, function(_, idx) {
        return preservedRatios[Number(idx)] || '';
    });
    normalizedCode = normalizedCode.replace(/__PRESERVED_COUNT_(\d+)__/g, function(_, idx) {
        return preservedCounts[Number(idx)] || '';
    });

    return { normalizedCode: normalizedCode, ips: ips };
}

function extractConditionEntities(item) {
    if (!item) return '';
    const direct = item.assigned_ip || item.peer_key || item.entity_id || item.connection_id || item.session_id || item.user_id || '';
    const parsed = parseConditionMessage(item.message);
    const parts = [];
    if (direct) {
        parts.push(direct);
    }
    const ips = parsed.ips.slice().sort();
    for (let i = 0; i < ips.length; i++) {
        if (ips[i] !== direct && !parts.includes(ips[i])) {
            parts.push(ips[i]);
        }
    }
    return parts.join(';');
}

// vpnIssueRows normalises actionable problems and qualifying conditions into one
// ordered, deduplicated list of rows. Sorting is critical -> degraded -> warning;
// identity reuses the existing condition/actionable keys so a fluctuated counter
// never becomes a "new" problem.
function vpnIssueRows(status) {
    const ha = (status && status.health_assessment) || {};
    const assessment = ha.status ? String(ha.status).toUpperCase() : '';
    const actionableProblems = Array.isArray(ha.actionable_problems) ? ha.actionable_problems : [];
    const rawConditions = Array.isArray(ha.conditions) ? ha.conditions : [];

    const rows = [];
    const seen = new Set();

    function severityRank(sev) {
        const s = String(sev || '').toUpperCase();
        if (s === 'CRITICAL' || s === 'DOWN') return 0;
        if (s === 'DEGRADED') return 1;
        if (s === 'WARNING' || s === 'WARN') return 2;
        return 3;
    }

    function push(row) {
        if (seen.has(row.key)) return;
        seen.add(row.key);
        rows.push(row);
    }

    for (let i = 0; i < actionableProblems.length; i++) {
        const p = actionableProblems[i];
        if (!p) continue;
        const stableMessage = p.message_key || deriveStableConditionCode(p.message);
        const entityId = p.connection_id || p.session_id || p.user_id || p.assigned_ip || p.peer_key || p.entity_id || extractConditionEntities(p) || '';
        const backendId = p.backend_id ? (':' + p.backend_id) : '';
        push({
            key: 'act:' + (p.category || '') + ':' + stableMessage + ':' + entityId + backendId + ':' + (p.severity || ''),
            severity: p.severity,
            title: p.message_key && _(p.message_key) !== p.message_key ? _(p.message_key) : (p.message || ''),
            category: p.category || '',
            user: p.username || p.user_id || '',
            connectionName: p.connection_name || '',
            assignedIP: p.assigned_ip || '',
            sessionId: p.session_id || '',
            connectionId: p.connection_id || '',
            backendId: (p.backend_id !== undefined && p.backend_id !== null && p.backend_id !== '') ? String(p.backend_id) : '',
            observedRate: p.observed_rate || '',
            firstObserved: p.first_observed || ''
        });
    }

    const isDuplicateOfActionable = function(c) {
        return actionableProblems.some(function(p) {
            if (p.message && c.message && String(p.message).trim() === String(c.message).trim()) return true;
            if (p.message_key && c.message_key && p.message_key === c.message_key) return true;
            return false;
        });
    };

    for (let i = 0; i < rawConditions.length; i++) {
        const c = rawConditions[i];
        if (!c) continue;
        const sev = c.severity ? String(c.severity).toUpperCase() : '';
        if (!(sev === 'DEGRADED' || sev === 'CRITICAL' || sev === 'WARNING' || sev === 'WARN')) continue;
        if (isDuplicateOfActionable(c)) continue;
        const stableMessage = c.message_key || deriveStableConditionCode(c.message);
        push({
            key: 'cond:' + (c.category || '') + ':' + stableMessage + ':' + extractConditionEntities(c) + ':' + (c.severity || ''),
            severity: c.severity,
            title: c.message_key && _(c.message_key) !== c.message_key ? _(c.message_key) : (c.message || ''),
            category: c.category || '',
            user: c.username || c.user_id || '',
            connectionName: c.connection_name || '',
            assignedIP: c.assigned_ip || '',
            sessionId: c.session_id || '',
            connectionId: c.connection_id || '',
            backendId: (c.backend_id !== undefined && c.backend_id !== null && c.backend_id !== '') ? String(c.backend_id) : '',
            observedRate: '',
            firstObserved: c.first_observed || ''
        });
    }

    // An assessment with no explicit row still needs one honest row: a degraded,
    // down or critical verdict is itself the problem.
    if (rows.length === 0 && (assessment === 'DEGRADED' || assessment === 'DOWN' || assessment === 'CRITICAL')) {
        push({
            key: 'status:' + assessment,
            severity: assessment,
            title: (ha && ha.summary) ? ha.summary
                : (assessment === 'DOWN' ? (_('vpn_forwarder_down') || 'Down')
                    : assessment === 'CRITICAL' ? _('vpn_forwarder_critical') : _('vpn_forwarder_degraded')),
            category: '', user: '', connectionName: '', assignedIP: '', sessionId: '',
            connectionId: '', backendId: '', observedRate: '', firstObserved: ''
        });
    }

    rows.sort(function(a, b) { return severityRank(a.severity) - severityRank(b.severity); });
    return rows;
}

// vpnIssueEntityLabel renders the known affected entity for one row. Identifiers
// and addresses are isolated with <bdi> in the DOM so a mixed-direction value
// cannot reorder the surrounding sentence.
function vpnIssueEntityLabel(row) {
    const parts = [];
    if (row.user) parts.push(_('vpn_fwd_user_prefix') + row.user);
    if (row.connectionName) parts.push(_('vpn_fwd_config_prefix') + row.connectionName);
    if (row.assignedIP) parts.push(_('vpn_fwd_ip_prefix') + row.assignedIP);
    if (row.backendId) parts.push(_('vpn_fwd_backend_prefix') + row.backendId);
    if (row.sessionId && !row.connectionName) parts.push(vpnDiagText('vpn_issue_session_id', {id:row.sessionId}));
    if (row.observedRate) parts.push(row.observedRate);
    return parts.join(' \u00b7 ');
}

// vpnFindSessionRow returns the session table row for one identifier. It walks the
// tbody's rows rather than relying on a selector engine, so the same lookup works
// in every environment and never depends on CSS.escape for an id.
function vpnFindSessionRow(sessionId) {
    const tbody = document.getElementById('vpn-sessions-tbody');
    if (!tbody || !tbody.children) return null;
    const wanted = String(sessionId);
    for (let i = 0; i < tbody.children.length; i++) {
        const candidate = tbody.children[i];
        if (!candidate || typeof candidate.getAttribute !== 'function') continue;
        if (candidate.getAttribute('data-session-id') === wanted) {
            return candidate;
        }
    }
    return null;
}

// vpnFocusHeading moves the caller's focus to a table heading that already exists
// in the template with tabindex="-1", so it is genuinely focusable.
function vpnFocusHeading(id, explanationKey) {
    const heading = document.getElementById(id);
    if (heading && typeof heading.focus === 'function') heading.focus();
    const summaryEl = document.getElementById('vpn-fwd-headline-summary');
    if (summaryEl && explanationKey) summaryEl.textContent = _(explanationKey);
}

// vpnBackendFocusCell returns the focusable cell for one backend row. Row cells are
// matched by kind, never by element name: a plain <td> always satisfies
// typeof node.focus === 'function', so checking the function alone would claim a
// non-focusable cell can take focus. The search is restricted to the row's own cells
// so a nested control's tabindex cannot stand in for the cell's.
function vpnBackendFocusCell(row) {
    const cells = row.children || [];
    for (let i = 0; i < cells.length; i++) {
        const cell = cells[i];
        if (cell && cell.getAttribute && cell.getAttribute('tabindex') !== null) return cell;
    }
    return null;
}

// vpnFocusFirstFocusable focuses the first candidate that carries an explicit
// tabindex. A plain element satisfies typeof node.focus === 'function' even when
// the browser refuses to focus it, so focusability is read from the attribute that
// actually grants it.
function vpnFocusFirstFocusable(candidates) {
    for (let i = 0; i < candidates.length; i++) {
        const node = candidates[i];
        if (node && typeof node.focus === 'function' && node.getAttribute && node.getAttribute('tabindex') !== null) {
            node.focus();
            return true;
        }
    }
    return false;
}

// vpnFocusSessionIssue reveals one session's drill-down and moves focus to the
// affected session row's action cell. Diagnostics is never touched.
function vpnFocusSessionIssue(row) {
    const wanted = String(row.sessionId || row.connectionId);
    const tr = vpnFindSessionRow(wanted);
    if (!tr) {
        vpnFocusHeading('vpn-troubleshooting-title', 'vpn_issue_entity_missing_session');
        return;
    }
    // Reveal, never toggle: the action means "show me this", so it must not close a
    // fold the operator is already reading.
    if (typeof vpnSetSessionDrilldownOpen === 'function') {
        vpnSetSessionDrilldownOpen(wanted, tr, true);
    }
    const cell = (typeof tr.querySelector === 'function') ? tr.querySelector('[data-action="vpn-toggle-session"]') : null;
    if (!vpnFocusFirstFocusable([cell, tr])) {
        // No focusable target on the row means focus would silently stay put.
        vpnFocusHeading('vpn-troubleshooting-title', null);
    }
}

// vpnFindBackendRowByTunnelId returns the backend table row whose own tunnel id is
// the one the problem reports. It walks the tbody's rows rather than depending on a
// selector engine, the same way the session lookup does.
//
// The row's own tunnel id (data-tunnel-id) is what the diagnostics payload reports
// as backend_id, because that value comes from the session/route backend tunnel id.
// The row's data-server-id is a DIFFERENT id space — it is the server the row's
// enable/delete actions post to — so it is never compared against a problem.
function vpnFindBackendRowByTunnelId(tbody, tunnelId) {
    const rows = (tbody && tbody.children) ? tbody.children : [];
    const wanted = String(tunnelId);
    for (let i = 0; i < rows.length; i++) {
        const candidate = rows[i];
        if (!candidate || typeof candidate.getAttribute !== 'function') continue;
        if (candidate.getAttribute('data-tunnel-id') === wanted) return candidate;
    }
    return null;
}

// vpnFocusBackendIssue moves focus to the affected backend's name cell, or to the
// backend table heading when that backend is no longer listed.
function vpnFocusBackendIssue(row) {
    const tr = vpnFindBackendRowByTunnelId(document.getElementById('vpn-backends-tbody'), row.backendId);
    if (!tr) {
        vpnFocusHeading('vpn-backends-title', 'vpn_issue_entity_missing_backend');
        return;
    }
    const nameCell = vpnBackendFocusCell(tr);
    if (nameCell && vpnFocusFirstFocusable([nameCell])) return;
    vpnFocusHeading('vpn-backends-title', null);
}

// vpnIssueDestinationHeading names the card that owns a problem carrying no entity
// id. Such a problem is a statement about a SURFACE rather than about a row that has
// vanished, and the surface is named by its category. Keying this on an explicit
// category set is what keeps a backend-scoped condition (for example "no healthy
// backends available to route traffic") out of the sessions table while a
// connection, routing or dataplane condition keeps the destination it already had;
// pointing every fallback at one card would only move the error.
const VPN_BACKEND_CATEGORIES = ['backend'];
function vpnIssueDestinationHeading(category) {
    const c = String(category || '').toLowerCase();
    if (VPN_BACKEND_CATEGORIES.indexOf(c) !== -1) return 'vpn-backends-title';
    return 'vpn-troubleshooting-title';
}

// vpnFocusIssueTarget moves focus to the existing detail for a problem WITHOUT
// opening Advanced Diagnostics. The destination must be a node that can actually
// take focus, and the reveal is idempotent: a second Inspect on an already-open
// detail keeps it open instead of toggling it shut.
function vpnFocusIssueTarget(row) {
    if (row.sessionId || row.connectionId) {
        vpnFocusSessionIssue(row);
    } else if (row.backendId) {
        vpnFocusBackendIssue(row);
    } else {
        vpnFocusHeading(vpnIssueDestinationHeading(row.category), null);
    }
}

// vpnIssueSeverityLabel returns the localized severity word for one row.
function vpnIssueSeverityLabel(upperSev) {
    return (upperSev === 'CRITICAL' || upperSev === 'DOWN') ? _('vpn_forwarder_critical')
        : upperSev === 'DEGRADED' ? _('vpn_forwarder_degraded')
        : _('vpn_forwarder_warning');
}

// vpnAnnounceProblems publishes the current problem set into the polite live region.
// Only the headline used to be inside it, so a NEW affected entity at an unchanged
// severity changed visible text with no announcement. This writes severity, title
// and the known entity for every row; identical text is suppressed by vpnAssignText,
// so an unchanged poll stays silent while a genuinely new entity is announced.
function vpnAnnounceProblems(rows) {
    const sink = document.getElementById('vpn-fwd-problem-announcement');
    if (!sink) return;
    if (!rows || rows.length === 0) {
        vpnAssignText(sink, '');
        return;
    }
    const parts = rows.map(function(row) {
        const severity = vpnIssueSeverityLabel(String(row.severity || '').toUpperCase());
        const entity = vpnIssueEntityLabel(row);
        return entity ? severity + ': ' + row.title + ' (' + entity + ')' : severity + ': ' + row.title;
    });
    vpnAssignText(sink, parts.join(' \u00b7 '));
}

// vpnRenderActiveProblemsCards renders the problem rows and returns the number of
// rows. It never changes the Advanced Diagnostics open state: a new problem is
// surfaced here, not by expanding technical telemetry.
function vpnRenderActiveProblemsCards(status, context) {
    const ctx = context || {};
    const problemListElem = document.getElementById('vpn-fwd-problem-list');
    const rows = (status && status.forwarder_available === true) ? vpnIssueRows(status) : [];

    if (!problemListElem) return rows.length;

    if (rows.length === 0) {
        problemListElem.textContent = '';
        problemListElem.hidden = true;
        vpnLastActiveProblemKeys = new Set();
        if (typeof window !== 'undefined') window.vpnLastActiveProblemKeys = vpnLastActiveProblemKeys;
        vpnAnnounceProblems([]);
        return 0;
    }

    problemListElem.textContent = '';
    problemListElem.hidden = false;

    for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        const upperSev = String(row.severity || '').toUpperCase();
        const severity = (upperSev === 'CRITICAL' || upperSev === 'DOWN') ? 'critical'
            : upperSev === 'DEGRADED' ? 'degraded' : 'warning';

        const li = document.createElement('li');
        li.className = 'vpn-issue';
        li.setAttribute('data-severity', severity);
        li.setAttribute('data-issue-key', row.key);

        const copy = document.createElement('div');
        copy.className = 'vpn-issue-copy';

        const severityEl = document.createElement('span');
        severityEl.className = 'vpn-issue-severity';
        const severityIcon = document.createElement('span');
        severityIcon.setAttribute('aria-hidden', 'true');
        severityIcon.textContent = severity === 'critical' ? '\u2297' : '\u26a0';
        severityEl.appendChild(severityIcon);
        const severityLabel = document.createElement('span');
        severityLabel.textContent = vpnIssueSeverityLabel(upperSev);
        severityEl.appendChild(severityLabel);
        copy.appendChild(severityEl);

        const title = document.createElement('h3');
        title.className = 'vpn-issue-title';
        title.textContent = row.title;
        copy.appendChild(title);

        const entityText = vpnIssueEntityLabel(row);
        if (entityText) {
            const entity = document.createElement('p');
            entity.className = 'vpn-issue-entity';
            const bdi = document.createElement('bdi');
            bdi.textContent = entityText;
            entity.appendChild(bdi);
            copy.appendChild(entity);
        }

        // The onset is a separate line so the explanation and the known entity stay
        // readable on their own. vpn_fwd_onset is printf-style, so format it directly.
        if (row.firstObserved) {
            const onset = document.createElement('p');
            onset.className = 'vpn-issue-entity';
            const onsetFmt = _('vpn_fwd_onset') || 'Onset: %s';
            onset.textContent = onsetFmt.replace('%s', vpnFormatTime(row.firstObserved));
            copy.appendChild(onset);
        }
        li.appendChild(copy);

        const action = document.createElement('button');
        action.type = 'button';
        action.className = 'btn btn-secondary btn-sm vpn-issue-action';
        action.textContent = (row.sessionId || row.connectionId) ? _('vpn_issue_inspect_session') : _('vpn_issue_inspect');
        action.setAttribute('data-action', 'vpn-issue-inspect');
        action.setAttribute('data-issue-key', row.key);
        // The handler is also stored on the node so a test harness without a real
        // event dispatcher can invoke exactly the code a click runs.
        const inspectHandler = (function(captured) {
            return function(event) {
                if (event && typeof event.preventDefault === 'function') event.preventDefault();
                vpnFocusIssueTarget(captured);
            };
        })(row);
        action._vpnIssueAction = inspectHandler;
        action.addEventListener('click', inspectHandler);
        li.appendChild(action);

        problemListElem.appendChild(li);
    }

    const keys = new Set(rows.map(function(r) { return r.key; }));
    vpnLastActiveProblemKeys = keys;
    vpnLastActiveProblemCount = rows.length;
    if (typeof window !== 'undefined') {
        window.vpnLastActiveProblemKeys = keys;
        window.vpnLastActiveProblemCount = rows.length;
    }
    vpnAnnounceProblems(rows);
    return rows.length;
}

function vpnRenderTechDiagnosticCards(status, context) {
    const ctx = context || {};
    const cap = Number(ctx.cap || 0);
    const occ = Number(ctx.occ || 0);
    const peak = Number(ctx.peak || 0);
    const dropsQueueFull = Number(ctx.dropsQueueFull || 0);
    const dropsNoRoute = Number(ctx.dropsNoRoute || 0);
    const dropsOversize = Number(ctx.dropsOversize || 0);
    const fmtBps = typeof ctx.fmtBps === 'function' ? ctx.fmtBps : function(b) { return String(b || 0) + ' bps'; };
    const notMeasured = _('vpn_diag_not_measured');

    // Data Plane Performance
    const dThroughput = document.getElementById('vpn-diag-throughput');
    if (dThroughput) {
        const r = status.rates || {};
        dThroughput.textContent = r.available !== true ? _('vpn_diag_traffic_unavailable') :
            'Rx: ' + fmtBps(r.rx_bps || 0) + ' | Tx: ' + fmtBps(r.tx_bps || 0);
    }
    const dEwma5m = document.getElementById('vpn-diag-ewma5m');
    if (dEwma5m) {
        const r = status.rates || {};
        dEwma5m.textContent = r.available !== true ? _('vpn_diag_traffic_unavailable') :
            'Rx: ' + fmtBps(r.rx_bps_avg_5m || 0) + ' | Tx: ' + fmtBps(r.tx_bps_avg_5m || 0);
    }
    const dEwma1h = document.getElementById('vpn-diag-ewma1h');
    if (dEwma1h) {
        const r = status.rates || {};
        dEwma1h.textContent = r.available !== true ? _('vpn_diag_traffic_unavailable') :
            'Rx: ' + fmtBps(r.rx_bps_avg_1h || 0) + ' | Tx: ' + fmtBps(r.tx_bps_avg_1h || 0);
    }

    // Recent forward-write p95. The gate is the SAMPLE COUNT of the recent
    // reservoir plus a finite value: p95_health_samples == 0 means no recent write
    // was observed, so the percentile is not measured and must never print a
    // numeric zero. write_total cannot prove a sample (client_write.go increments
    // it before completion), and the historical global reservoir is deliberately
    // not surfaced here because its sample presence cannot be proven.
    const dLatPct = document.getElementById('vpn-diag-lat-percentiles');
    if (dLatPct) {
        const fl = status.forward_latency || {};
        const samples = Number(fl.p95_health_samples || 0);
        const p95 = Number(fl.p95_health_ms);
        if (samples > 0 && Number.isFinite(p95)) {
            const windowSec = Number(fl.p95_health_window_sec || 0);
            dLatPct.textContent = windowSec > 0
                ? vpnDiagText('vpn_diag_forward_p95_window', {value:p95.toFixed(1), window:vpnFormatHealthWindow(windowSec)})
                : vpnDiagText('vpn_diag_forward_p95_value', {value:p95.toFixed(1)});
            dLatPct.classList.remove('vpn-not-measured');
        } else {
            dLatPct.textContent = notMeasured;
            dLatPct.classList.add('vpn-not-measured');
        }
    }

    const dQueueOcc = document.getElementById('vpn-diag-queue-occ');
    if (dQueueOcc) {
        const qp = status.queue_pressure || {};
        const uPct = qp.utilization_pct !== undefined ? qp.utilization_pct.toFixed(1) : (cap > 0 ? (occ / cap * 100).toFixed(1) : '0.0');
        dQueueOcc.textContent = occ + ' / ' + cap + ' (' + uPct + '%)';
        dQueueOcc.style.color = (qp.utilization_pct >= 80 || (cap > 0 && occ >= cap * 0.8)) ? 'var(--danger)' : '';
    }
    const dQueuePeak = document.getElementById('vpn-diag-queue-peak');
    if (dQueuePeak) {
        const qp = status.queue_pressure || {};
        const hwPct = qp.high_water_pct !== undefined ? qp.high_water_pct.toFixed(1) : (cap > 0 ? (peak / cap * 100).toFixed(1) : '0.0');
        dQueuePeak.textContent = peak + ' (' + hwPct + '%)';
    }

    // Traffic Drops
    const liveHorizon = _('vpn_fwd_horizon_current') || 'Current / Live';
    const resetHorizon = _('vpn_fwd_horizon_since_reset') || 'Since Startup / Reset';
    const dDropsClient = document.getElementById('vpn-diag-drops-client');
    if (dDropsClient) {
        const dc = status.drop_categories || {};
        const rate = (dc.client_drop_rate_pps || 0).toFixed(2);
        const rateText = dc.rates_available !== true ? _('vpn_diag_loss_unavailable') : rate + ' pps';
        dDropsClient.textContent = vpnDiagText('vpn_diag_with_cumulative', {value:rateText, count:dc.client_total_drops || 0});
        dDropsClient.title = liveHorizon + ': ' + rateText + ' | ' + resetHorizon + ': ' + (dc.client_total_drops || 0);
        dDropsClient.style.color = dc.rates_available === true && Number(dc.client_drop_rate_pps || 0) > 0 ? 'var(--danger)' : '';
    }
    const dDropsRet = document.getElementById('vpn-diag-drops-return');
    if (dDropsRet) {
        const dc = status.drop_categories || {};
        const rate = (dc.return_drop_rate_pps || 0).toFixed(2);
        const rateText = dc.rates_available !== true ? _('vpn_diag_loss_unavailable') : rate + ' pps';
        dDropsRet.textContent = vpnDiagText('vpn_diag_with_cumulative', {value:rateText, count:dc.return_total_drops || 0});
        dDropsRet.title = liveHorizon + ': ' + rateText + ' | ' + resetHorizon + ': ' + (dc.return_total_drops || 0);
        dDropsRet.style.color = dc.rates_available === true && Number(dc.return_drop_rate_pps || 0) > 0 ? 'var(--danger)' : '';
    }
    const dDropsTot = document.getElementById('vpn-diag-drops-total');
    if (dDropsTot) {
        const dc = status.drop_categories || {};
        const tot = dc.total_drops !== undefined ? dc.total_drops : (dropsQueueFull + dropsNoRoute + dropsOversize);
        const rate = (dc.total_drop_rate_pps || 0).toFixed(2);
        const rateText = dc.rates_available !== true ? _('vpn_diag_loss_unavailable') : rate + ' pps';
        dDropsTot.textContent = vpnDiagText('vpn_diag_with_cumulative', {value:rateText, count:tot});
        dDropsTot.title = liveHorizon + ': ' + rateText + ' | ' + resetHorizon + ': ' + tot;
        dDropsTot.style.color = dc.rates_available === true && Number(dc.total_drop_rate_pps || 0) > 0 ? 'var(--danger)' : '';
    }

    const reasonTable = document.getElementById('vpn-diag-drop-reasons');
    if (reasonTable) {
        reasonTable.textContent = '';
        const dc = status.drop_categories || {};
        const labels = vpnLossReasonLabels();
        const rates = dc.reason_rates || {};
        const reasons = Object.keys(labels).sort((a, b) =>
            (dc.rates_available === true ? Number(rates[b] || 0) - Number(rates[a] || 0) : 0) ||
            Number(dc[b] || 0) - Number(dc[a] || 0) || a.localeCompare(b));
        let renderedCount = 0;
        for (const reason of reasons) {
            const count = Number(dc[reason] || 0);
            const rateVal = (dc.rates_available === true && Number.isFinite(rates[reason])) ? Number(rates[reason]) : 0;
            if (count <= 0 && rateVal <= 0) {
                continue;
            }
            renderedCount++;
            const row = document.createElement('div');
            const rate = dc.rates_available === true && Number.isFinite(rates[reason]) ?
                Number(rates[reason]).toFixed(2) + ' pps' : _('vpn_diag_loss_unavailable');
            row.textContent = _(labels[reason]) + ': ' +
                vpnDiagText('vpn_diag_with_cumulative', {value:rate, count:count});
            row.style.color = dc.rates_available === true && rateVal > 0 ? 'var(--danger)' : '';
            reasonTable.appendChild(row);
        }
        if (renderedCount === 0) {
            const emptyRow = document.createElement('div');
            emptyRow.className = 'text-muted';
            emptyRow.textContent = dc.rates_available === false ?
                _('vpn_diag_loss_unavailable') :
                (_('vpn_diag_no_active_drops') || 'No active drops');
            reasonTable.appendChild(emptyRow);
        }
    }

    // Engine & Route Integrity
    const dEngine = document.getElementById('vpn-diag-engine-status');
    if (dEngine) {
        const awgState = status.listener_running ? (_('vpn_diag_state_active') || 'active') : (_('vpn_diag_state_stopped') || 'stopped');
        const vt = status.virtual_tun || {};
        const vtUp = vt.upstream_to_nexus || {};
        const vtNexus = vt.nexus_to_upstream || {};
        const dc = status.drop_categories || {};
        const rates = dc.reason_rates || {};
        const vtDropRate = (dc.rates_available === true) ? (Number(rates['client_virtualtun_drops'] || 0) + Number(rates['return_virtualtun_drops'] || 0)) : 0;
        const upCap = Number(vtUp.capacity || 0);
        const nexusCap = Number(vtNexus.capacity || 0);
        const upOcc = Number(vtUp.occupancy || 0);
        const nexusOcc = Number(vtNexus.occupancy || 0);
        const upUtil = upCap > 0 ? upOcc / upCap : 0;
        const nexusUtil = nexusCap > 0 ? nexusOcc / nexusCap : 0;

        let vtStatus = _('vpn_fwd_healthy') || 'Healthy';
        let isVtDegraded = false;
        let isVtWarning = false;

        if (vt.available === false || (upCap === 0 && nexusCap === 0 && upOcc === 0 && nexusOcc === 0)) {
            vtStatus = _('vpn_diag_loss_unavailable') || 'Unavailable';
        } else if (upUtil >= 0.8 || nexusUtil >= 0.8 || vtDropRate >= 10.0) {
            isVtDegraded = true;
            vtStatus = _('vpn_fwd_degraded') || 'Degraded';
        } else if (upUtil >= 0.5 || nexusUtil >= 0.5 || vtDropRate > 0) {
            isVtWarning = true;
            vtStatus = _('vpn_fwd_warning') || 'Warning';
        }

        dEngine.textContent = 'amneziawg-go (' + awgState + ') \u2022 VirtualTUN: ' + vtStatus;
        if (!status.listener_running || isVtDegraded) {
            dEngine.style.color = 'var(--danger)';
        } else if (isVtWarning) {
            dEngine.style.color = 'var(--warning)';
        } else if (vt.available === false || vtStatus === (_('vpn_diag_loss_unavailable') || 'Unavailable')) {
            dEngine.style.color = 'var(--text-muted)';
        } else {
            dEngine.style.color = 'var(--success)';
        }
    }
    const peerSyncUnavailable = _('vpn_diag_peer_sync_unavailable');
    const ps = status.peer_sync;
    const psAvailable = !!ps && typeof ps === 'object';
    const dPeers = document.getElementById('vpn-diag-peers-status');
    if (dPeers) {
        if (psAvailable) {
            dPeers.textContent = (ps.desired_peers || 0) + ' / ' + (ps.actual_peers || 0);
            dPeers.style.color = (ps.desired_peers || 0) === (ps.actual_peers || 0) ? '' : 'var(--warning)';
        } else {
            dPeers.textContent = peerSyncUnavailable;
            dPeers.style.color = 'var(--text-muted)';
        }
    }
    const dHsFresh = document.getElementById('vpn-diag-hs-freshness');
    if (dHsFresh) {
        const hsf = status.handshake_freshness || {};
        dHsFresh.textContent = '<2m: ' + (hsf.under_2m_count || 0) + ' | 2-5m: ' + (hsf.between_2m_5m_count || 0) + ' | >5m: ' + (hsf.over_5m_count || 0) + ' | ' + _('vpn_diag_peer_sync_never') + ': ' + (hsf.never_count || 0);
    }

    // Aggregate recent write stalls. Issue #955 retires the slow-write summary tile
    // but requires its raw value to stay reachable here. stalls_recent is the count
    // over stalls_window_sec; the horizon is printed with it so the number cannot be
    // read as a since-reset total. A window of 0 means the producer reported no
    // horizon, so the count is not measured rather than silently timeless.
    const dStallsRecent = document.getElementById('vpn-diag-write-stalls-recent');
    if (dStallsRecent) {
        const fl = status.forward_latency || {};
        const recentStalls = fl.stalls_recent;
        const windowSec = Number(fl.stalls_window_sec || 0);
        if (typeof recentStalls === 'number' && Number.isFinite(recentStalls) && windowSec > 0) {
            dStallsRecent.textContent = vpnDiagText('vpn_diag_write_stalls_window', {
                count: recentStalls,
                window: vpnFormatHealthWindow(windowSec)
            });
            dStallsRecent.classList.remove('vpn-not-measured');
        } else {
            dStallsRecent.textContent = _('vpn_diag_not_measured');
            dStallsRecent.classList.add('vpn-not-measured');
        }
    }
    const dRoutBadge = document.getElementById('vpn-diag-routing-badge');
    const dRoutCounts = document.getElementById('vpn-diag-routing-counts');
    const dRoutAlerts = document.getElementById('vpn-diag-routing-alerts');
    if (dRoutBadge || dRoutCounts) {
        const rc = status.routing_consistency || {};
        const isConsistent = rc.is_consistent !== undefined ? rc.is_consistent : true;
        let routBadgeClass = 'badge-danger';
        let routAlertColor = 'var(--danger)';
        if (isConsistent) {
            routBadgeClass = 'badge-success';
        } else {
            const rawConds = Array.isArray(status.conditions)
                ? status.conditions
                : ((status.health_assessment && Array.isArray(status.health_assessment.conditions))
                    ? status.health_assessment.conditions
                    : []);
            const routingConds = rawConds.filter(function(c) { return c && c.category === 'routing'; });
            const hasCritOrDegraded = routingConds.some(function(c) {
                return c && (c.severity === 'CRITICAL' || c.severity === 'DEGRADED');
            });
            const isOnlyWarning = routingConds.length > 0 && !hasCritOrDegraded && routingConds.every(function(c) {
                return c && c.severity === 'WARNING';
            });
            if (isOnlyWarning) {
                routBadgeClass = 'badge-warning';
                routAlertColor = 'var(--warning)';
            }
        }
        if (dRoutBadge) {
            dRoutBadge.className = 'badge ' + routBadgeClass;
            dRoutBadge.textContent = isConsistent ? _('vpn_fwd_consistent') : _('vpn_fwd_inconsistent');
        }
        if (dRoutCounts) {
            const sLabel = _('vpn_diag_sessions') || 'sessions';
            const rLabel = _('vpn_diag_routes') || 'routes';
            const retLabel = _('vpn_diag_returns') || 'returns';
            dRoutCounts.textContent = (rc.active_sessions_count || 0) + ' ' + sLabel + ' \u2022 ' + (rc.active_routes_count || 0) + ' ' + rLabel + ' \u2022 ' + (rc.return_owners_count || 0) + ' ' + retLabel + ' (' + vpnDiagText('vpn_diag_mismatch_drops', {count:rc.ownership_mismatch_drops || 0}) + ')';
        }
        if (dRoutAlerts) {
            if (Array.isArray(rc.inconsistency_details) && rc.inconsistency_details.length > 0) {
                dRoutAlerts.textContent = rc.inconsistency_details.join('; ');
                dRoutAlerts.hidden = false;
                dRoutAlerts.style.color = routAlertColor;
            } else {
                dRoutAlerts.textContent = '';
                dRoutAlerts.hidden = true;
            }
        }
    }

    // System & Fleet Resources
    const dResCpu = document.getElementById('vpn-diag-res-cpu');
    if (dResCpu) {
        const rr = status.runtime_resources || {};
        dResCpu.textContent = (rr.cpu_percent || 0).toFixed(1) + '%';
    }
    const dResMem = document.getElementById('vpn-diag-res-mem');
    if (dResMem) {
        const rr = status.runtime_resources || {};
        const allocMB = ((rr.memory_alloc_bytes || 0) / 1048576).toFixed(1);
        const limitMB = ((rr.memory_limit_bytes || 0) / 1048576).toFixed(1);
        const pct = (rr.memory_usage_pct || 0).toFixed(1);
        dResMem.textContent = vpnDiagText('vpn_diag_heap_memory', {value:allocMB}) + ' / ' +
            (rr.memory_limit_available === true ? limitMB + ' MiB (' + pct + '%)' : _('vpn_diag_memory_limit_unavailable'));
    }
    const dResFd = document.getElementById('vpn-diag-res-fd');
    if (dResFd) {
        const rr = status.runtime_resources || {};
        dResFd.textContent = (rr.open_file_desc || 0) + ' / ' + (rr.max_file_desc || 0);
    }

    const backendTraffic = document.getElementById('vpn-diag-be-traffic');
    if (backendTraffic) {
        backendTraffic.textContent = '';
        const beList = (status.backends && status.backends.backends) || [];
        const activeBackends = beList.filter(b => b.enabled !== false && b.routable !== false);
        if (activeBackends.length > 0) {
            const measuredBackends = activeBackends.filter(b => b.traffic_available !== false);
            const totalTraffic = measuredBackends.reduce((sum, b) => {
                const rx = Number(b.rx_bytes_per_sec || 0);
                const tx = Number(b.tx_bytes_per_sec || 0);
                return sum + rx + tx;
            }, 0);
            const parts = activeBackends.map(b => {
                const name = b.server_name || ('Backend ' + (b.id !== undefined ? b.id : ''));
                if (b.traffic_available === false) {
                    return name + ' (' + _('vpn_diag_loss_unavailable') + ')';
                }
                const traffic = Number(b.rx_bytes_per_sec || 0) + Number(b.tx_bytes_per_sec || 0);
                const pct = totalTraffic > 0 ? Math.round((traffic / totalTraffic) * 100) : 0;
                return name + ' (' + pct + '%)';
            });
            const row = document.createElement('div');
            row.textContent = parts.join(' \u2022 ');
            backendTraffic.appendChild(row);
        }
    }
}

// vpnFormatHealthWindow renders a diagnostic window length for the sample horizon.
function vpnFormatHealthWindow(sec) {
    const s = Math.max(0, Number(sec) || 0);
    if (s >= 3600 && s % 3600 === 0) return (s / 3600) + 'h';
    if (s >= 60) return Math.floor(s / 60) + 'm';
    return s + 's';
}

function vpnResetHealthProblems() {
    const problemListElem = document.getElementById('vpn-fwd-problem-list');
    if (problemListElem) {
        problemListElem.textContent = '';
        problemListElem.hidden = true;
    }
    // The announcement sink belongs to the live region, so a failed poll clears it
    // together with the rows it described.
    vpnAnnounceProblems([]);
    // Note: the Advanced Diagnostics open state belongs to the operator and is
    // deliberately NOT reset here, so a failed poll does not close a panel the
    // operator opened.
    vpnLastActiveProblemKeys = null;
    vpnLastActiveProblemCount = 0;
    if (typeof window !== 'undefined') {
        window.vpnLastActiveProblemKeys = null;
        window.vpnLastActiveProblemCount = 0;
    }
}

function vpnResetTechDiagnosticCards() {
    const diagIds = [
        'vpn-diag-throughput', 'vpn-diag-ewma5m', 'vpn-diag-ewma1h',
        'vpn-diag-lat-percentiles',
        'vpn-diag-queue-occ', 'vpn-diag-queue-peak',
        'vpn-diag-drops-client', 'vpn-diag-drops-return', 'vpn-diag-drops-total', 'vpn-diag-drop-reasons',
        'vpn-diag-engine-status', 'vpn-diag-peers-status', 'vpn-diag-hs-freshness', 'vpn-diag-routing-counts',
        'vpn-diag-write-stalls-recent',
        'vpn-diag-res-cpu', 'vpn-diag-res-mem', 'vpn-diag-res-fd',
        'vpn-fwd-counters-since'
    ];
    for (let i = 0; i < diagIds.length; i++) {
        const el = document.getElementById(diagIds[i]);
        if (el) {
            el.textContent = '-';
            el.style.color = '';
        }
    }
    // The recent-percentile row has no sample after a failed poll: it reads as
    // not measured rather than a numeric zero.
    const dLatPct = document.getElementById('vpn-diag-lat-percentiles');
    if (dLatPct) {
        dLatPct.textContent = _('vpn_diag_not_measured');
        dLatPct.classList.add('vpn-not-measured');
    }
    // Same rule for the aggregate recent-stall count: no trustworthy window after a
    // failed poll, so it is not measured rather than a number.
    const dStallsReset = document.getElementById('vpn-diag-write-stalls-recent');
    if (dStallsReset) {
        dStallsReset.textContent = _('vpn_diag_not_measured');
        dStallsReset.classList.add('vpn-not-measured');
    }
    const dRoutBadge = document.getElementById('vpn-diag-routing-badge');
    if (dRoutBadge) {
        dRoutBadge.className = 'badge';
        dRoutBadge.textContent = '-';
    }
    const dRoutAlerts = document.getElementById('vpn-diag-routing-alerts');
    if (dRoutAlerts) {
        dRoutAlerts.textContent = '';
        dRoutAlerts.hidden = true;
    }
    const beTraffic = document.getElementById('vpn-diag-be-traffic');
    if (beTraffic) {
        beTraffic.textContent = '';
        beTraffic.innerHTML = '';
    }
}

if (typeof window !== 'undefined') {
    window.vpnLastActiveProblemKeys = vpnLastActiveProblemKeys;
    window.vpnLastActiveProblemCount = vpnLastActiveProblemCount;
    window.vpnFormatTime = vpnFormatTime;
    window.vpnFormatPeerKey = vpnFormatPeerKey;
    window.vpnDiagText = vpnDiagText;
    window.vpnLossReasonLabels = vpnLossReasonLabels;
    window.parseConditionMessage = parseConditionMessage;
    window.deriveStableConditionCode = deriveStableConditionCode;
    window.extractConditionEntities = extractConditionEntities;
    window.vpnRenderActiveProblemsCards = vpnRenderActiveProblemsCards;
    window.vpnRenderTechDiagnosticCards = vpnRenderTechDiagnosticCards;
    window.vpnIssueRows = vpnIssueRows;
    window.vpnIssueSeverityLabel = vpnIssueSeverityLabel;
    window.vpnAnnounceProblems = vpnAnnounceProblems;
    window.vpnFocusIssueTarget = vpnFocusIssueTarget;
    window.vpnIssueDestinationHeading = vpnIssueDestinationHeading;
    window.vpnFormatHealthWindow = vpnFormatHealthWindow;
    window.vpnResetHealthProblems = vpnResetHealthProblems;
    window.vpnResetTechDiagnosticCards = vpnResetTechDiagnosticCards;
}
