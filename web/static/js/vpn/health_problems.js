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

function vpnRenderActiveProblemsCards(status, context) {
    const ctx = context || {};
    const allRouteList = ctx.allRouteList || [];
    const routeHasPressure = !!ctx.routeHasPressure;

    const ha = (status && status.health_assessment) || {};
    const s = ha.status ? String(ha.status).toUpperCase() : '';
    const actionableProblems = Array.isArray(ha.actionable_problems) ? ha.actionable_problems : [];
    const hasActionableProblems = actionableProblems.length > 0;
    const rawConditions = Array.isArray(ha.conditions) ? ha.conditions : [];
    const hasExplicitConditions = rawConditions.length > 0;

    const qualifyingConditions = [];
    const seenCondKeys = new Set();
    for (let i = 0; i < rawConditions.length; i++) {
        const c = rawConditions[i];
        if (!c) continue;
        const sev = (c && c.severity) ? String(c.severity).toUpperCase() : '';
        const isQualifyingSev = sev === 'DEGRADED' || sev === 'CRITICAL' || sev === 'WARNING' || sev === 'WARN';
        if (!isQualifyingSev) continue;

        const isDuplicateOfActionable = actionableProblems.some(function(p) {
            if (p.message && c.message && p.message.trim() === c.message.trim()) return true;
            if (p.message_key && c.message_key && p.message_key === c.message_key) return true;
            return false;
        });
        if (isDuplicateOfActionable) continue;

        const condKey = (c.message_key || '') + '::' + (c.message || '') + '::' + (c.category || '') + '::' + sev;
        if (seenCondKeys.has(condKey)) continue;
        seenCondKeys.add(condKey);

        qualifyingConditions.push(c);
    }

    let activeProblemsCount = actionableProblems.length + qualifyingConditions.length;
    let affectedUsersCount = 0;
    let affectedConfigsCount = 0;

    if (hasActionableProblems) {
        affectedUsersCount = new Set(actionableProblems.map(function(p) { return p.user_id || p.username; }).filter(Boolean)).size;
        affectedConfigsCount = new Set(actionableProblems.map(function(p) {
            return p.connection_id || (p.user_id ? p.user_id + ':' + (p.connection_name || '') : p.connection_name);
        }).filter(Boolean)).size;
    }

    const summaryHeaderElem = document.getElementById('vpn-fwd-summary-header');
    if (summaryHeaderElem) {
        if (activeProblemsCount > 0) {
            const problemsFmt = _('vpn_fwd_active_problems_count') || '%d active problems';
            const usersFmt = _('vpn_fwd_affected_users_count') || '%d affected users';
            const configsFmt = _('vpn_fwd_affected_configs_count') || '%d client configs';
            const problemsText = problemsFmt.replace('%d', activeProblemsCount);
            const usersText = usersFmt.replace('%d', affectedUsersCount);
            const configsText = configsFmt.replace('%d', affectedConfigsCount);
            summaryHeaderElem.innerHTML = `<span class="badge badge-warn" style="font-size: 0.8rem; padding: 2px 8px;">${problemsText} • ${usersText} • ${configsText}</span>`;
            summaryHeaderElem.style.display = 'block';
        } else {
            summaryHeaderElem.textContent = '';
            summaryHeaderElem.style.display = 'none';
        }
    }

    const isDegradedOrDown = s === 'DEGRADED' || s === 'DOWN' || s === 'CRITICAL';
    const hasActiveProblems = hasActionableProblems || hasExplicitConditions || isDegradedOrDown || routeHasPressure;
    const isHealthy = s === 'HEALTHY' && !hasActiveProblems;

    const problemListElem = document.getElementById('vpn-fwd-problem-list');
    if (problemListElem) {
        if (hasActiveProblems) {
            problemListElem.textContent = '';
            problemListElem.style.display = 'flex';
            problemListElem.style.flexDirection = 'column';
            problemListElem.style.gap = '6px';

            for (let i = 0; i < actionableProblems.length; i++) {
                const p = actionableProblems[i];
                const row = document.createElement('div');
                row.className = 'card problem-card';
                row.style.display = 'flex';
                row.style.alignItems = 'center';
                row.style.gap = '8px';
                row.style.fontSize = '0.825rem';
                row.style.padding = 'var(--space-xs, 6px) var(--space-sm, 10px)';
                row.style.background = 'var(--bg-surface, rgba(0,0,0,0.2))';
                row.style.border = '1px solid var(--border-color)';
                row.style.borderRadius = 'var(--radius-sm, 4px)';

                const { badge: sevBadge, upperSev } = createSeverityBadge(p.severity);
                if (upperSev === 'CRITICAL' || upperSev === 'DOWN') {
                    row.style.borderLeft = '3px solid var(--danger)';
                } else if (upperSev === 'DEGRADED') {
                    row.style.borderLeft = '3px solid var(--warning)';
                } else {
                    row.style.borderLeft = '3px solid var(--primary, #3b82f6)';
                }
                row.appendChild(sevBadge);

                const msgSpan = document.createElement('span');
                msgSpan.style.flex = '1';
                msgSpan.textContent = p.message_key && _(p.message_key) !== p.message_key
                    ? _(p.message_key) : (p.message || '');
                row.appendChild(msgSpan);

                const detailsParts = [];
                if (p.category) {
                    detailsParts.push(p.category);
                }
                const user = p.username || p.user_id;
                if (user) {
                    const userPrefix = (_('vpn_fwd_user_prefix') && _('vpn_fwd_user_prefix') !== 'vpn_fwd_user_prefix') ? _('vpn_fwd_user_prefix') : (_('vpn_fwd_user_prefix') || 'User: ');
                    detailsParts.push(userPrefix + user);
                }
                if (p.connection_name) {
                    const configPrefix = (_('vpn_fwd_config_prefix') && _('vpn_fwd_config_prefix') !== 'vpn_fwd_config_prefix') ? _('vpn_fwd_config_prefix') : (_('vpn_fwd_config_prefix') || 'Config: ');
                    detailsParts.push(configPrefix + p.connection_name);
                }
                if (p.assigned_ip) {
                    const ipPrefix = (_('vpn_fwd_ip_prefix') && _('vpn_fwd_ip_prefix') !== 'vpn_fwd_ip_prefix') ? _('vpn_fwd_ip_prefix') : (_('vpn_fwd_ip_prefix') || 'IP: ');
                    detailsParts.push(ipPrefix + p.assigned_ip);
                }
                if (p.backend_id !== undefined && p.backend_id !== null && p.backend_id !== '') {
                    const backendPrefix = (_('vpn_fwd_backend_prefix') && _('vpn_fwd_backend_prefix') !== 'vpn_fwd_backend_prefix') ? _('vpn_fwd_backend_prefix') : (_('vpn_fwd_backend_prefix') || 'Backend ');
                    detailsParts.push(backendPrefix + p.backend_id);
                }
                if (p.observed_rate) {
                    detailsParts.push(p.observed_rate);
                }

                if (detailsParts.length > 0) {
                    const detailsBadge = document.createElement('span');
                    detailsBadge.className = 'badge text-muted font-mono';
                    detailsBadge.style.fontSize = '0.7rem';
                    detailsBadge.style.padding = '1px 6px';
                    detailsBadge.style.background = 'var(--bg-muted, rgba(255, 255, 255, 0.05))';
                    detailsBadge.style.border = '1px solid var(--border-color)';
                    detailsBadge.style.borderRadius = 'var(--radius-sm, 4px)';
                    detailsBadge.textContent = detailsParts.join(' • ');
                    row.appendChild(detailsBadge);
                }

                if (p.first_observed) {
                    const onsetSpan = document.createElement('span');
                    onsetSpan.className = 'text-muted font-mono';
                    onsetSpan.style.fontSize = '0.75rem';
                    const onsetFmt = _('vpn_fwd_onset') || 'Onset: %s';
                    onsetSpan.textContent = onsetFmt.replace('%s', vpnFormatTime(p.first_observed));
                    row.appendChild(onsetSpan);
                }

                problemListElem.appendChild(row);
            }

            let conditionsToRender = qualifyingConditions;
            if (!hasActionableProblems && qualifyingConditions.length === 0) {
                if (hasExplicitConditions) {
                    conditionsToRender = rawConditions;
                } else if (isDegradedOrDown || routeHasPressure) {
                    conditionsToRender = [
                        {
                            severity: isDegradedOrDown ? s : 'WARNING',
                            message: (ha && ha.summary) ? ha.summary : (s === 'DOWN' ? (_('vpn_forwarder_down') || 'Down') : (_('vpn_forwarder_degraded') || 'Degraded')),
                            category: routeHasPressure ? 'routing' : 'forwarder'
                        }
                    ];
                }
            }

            for (let i = 0; i < conditionsToRender.length; i++) {
                const cond = conditionsToRender[i];
                const row = document.createElement('div');
                row.className = 'card problem-card';
                row.style.display = 'flex';
                row.style.alignItems = 'center';
                row.style.gap = '8px';
                row.style.fontSize = '0.825rem';
                row.style.padding = 'var(--space-xs, 6px) var(--space-sm, 10px)';
                row.style.background = 'var(--bg-surface, rgba(0,0,0,0.2))';
                row.style.border = '1px solid var(--border-color)';
                row.style.borderRadius = 'var(--radius-sm, 4px)';

                const { badge: sevBadge, upperSev } = createSeverityBadge(cond.severity);
                if (upperSev === 'CRITICAL' || upperSev === 'DOWN') {
                    row.style.borderLeft = '3px solid var(--danger)';
                } else if (upperSev === 'DEGRADED') {
                    row.style.borderLeft = '3px solid var(--warning)';
                } else {
                    row.style.borderLeft = '3px solid var(--primary, #3b82f6)';
                }
                row.appendChild(sevBadge);

                const msgSpan = document.createElement('span');
                msgSpan.style.flex = '1';
                msgSpan.textContent = cond.message_key && _(cond.message_key) !== cond.message_key
                    ? _(cond.message_key) : (cond.message || '');
                row.appendChild(msgSpan);

                if (cond.category) {
                    const compBadge = document.createElement('span');
                    compBadge.className = 'badge text-muted font-mono';
                    compBadge.style.fontSize = '0.7rem';
                    compBadge.style.padding = '1px 6px';
                    compBadge.style.background = 'var(--bg-muted, rgba(255, 255, 255, 0.05))';
                    compBadge.style.border = '1px solid var(--border-color)';
                    compBadge.style.borderRadius = 'var(--radius-sm, 4px)';
                    compBadge.textContent = cond.category;
                    row.appendChild(compBadge);
                }

                problemListElem.appendChild(row);
            }
        } else if (isHealthy) {
            // NOMINAL (0 active problems): render reassuring green badge
            problemListElem.textContent = '';
            problemListElem.style.display = 'flex';
            problemListElem.style.flexDirection = 'column';
            problemListElem.style.gap = '6px';

            const nominalBadge = document.createElement('div');
            nominalBadge.className = 'badge badge-success';
            nominalBadge.style.display = 'inline-flex';
            nominalBadge.style.alignItems = 'center';
            nominalBadge.style.gap = '6px';
            nominalBadge.style.padding = 'var(--space-xs, 6px) var(--space-sm, 10px)';
            nominalBadge.style.fontSize = '0.825rem';
            nominalBadge.style.fontWeight = '500';
            nominalBadge.style.borderRadius = 'var(--radius-sm, 4px)';
            nominalBadge.style.width = 'fit-content';

            const psKpi = status.peer_sync;
            let actualPeers = 0;
            let desiredPeers = 0;
            if (psKpi && typeof psKpi === 'object') {
                actualPeers = Number(psKpi.actual_peers !== undefined ? psKpi.actual_peers : (psKpi.synced || 0));
                desiredPeers = Number(psKpi.desired_peers !== undefined ? psKpi.desired_peers : (psKpi.total || actualPeers));
            } else if (status.connected_sessions !== undefined) {
                actualPeers = Number(status.connected_sessions || 0);
                desiredPeers = actualPeers;
            } else if (status.routing_consistency && status.routing_consistency.active_sessions_count !== undefined) {
                actualPeers = Number(status.routing_consistency.active_sessions_count || 0);
                desiredPeers = actualPeers;
            } else if (allRouteList && allRouteList.length > 0) {
                actualPeers = allRouteList.length;
                desiredPeers = allRouteList.length;
            }

            const be = status.backends || {};
            let healthyBackends = 0;
            let totalBackends = 0;
            if (be.total_count !== undefined) {
                totalBackends = Number(be.total_count || 0);
                healthyBackends = Number(be.healthy_count !== undefined ? be.healthy_count : 0);
            } else if (be.total !== undefined) {
                totalBackends = Number(be.total || 0);
                healthyBackends = Number(be.healthy !== undefined ? be.healthy : 0);
            } else if (status.active_tunnels !== undefined) {
                healthyBackends = Number(status.active_tunnels || 0);
                totalBackends = healthyBackends;
            }

            let noProblemsText = _('vpn_fwd_no_active_problems');
            if (!noProblemsText || noProblemsText === 'vpn_fwd_no_active_problems') {
                noProblemsText = 'No active problems detected';
            }

            let peersText = vpnDiagText('vpn_fwd_nominal_peers', {
                actual: actualPeers,
                desired: desiredPeers,
                synced: actualPeers,
                total: desiredPeers
            });
            if (!peersText || peersText === 'vpn_fwd_nominal_peers') {
                peersText = actualPeers + '/' + desiredPeers + ' peers synced';
            }

            let routesText = _('vpn_fwd_nominal_routes');
            if (!routesText || routesText === 'vpn_fwd_nominal_routes') {
                routesText = 'All routes consistent';
            }

            let backendsText = vpnDiagText('vpn_fwd_nominal_backends', {
                healthy: healthyBackends,
                total: totalBackends
            });
            if (!backendsText || backendsText === 'vpn_fwd_nominal_backends') {
                backendsText = healthyBackends + '/' + totalBackends + ' backends healthy';
            }

            nominalBadge.textContent = '✓ ' + noProblemsText + ' • ' + peersText + ' • ' + routesText + ' • ' + backendsText;
            problemListElem.appendChild(nominalBadge);
        } else {
            problemListElem.textContent = '';
            problemListElem.style.display = 'none';
        }
    }

    const currentProblemKeys = new Set();
    if (isDegradedOrDown) {
        currentProblemKeys.add('status:' + s);
    }
    actionableProblems.forEach(function(p) {
        const pMsgKey = p.message_key || deriveStableConditionCode(p.message);
        const pDurableId = p.connection_id || p.session_id || p.user_id || p.assigned_ip || p.peer_key || p.entity_id || extractConditionEntities(p) || '';
        const pBackendId = p.backend_id ? (':' + p.backend_id) : '';
        const k = 'act:' + (p.category || '') + ':' + pMsgKey + ':' + pDurableId + pBackendId + ':' + (p.severity || '');
        currentProblemKeys.add(k);
    });
    qualifyingConditions.forEach(function(c) {
        const cKey = c.message_key || deriveStableConditionCode(c.message);
        const cEntityId = extractConditionEntities(c);
        const k = 'cond:' + (c.category || '') + ':' + cKey + ':' + cEntityId + ':' + (c.severity || '');
        currentProblemKeys.add(k);
    });
    if (routeHasPressure) {
        currentProblemKeys.add('route_pressure');
        allRouteList.forEach(function(r) {
            if (r && (r.has_pressure || (Number(r.queue_full_drops_recent || 0) > 0) || (Number(r.write_errors_recent || 0) > 0) || (Number(r.write_stalls_recent || 0) > 0))) {
                currentProblemKeys.add('route_pressure:' + (r.session_id || r.connection_id || r.assigned_ip || r.peer_key || 'unknown'));
            }
        });
    }
    if (hasActiveProblems && currentProblemKeys.size === 0) {
        currentProblemKeys.add('active_problem_generic');
    }

    const prevKeys = typeof vpnLastActiveProblemKeys !== 'undefined' ? vpnLastActiveProblemKeys : null;
    const prevCount = typeof vpnLastActiveProblemCount !== 'undefined' ? vpnLastActiveProblemCount : 0;

    let shouldAutoExpand = false;
    if (hasActiveProblems) {
        if (!prevKeys || prevKeys.size === 0) {
            shouldAutoExpand = true;
        } else {
            for (const k of currentProblemKeys) {
                if (!prevKeys.has(k)) {
                    shouldAutoExpand = true;
                    break;
                }
            }
            if (activeProblemsCount > prevCount) {
                shouldAutoExpand = true;
            }
        }
    }

    const techDetails = document.getElementById('vpn-fwd-tech-details');
    if (techDetails && shouldAutoExpand) {
        techDetails.open = true;
    }

    vpnLastActiveProblemKeys = currentProblemKeys;
    vpnLastActiveProblemCount = activeProblemsCount;
    if (typeof window !== 'undefined') {
        window.vpnLastActiveProblemKeys = currentProblemKeys;
        window.vpnLastActiveProblemCount = activeProblemsCount;
    }
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

    // Card 1: Data Plane Performance
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
    const dLatPct = document.getElementById('vpn-diag-lat-percentiles');
    if (dLatPct) {
        const fl = status.forward_latency || {};
        dLatPct.textContent = vpnDiagText('vpn_diag_historical_percentiles', {p50:(fl.p50_ms || 0).toFixed(1), p95:(fl.p95_ms || 0).toFixed(1), p99:(fl.p99_ms || 0).toFixed(1)});
    }
    const dLatMax = document.getElementById('vpn-diag-lat-max');
    if (dLatMax) {
        const fl = status.forward_latency || {};
        dLatMax.textContent = vpnDiagText('vpn_diag_historical_ms', {value:fl.max_ms || 0});
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

    // Card 2: Traffic Drops & Loss Diagnostics
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

    // Card 3: Engine & Route Integrity
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

        dEngine.textContent = 'amneziawg-go (' + awgState + ') • VirtualTUN: ' + vtStatus;
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
            dRoutCounts.textContent = (rc.active_sessions_count || 0) + ' ' + sLabel + ' • ' + (rc.active_routes_count || 0) + ' ' + rLabel + ' • ' + (rc.return_owners_count || 0) + ' ' + retLabel + ' (' + vpnDiagText('vpn_diag_mismatch_drops', {count:rc.ownership_mismatch_drops || 0}) + ')';
        }
        if (dRoutAlerts) {
            if (Array.isArray(rc.inconsistency_details) && rc.inconsistency_details.length > 0) {
                dRoutAlerts.textContent = rc.inconsistency_details.join('; ');
                dRoutAlerts.style.display = 'block';
                dRoutAlerts.style.color = routAlertColor;
            } else {
                dRoutAlerts.textContent = '';
                dRoutAlerts.style.display = 'none';
            }
        }
    }

    // Card 4: System & Fleet Resources
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
            row.textContent = parts.join(' • ');
            backendTraffic.appendChild(row);
        }
    }
}

function vpnResetHealthProblems() {
    const summaryHeaderElem = document.getElementById('vpn-fwd-summary-header');
    if (summaryHeaderElem) {
        summaryHeaderElem.textContent = '';
        summaryHeaderElem.style.display = 'none';
    }
    const problemListElem = document.getElementById('vpn-fwd-problem-list');
    if (problemListElem) {
        problemListElem.textContent = '';
        problemListElem.style.display = 'none';
    }
    const techDetails = document.getElementById('vpn-fwd-tech-details');
    if (techDetails) {
        techDetails.open = false;
    }
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
        'vpn-diag-lat-percentiles', 'vpn-diag-lat-max',
        'vpn-diag-queue-occ', 'vpn-diag-queue-peak',
        'vpn-diag-drops-client', 'vpn-diag-drops-return', 'vpn-diag-drops-total', 'vpn-diag-drop-reasons',
        'vpn-diag-engine-status', 'vpn-diag-peers-status', 'vpn-diag-hs-freshness', 'vpn-diag-routing-counts',
        'vpn-diag-res-cpu', 'vpn-diag-res-mem', 'vpn-diag-res-fd'
    ];
    for (let i = 0; i < diagIds.length; i++) {
        const el = document.getElementById(diagIds[i]);
        if (el) {
            el.textContent = '-';
            el.style.color = '';
        }
    }
    const dRoutBadge = document.getElementById('vpn-diag-routing-badge');
    if (dRoutBadge) {
        dRoutBadge.className = 'badge';
        dRoutBadge.textContent = '-';
    }
    const dRoutAlerts = document.getElementById('vpn-diag-routing-alerts');
    if (dRoutAlerts) {
        dRoutAlerts.textContent = '';
        dRoutAlerts.style.display = 'none';
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
    window.createSeverityBadge = createSeverityBadge;
    window.vpnRenderActiveProblemsCards = vpnRenderActiveProblemsCards;
    window.vpnRenderTechDiagnosticCards = vpnRenderTechDiagnosticCards;
    window.vpnResetHealthProblems = vpnResetHealthProblems;
    window.vpnResetTechDiagnosticCards = vpnResetTechDiagnosticCards;
}
