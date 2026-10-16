// VPN Historical Telemetry Charts, Sparklines & Window Controls
// Extracted from web/templates/vpn.html per #497 (Epic #475 Phase 3).

let vpnHistoryWindow = '15m';

function vpnGenerateSparklineSVG(data, color, fillOpacity, points) {
    const isMulti = Array.isArray(data) && data.length > 0 && typeof data[0] === 'object' && data[0] !== null && Array.isArray(data[0].data);
    const seriesList = isMulti ? data : [{ data: data || [], color: color, fillOpacity: fillOpacity }];
    const hasAnyData = seriesList.some(function(s) {
        return s && Array.isArray(s.data) && s.data.some(Number.isFinite);
    });
    if (!hasAnyData) {
        return '<svg viewBox="0 0 200 40" width="100%" height="40" style="display:block;"><text x="100" y="24" text-anchor="middle" fill="var(--text-muted, #888)" font-size="10">' + escapeHtml(_('no_data')) + '</text></svg>';
    }
    const width = 200;
    const height = 40;
    const padding = 2;
    let maxVal = 0;
    let maxLen = 0;
    for (let s = 0; s < seriesList.length; s++) {
        const sData = seriesList[s] && seriesList[s].data ? seriesList[s].data : [];
        if (sData.length > maxLen) maxLen = sData.length;
        for (let i = 0; i < sData.length; i++) {
            if (Number.isFinite(sData[i]) && sData[i] > maxVal) maxVal = sData[i];
        }
    }
    if (maxVal <= 0) maxVal = 1;
    const step = (width - padding * 2) / Math.max(maxLen - 1, 1);
    let hasTimestamps = false;
    let minT = Infinity;
    let maxT = -Infinity;
    if (Array.isArray(points) && points.length > 0) {
        for (let i = 0; i < points.length; i++) {
            const pt = points[i];
            const t = (pt && typeof pt.t === 'number' && Number.isFinite(pt.t)) ? pt.t : null;
            if (t !== null) {
                if (t < minT) minT = t;
                if (t > maxT) maxT = t;
            }
        }
        if (minT < Infinity && maxT > minT) {
            hasTimestamps = true;
        }
    }
    let pathsMarkup = '';
    for (let s = 0; s < seriesList.length; s++) {
        const item = seriesList[s];
        const sData = item && item.data ? item.data : [];
        if (!sData.some(Number.isFinite)) continue;
        const sColor = item.color || color || 'var(--primary, #3b82f6)';
        const sFillOpacity = item.fillOpacity !== undefined ? item.fillOpacity : (fillOpacity || 0.15);

        const segments = [];
        let segment = [];
        for (let i = 0; i < sData.length; i++) {
            if (!Number.isFinite(sData[i])) {
                if (segment.length) segments.push(segment);
                segment = [];
                continue;
            }
            let x;
            if (hasTimestamps && points && points[i] && typeof points[i].t === 'number' && Number.isFinite(points[i].t)) {
                x = (padding + (points[i].t - minT) / (maxT - minT) * (width - 2 * padding)).toFixed(1);
            } else {
                x = (padding + i * step).toFixed(1);
            }
            const y = (height - padding - sData[i] / maxVal * (height - padding * 2)).toFixed(1);
            segment.push([x, y]);
        }
        if (segment.length) segments.push(segment);

        let pathD = '';
        let fillD = '';
        let dots = '';
        for (const pts of segments) {
            const line = pts.map(function(p, i) { return (i === 0 ? 'M ' : ' L ') + p[0] + ' ' + p[1]; }).join('');
            pathD += line + ' ';
            fillD += line + ' L ' + pts[pts.length - 1][0] + ' ' + height + ' L ' + pts[0][0] + ' ' + height + ' Z ';
            if (pts.length === 1) {
                dots += '<circle cx="' + pts[0][0] + '" cy="' + pts[0][1] + '" r="1.5" fill="' + sColor + '" />';
            }
        }
        if (sFillOpacity > 0 && fillD.trim()) {
            pathsMarkup += '<path d="' + fillD + '" fill="' + sColor + '" fill-opacity="' + sFillOpacity + '" />';
        }
        if (pathD.trim()) {
            pathsMarkup += '<path d="' + pathD + '" fill="none" stroke="' + sColor + '" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />';
        }
        pathsMarkup += dots;
    }

    const crosshair = '<line class="chart-crosshair" x1="0" y1="0" x2="0" y2="' + height + '" stroke="var(--text-muted, #94a3b8)" stroke-width="1" stroke-dasharray="2,2" style="display:none; pointer-events:none;" />';
    const overlay = '<rect class="chart-overlay" x="0" y="0" width="' + width + '" height="' + height + '" fill="transparent" style="cursor:crosshair; pointer-events:all;" />';
    return '<svg viewBox="0 0 ' + width + ' ' + height + '" width="100%" height="' + height + '" preserveAspectRatio="none" style="display:block; overflow:visible;">' +
        pathsMarkup + crosshair + overlay + '</svg>';
}

function vpnDisposeChartInteractions(clearActiveHover) {
    if (clearActiveHover === true && typeof window !== 'undefined') {
        window._vpnActiveChartHover = null;
    }
    const tip = document.getElementById('vpn-chart-tooltip');
    const hasActiveHover = typeof window !== 'undefined' && !!window._vpnActiveChartHover;
    if (tip && (!hasActiveHover || clearActiveHover === true)) {
        tip.style.display = 'none';
    }
    const crosshairs = (document.querySelectorAll && typeof document.querySelectorAll === 'function')
        ? document.querySelectorAll('.chart-crosshair')
        : [];
    for (let i = 0; i < crosshairs.length; i++) {
        crosshairs[i].style.display = 'none';
    }
    ['vpn-chart-throughput', 'vpn-chart-queue', 'vpn-chart-drops', 'vpn-chart-latency'].forEach(function(id) {
        const el = document.getElementById(id);
        if (el && el._vpnCleanup) {
            el._vpnCleanup();
            el._vpnCleanup = null;
        }
    });
}

function vpnRenderHistoryCharts(series) {
    if (typeof vpnDisposeChartInteractions === 'function') {
        vpnDisposeChartInteractions();
    }
    if (!series || typeof series !== 'object') {
        if (typeof window !== 'undefined') window._vpnActiveChartHover = null;
        const tip = document.getElementById('vpn-chart-tooltip');
        if (tip) tip.style.display = 'none';
        return;
    }
    const w = (typeof vpnHistoryWindow !== 'undefined') ? vpnHistoryWindow : '15m';
    let points = [];
    if (w === '1m') points = series.window_1m || [];
    else if (w === '5m') points = series.window_5m || [];
    else if (w === '1h') points = series.window_1h || [];
    else if (w === '6h') points = series.window_6h || [];
    else if (w === '24h') points = series.window_24h || [];
    else points = series.window_15m || [];

    const tData = points.map(function(p) { return p.traffic_available !== true ? null : (p.rx_bps || 0) + (p.tx_bps || 0); });
    const qData = points.map(function(p) { return Number.isFinite(p.q_pct) ? p.q_pct : null; });
    const dData = points.map(function(p) { return p.drop_rates_available !== true ? null : (p.drop_rate || 0); });
    // Forward-write P95 and backend-probe P95 are independent series.
    // Latency chart renders both series on a shared scale and remains available whenever at least one is measured.
    const fwdLatencyData = points.map(function(p) {
        if (!(Number(p.fwd_p95_samples) > 0)) return null;
        return Number.isFinite(p.fwd_p95_ms) ? p.fwd_p95_ms : null;
    });
    const beLatencyData = points.map(function(p) {
        if (!(Number(p.be_latency_samples) > 0)) return null;
        return Number.isFinite(p.be_p95_ms) ? p.be_p95_ms : null;
    });
    const hasFwd = fwdLatencyData.some(Number.isFinite);
    const hasBe = beLatencyData.some(Number.isFinite);
    const latencySeries = [
        { data: fwdLatencyData, color: 'var(--info, #06b6d4)', fillOpacity: 0.12 },
        { data: beLatencyData, color: '#a855f7', fillOpacity: 0.12 }
    ];

    const chartT = document.getElementById('vpn-chart-throughput');
    if (chartT) chartT.innerHTML = vpnGenerateSparklineSVG(tData, 'var(--primary, #3b82f6)', 0.15, points);
    const chartQ = document.getElementById('vpn-chart-queue');
    if (chartQ) chartQ.innerHTML = vpnGenerateSparklineSVG(qData, 'var(--warning, #f59e0b)', 0.15, points);
    const chartD = document.getElementById('vpn-chart-drops');
    if (chartD) chartD.innerHTML = vpnGenerateSparklineSVG(dData, 'var(--danger, #ef4444)', 0.15, points);
    const chartL = document.getElementById('vpn-chart-latency');
    if (chartL) chartL.innerHTML = vpnGenerateSparklineSVG(latencySeries, 'var(--info, #06b6d4)', 0.15, points);

    function computeCurrentPeak(data) {
        let current = null;
        if (data && data.length > 0) {
            const latest = data[data.length - 1];
            if (Number.isFinite(latest)) {
                current = latest;
            }
        }
        let peak = null;
        if (data) {
            for (let i = 0; i < data.length; i++) {
                if (Number.isFinite(data[i])) {
                    if (peak === null || data[i] > peak) {
                        peak = data[i];
                    }
                }
            }
        }
        return { current: current, peak: peak };
    }

    function vpnFmtThroughput(bps) {
        if (!Number.isFinite(bps)) return '—';
        const Bps = bps / 8;
        if (Bps >= 1048576) {
            return (Bps / 1048576).toFixed(1) + ' ' + (_('vpn_unit_mbps') || 'MB/s');
        }
        if (Bps >= 1024) {
            return (Bps / 1024).toFixed(1) + ' ' + (_('vpn_unit_kbps') || 'KB/s');
        }
        if (Bps > 0) {
            const unit = (_('vpn_unit_bps') && _('vpn_unit_bps') !== 'vpn_unit_bps') ? _('vpn_unit_bps') : 'B/s';
            return (Bps >= 1 ? Math.round(Bps) : Bps.toFixed(1)) + ' ' + unit;
        }
        return '0.0 ' + (_('vpn_unit_mbps') || 'MB/s');
    }

    function vpnFmtDrops(drops) {
        if (!Number.isFinite(drops)) return '—';
        const d = Number(drops);
        const str = (d % 1 === 0) ? d.toFixed(0) : d.toFixed(1);
        return str + ' ' + (_('vpn_unit_dps') || 'drops/s');
    }

    function vpnFmtQueue(q) {
        if (q === null || typeof q === 'undefined' || !Number.isFinite(q)) return '—';
        const rounded = Math.round(q * 10) / 10;
        const unit = (_('vpn_unit_pct') && _('vpn_unit_pct') !== 'vpn_unit_pct') ? _('vpn_unit_pct') : '%';
        return (rounded % 1 === 0 ? rounded.toFixed(0) : rounded.toFixed(1)) + unit;
    }

    function vpnFmtLatency(ms) {
        if (!Number.isFinite(ms)) return '—';
        const num = Number(ms);
        const str = (num % 1 === 0) ? num.toFixed(0) : num.toFixed(1);
        return str + ' ' + (_('vpn_unit_ms') || 'ms');
    }

    function renderBadges(badgeId, current, peak, formatFn) {
        const el = document.getElementById(badgeId);
        if (!el) return;
        const curStr = Number.isFinite(current) ? formatFn(current) : '—';
        const peakStr = Number.isFinite(peak) ? formatFn(peak) : '—';
        const curLabel = _('vpn_chart_current') || 'Current';
        const peakLabel = _('vpn_chart_peak') || 'Peak';
        el.textContent = curLabel + ': ' + curStr + ' | ' + peakLabel + ': ' + peakStr;
    }

    const tStats = computeCurrentPeak(tData);
    renderBadges('vpn-chart-throughput-badges', tStats.current, tStats.peak, vpnFmtThroughput);
    const dStats = computeCurrentPeak(dData);
    renderBadges('vpn-chart-drops-badges', dStats.current, dStats.peak, vpnFmtDrops);
    const qStats = computeCurrentPeak(qData);
    renderBadges('vpn-chart-queue-badges', qStats.current, qStats.peak, vpnFmtQueue);
    const fwdStats = computeCurrentPeak(fwdLatencyData);
    const beStats = computeCurrentPeak(beLatencyData);
    const elL = document.getElementById('vpn-chart-latency-badges');
    if (elL) {
        const curLabel = _('vpn_chart_current') || 'Current';
        const peakLabel = _('vpn_chart_peak') || 'Peak';
        const writeLabel = _('vpn_chart_write') || 'Write';
        const probeLabel = _('vpn_chart_probe') || 'Probe';
        const writeSuffix = _('vpn_diag_write_suffix') || ' (write)';
        const probeSuffix = _('vpn_diag_probe_suffix') || ' (probe)';
        const hasFwdWin = Number.isFinite(fwdStats.peak);
        const hasBeWin = Number.isFinite(beStats.peak);
        const fwdCurStr = Number.isFinite(fwdStats.current) ? vpnFmtLatency(fwdStats.current) : '—';
        const beCurStr = Number.isFinite(beStats.current) ? vpnFmtLatency(beStats.current) : '—';
        const writeDot = '<span class="chart-legend-dot" style="display:inline-block;width:7px;height:7px;border-radius:50%;background-color:var(--info, #06b6d4);margin-right:4px;vertical-align:middle;"></span>';
        const probeDot = '<span class="chart-legend-dot" style="display:inline-block;width:7px;height:7px;border-radius:50%;background-color:#a855f7;margin-right:4px;vertical-align:middle;"></span>';

        if (hasFwdWin && hasBeWin) {
            const peakVal = Math.max(fwdStats.peak, beStats.peak);
            const peakStr = Number.isFinite(peakVal) ? vpnFmtLatency(peakVal) : '—';
            const peakSuffix = fwdStats.peak >= beStats.peak ? writeSuffix : probeSuffix;
            elL.innerHTML = writeDot + escapeHtml(writeLabel) + ': ' + escapeHtml(fwdCurStr) + ' | ' + probeDot + escapeHtml(probeLabel) + ': ' + escapeHtml(beCurStr) + ' | ' + escapeHtml(peakLabel) + ': ' + escapeHtml(peakStr) + escapeHtml(peakSuffix);
        } else if (hasBeWin) {
            const peakStr = Number.isFinite(beStats.peak) ? vpnFmtLatency(beStats.peak) : '—';
            const curPart = Number.isFinite(beStats.current) ? (beCurStr + probeSuffix) : '—';
            elL.innerHTML = probeDot + escapeHtml(curLabel) + ': ' + escapeHtml(curPart) + ' | ' + escapeHtml(peakLabel) + ': ' + escapeHtml(peakStr) + escapeHtml(probeSuffix);
        } else if (hasFwdWin) {
            const peakStr = Number.isFinite(fwdStats.peak) ? vpnFmtLatency(fwdStats.peak) : '—';
            elL.innerHTML = writeDot + escapeHtml(curLabel) + ': ' + escapeHtml(fwdCurStr) + ' | ' + escapeHtml(peakLabel) + ': ' + escapeHtml(peakStr);
        } else {
            elL.textContent = curLabel + ': — | ' + peakLabel + ': —';
        }
    }

    function vpnFormatTime(t) {
        if (!t && t !== 0) return '--:--:--';
        let d;
        if (t > 1e11) {
            d = new Date(t);
        } else if (t > 1e8) {
            d = new Date(t * 1000);
        } else {
            const s = Math.floor(Math.abs(t) % 86400);
            const hrs = String(Math.floor(s / 3600)).padStart(2, '0');
            const mins = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
            const secs = String(s % 60).padStart(2, '0');
            return hrs + ':' + mins + ':' + secs;
        }
        const hrs = String(d.getHours()).padStart(2, '0');
        const mins = String(d.getMinutes()).padStart(2, '0');
        const secs = String(d.getSeconds()).padStart(2, '0');
        return hrs + ':' + mins + ':' + secs;
    }

    function renderTimeAxis(axisId) {
        const axisEl = document.getElementById(axisId);
        if (!axisEl) return;
        if (!points || points.length === 0) {
            axisEl.innerHTML = '<span>--:--:--</span><span>--:--:--</span>';
            return;
        }
        const startT = points[0] ? points[0].t : null;
        const endT = points[points.length - 1] ? points[points.length - 1].t : null;
        axisEl.innerHTML = '<span>' + escapeHtml(vpnFormatTime(startT)) + '</span><span>' + escapeHtml(vpnFormatTime(endT)) + '</span>';
    }

    renderTimeAxis('vpn-chart-throughput-axis');
    renderTimeAxis('vpn-chart-drops-axis');
    renderTimeAxis('vpn-chart-queue-axis');
    renderTimeAxis('vpn-chart-latency-axis');

    function attachInteraction(chartId, data, formatTooltipFn) {
        const container = document.getElementById(chartId);
        if (!container) return;

        if (!points || !points.length) return;
        const overlay = container.querySelector ? container.querySelector('.chart-overlay') : null;
        if (!overlay || typeof overlay.addEventListener !== 'function') return;

        const crosshair = container.querySelector ? container.querySelector('.chart-crosshair') : null;
        const tooltip = document.getElementById('vpn-chart-tooltip');

        let hasTimestamps = false;
        let minT = Infinity;
        let maxT = -Infinity;
        for (let i = 0; i < points.length; i++) {
            const pt = points[i];
            const t = (pt && typeof pt.t === 'number' && Number.isFinite(pt.t)) ? pt.t : null;
            if (t !== null) {
                if (t < minT) minT = t;
                if (t > maxT) maxT = t;
            }
        }
        if (minT < Infinity && maxT > minT) {
            hasTimestamps = true;
        }

        const onMouseMove = function(e) {
            if (typeof window !== 'undefined') {
                window._vpnActiveChartHover = {
                    chartId: chartId,
                    clientX: e.clientX,
                    clientY: e.clientY,
                    pageX: (typeof e.pageX === 'number') ? e.pageX : e.clientX,
                    pageY: (typeof e.pageY === 'number') ? e.pageY : e.clientY
                };
            }
            const rect = container.getBoundingClientRect ? container.getBoundingClientRect() : null;
            if (!rect || !rect.width) return;
            const mouseX = Math.max(0, Math.min(rect.width, e.clientX - rect.left));
            const width = 200;
            const padding = 2;
            const svgX = (mouseX / rect.width) * width;
            let idx = 0;
            if (hasTimestamps) {
                const plotFrac = Math.max(0, Math.min(1, (svgX - padding) / (width - padding * 2)));
                const targetT = minT + plotFrac * (maxT - minT);
                let bestDist = Infinity;
                for (let i = 0; i < points.length; i++) {
                    const pt = points[i];
                    const t = (pt && typeof pt.t === 'number' && Number.isFinite(pt.t)) ? pt.t : null;
                    if (t !== null) {
                        const dist = Math.abs(t - targetT);
                        if (dist < bestDist) {
                            bestDist = dist;
                            idx = i;
                        }
                    }
                }
            } else {
                const plotFrac = Math.max(0, Math.min(1, (svgX - padding) / (width - padding * 2)));
                idx = Math.min(points.length - 1, Math.max(0, Math.round(plotFrac * (points.length - 1))));
            }
            const pt = points[idx];
            const val = (data && idx < data.length) ? data[idx] : null;

            if (crosshair && typeof crosshair.setAttribute === 'function') {
                let crosshairX;
                if (hasTimestamps && pt && typeof pt.t === 'number' && Number.isFinite(pt.t)) {
                    crosshairX = (padding + (pt.t - minT) / (maxT - minT) * (width - 2 * padding)).toFixed(1);
                } else {
                    const step = (width - padding * 2) / Math.max(points.length - 1, 1);
                    crosshairX = (padding + idx * step).toFixed(1);
                }
                crosshair.setAttribute('x1', crosshairX);
                crosshair.setAttribute('x2', crosshairX);
                crosshair.style.display = 'block';
            }

            if (tooltip) {
                const timeStr = vpnFormatTime(pt ? pt.t : null);
                tooltip.innerHTML = formatTooltipFn(timeStr, val, pt, idx);
                tooltip.style.display = 'block';

                const tooltipWidth = tooltip.offsetWidth || 140;
                let left = (e.pageX || 0) + 12;
                if (typeof window !== 'undefined' && window.innerWidth && left + tooltipWidth > window.innerWidth - 10) {
                    left = (e.pageX || 0) - tooltipWidth - 12;
                }
                const top = Math.max(10, (e.pageY || 0) - 35);
                tooltip.style.left = left + 'px';
                tooltip.style.top = top + 'px';
            }
        };

        const onMouseLeave = function() {
            if (typeof window !== 'undefined') {
                window._vpnActiveChartHover = null;
            }
            if (crosshair) crosshair.style.display = 'none';
            if (tooltip) tooltip.style.display = 'none';
        };

        overlay._vpnMouseMove = onMouseMove;
        overlay._vpnMouseLeave = onMouseLeave;
        overlay.addEventListener('mousemove', onMouseMove);
        overlay.addEventListener('mouseleave', onMouseLeave);

        container._vpnCleanup = function() {
            overlay.removeEventListener('mousemove', onMouseMove);
            overlay.removeEventListener('mouseleave', onMouseLeave);
            overlay._vpnMouseMove = null;
            overlay._vpnMouseLeave = null;
            if (crosshair) crosshair.style.display = 'none';
        };
    }

    attachInteraction('vpn-chart-throughput', tData, function(timeStr, val, pt) {
        let html = '<div style="font-weight:600;margin-bottom:2px;">' + escapeHtml(timeStr) + '</div>';
        html += '<div>' + escapeHtml(_('vpn_fwd_kpi_throughput')) + ': <strong>' + escapeHtml(vpnFmtThroughput(val)) + '</strong></div>';
        if (pt && pt.traffic_available === true) {
            const rx = Number.isFinite(pt.rx_bps) ? vpnFmtThroughput(pt.rx_bps) : '—';
            const tx = Number.isFinite(pt.tx_bps) ? vpnFmtThroughput(pt.tx_bps) : '—';
            html += '<div style="font-size:0.7rem;color:var(--text-muted,#94a3b8);margin-top:2px;">RX: ' + escapeHtml(rx) + ' | TX: ' + escapeHtml(tx) + '</div>';
        }
        return html;
    });

    attachInteraction('vpn-chart-drops', dData, function(timeStr, val, pt) {
        let html = '<div style="font-weight:600;margin-bottom:2px;">' + escapeHtml(timeStr) + '</div>';
        html += '<div>' + escapeHtml(_('vpn_diag_drop_rate')) + ': <strong>' + escapeHtml(vpnFmtDrops(val)) + '</strong></div>';
        if (pt && pt.drop_rates_available === true && pt.drop_reason_rates) {
            const lossLabels = vpnLossReasonLabels();
            const active = [];
            for (const [k, rate] of Object.entries(pt.drop_reason_rates)) {
                if (Number.isFinite(rate) && rate > 0) {
                    const lbl = lossLabels[k] ? _(lossLabels[k]) : k.replace(/_/g, ' ');
                    active.push(escapeHtml(lbl) + ': ' + escapeHtml(vpnFmtDrops(rate)));
                }
            }
            if (active.length > 0) {
                html += '<div style="font-size:0.7rem;color:var(--text-muted,#94a3b8);margin-top:2px;">' + active.join('<br>') + '</div>';
            }
        }
        return html;
    });

    attachInteraction('vpn-chart-queue', qData, function(timeStr, val, pt) {
        let html = '<div style="font-weight:600;margin-bottom:2px;">' + escapeHtml(timeStr) + '</div>';
        html += '<div>' + escapeHtml(_('vpn_diag_queue_utilization')) + ': <strong>' + escapeHtml(vpnFmtQueue(val)) + '</strong></div>';
        return html;
    });

    attachInteraction('vpn-chart-latency', fwdLatencyData, function(timeStr, val, pt) {
        let html = '<div style="font-weight:600;margin-bottom:2px;">' + escapeHtml(timeStr) + '</div>';
        const fwdValid = pt && Number(pt.fwd_p95_samples) > 0 && Number.isFinite(pt.fwd_p95_ms);
        const beValid = pt && Number(pt.be_latency_samples) > 0 && Number.isFinite(pt.be_p95_ms);
        if (hasFwd) {
            const fwdStr = fwdValid ? vpnFmtLatency(pt.fwd_p95_ms) : '—';
            html += '<div>' + escapeHtml(_('vpn_diag_forward_p95')) + ': <strong>' + escapeHtml(fwdStr) + '</strong></div>';
            if (hasBe) {
                const beStr = beValid ? vpnFmtLatency(pt.be_p95_ms) : '—';
                html += '<div style="font-size:0.7rem;color:var(--text-muted,#94a3b8);margin-top:2px;">' + escapeHtml(_('vpn_diag_backend_probe_p95')) + ': ' + escapeHtml(beStr) + '</div>';
            }
        } else if (hasBe) {
            const beStr = beValid ? vpnFmtLatency(pt.be_p95_ms) : '—';
            html += '<div>' + escapeHtml(_('vpn_diag_backend_probe_p95')) + ': <strong>' + escapeHtml(beStr) + '</strong></div>';
        } else {
            html += '<div>' + escapeHtml(_('vpn_diag_latency_p95')) + ': <strong>—</strong></div>';
        }
        return html;
    });

    function renderSeries(id, entries) {
        const element = document.getElementById(id);
        if (!element) return;
        element.textContent = '';
        if (entries.length === 0) {
            element.textContent = _('no_data') + ' (' + w + ')';
            return;
        }
        for (const entry of entries) {
            const label = document.createElement('div');
            label.textContent = entry.label + ' (' + w + ')';
            label.className = 'text-muted text-sm';
            const graph = document.createElement('div');
            graph.innerHTML = vpnGenerateSparklineSVG(entry.values, entry.color || 'var(--primary, #3b82f6)', 0.15, points);
            element.appendChild(label);
            element.appendChild(graph);
        }
    }
    const lossLabels = vpnLossReasonLabels();
    const allReasons = Array.from(new Set(points.flatMap(p => Object.keys(p.drop_reason_rates || {})))).sort();
    const reasons = allReasons.filter(key => {
        return points.some(p => p && p.drop_rates_available === true && p.drop_reason_rates && Number.isFinite(p.drop_reason_rates[key]) && p.drop_reason_rates[key] > 0);
    });
    renderSeries('vpn-chart-reasons', reasons.map(key => ({
        label:(lossLabels[key] ? _(lossLabels[key]) : key.replace(/_/g,' ')) + ' (drops/s)',
        values:points.map(p => p.drop_rates_available !== true || !p.drop_reason_rates || !Number.isFinite(p.drop_reason_rates[key]) ? null : p.drop_reason_rates[key]),
        color:'var(--danger, #ef4444)'
    })));
    // The stored fleet context is capped; the renderer also caps churn
    // across one window, keeping a large retired fleet from expanding the page.
    const ids = Array.from(new Set(points.flatMap(p => (p.backends || []).map(b => b.id)))).sort((a,b) => a-b);
    const backendsContainer = document.getElementById('vpn-chart-backends');
    let selectEl = document.getElementById('vpn-history-backend-select');
    let seriesEl = document.getElementById('vpn-chart-backend-series');

    if (backendsContainer) {
        const hasSelect = backendsContainer.children && Array.prototype.indexOf.call(backendsContainer.children, selectEl) !== -1;
        if (!selectEl || !hasSelect) {
            if (!selectEl) {
                selectEl = document.createElement('select');
                selectEl.id = 'vpn-history-backend-select';
                selectEl.className = 'form-select form-select-sm';
                selectEl.style.maxWidth = '260px';
                selectEl.style.marginBottom = 'var(--space-sm)';
            }
            backendsContainer.appendChild(selectEl);
        }
        const hasSeries = backendsContainer.children && Array.prototype.indexOf.call(backendsContainer.children, seriesEl) !== -1;
        if (!seriesEl || !hasSeries) {
            if (!seriesEl) {
                seriesEl = document.createElement('div');
                seriesEl.id = 'vpn-chart-backend-series';
            }
            backendsContainer.appendChild(seriesEl);
        }

        if (ids.length === 0) {
            selectEl.style.display = 'none';
            selectEl.innerHTML = '';
            seriesEl.textContent = _('no_data') + ' (' + w + ')';
        } else {
            selectEl.style.display = 'block';
            const boundedIds = ids.slice(0, 128);
            const prevSelected = selectEl.value ? Number(selectEl.value) : null;
            const selectedId = (prevSelected !== null && boundedIds.includes(prevSelected)) ? prevSelected : boundedIds[0];

            selectEl.innerHTML = '';
            for (const id of boundedIds) {
                const opt = document.createElement('option');
                opt.value = String(id);
                opt.textContent = vpnDiagText('vpn_diag_backend_option', {id: id});
                if (id === selectedId) {
                    opt.selected = true;
                }
                selectEl.appendChild(opt);
            }
            selectEl.value = String(selectedId);

            function renderSelectedBackend(targetId) {
                const backendEntries = [];
                for (const [key, label, availability] of [
                    ['rx_bps', 'RX (bps)', 'traffic_available'],
                    ['tx_bps', 'TX (bps)', 'traffic_available'],
                    ['rx_pps', _('vpn_diag_rx_packets_rate'), 'traffic_available'],
                    ['tx_pps', _('vpn_diag_tx_packets_rate'), 'traffic_available'],
                    ['probe_latency_ms', _('vpn_diag_probe_latency'), 'probe_available']
                ]) {
                    backendEntries.push({
                        label: vpnDiagText('vpn_diag_backend_series', {id: targetId, label: label}),
                        values: points.map(function(p) {
                            const b = (p.backends || []).find(function(item) { return item.id === targetId; });
                            return (!b || !b[availability] || !Number.isFinite(b[key])) ? null : b[key];
                        })
                    });
                }
                renderSeries('vpn-chart-backend-series', backendEntries);
            }

            renderSelectedBackend(selectedId);

            selectEl.onchange = function() {
                const chosenId = Number(selectEl.value);
                renderSelectedBackend(chosenId);
            };
        }
    }
    const fleetNote = document.getElementById('vpn-history-fleet-note');
    if (fleetNote) {
        const omitted = points.reduce((max,p) => Math.max(max,Number(p.backends_omitted || 0)),0);
        fleetNote.textContent = omitted || ids.length > 128 ? vpnDiagText('vpn_diag_fleet_limit', {count:Math.max(omitted,ids.length-128)}) : '';
    }

    if (typeof window !== 'undefined' && window._vpnActiveChartHover) {
        const activeHover = window._vpnActiveChartHover;
        const activeContainer = document.getElementById(activeHover.chartId);
        const activeOverlay = activeContainer ? activeContainer.querySelector('.chart-overlay') : null;
        if (activeOverlay && typeof activeOverlay._vpnMouseMove === 'function' && points && points.length > 0) {
            activeOverlay._vpnMouseMove({
                clientX: activeHover.clientX,
                clientY: activeHover.clientY,
                pageX: (typeof activeHover.pageX === 'number') ? activeHover.pageX : activeHover.clientX,
                pageY: (typeof activeHover.pageY === 'number') ? activeHover.pageY : activeHover.clientY
            });
        } else {
            window._vpnActiveChartHover = null;
            const tip = document.getElementById('vpn-chart-tooltip');
            if (tip) tip.style.display = 'none';
        }
    }
}

function vpnSetHistoryWindow(w) {
    if (typeof vpnDisposeChartInteractions === 'function') {
        vpnDisposeChartInteractions(true);
    }
    vpnHistoryWindow = w;
    const toggles = document.getElementById('vpn-history-window-toggles');
    if (toggles) {
        const btns = toggles.querySelectorAll('button');
        for (let i = 0; i < btns.length; i++) {
            if (btns[i].textContent.trim() === w) {
                btns[i].className = 'btn btn-sm btn-primary active';
            } else {
                btns[i].className = 'btn btn-sm btn-secondary';
            }
        }
    }
    if (vpnLastStatus && vpnLastStatus.forwarder_available === true && vpnLastStatus.historical_series) {
        vpnRenderHistoryCharts(vpnLastStatus.historical_series);
    }
}

if (typeof window !== 'undefined') {
    window.vpnGenerateSparklineSVG = vpnGenerateSparklineSVG;
    window.vpnDisposeChartInteractions = vpnDisposeChartInteractions;
    window.vpnRenderHistoryCharts = vpnRenderHistoryCharts;
    window.vpnSetHistoryWindow = vpnSetHistoryWindow;
}
