/**
 * Amnezia Nexus — Telemetry & Live Polling Engine
 * Smart polling with visibility awareness and exponential error backoff,
 * pure SVG sparkline generator, and network bandwidth/latency formatters.
 */
(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        const Telemetry = factory();
        root.NexusTelemetry = Telemetry;
        root.Telemetry = Telemetry; // Primary global export
    }
}(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    /* ===== Formatters ===== */

    /**
     * Format network transfer speed (bytes per second)
     * e.g. 14857600 -> "14.2 MB/s", 839680 -> "820.0 KB/s", 0 -> "0 B/s"
     */
    function formatSpeed(bytesPerSec) {
        if (bytesPerSec === null || bytesPerSec === undefined || isNaN(bytesPerSec)) {
            return '0 B/s';
        }
        const num = Math.max(0, Number(bytesPerSec));
        if (num === 0) return '0 B/s';

        const units = ['B/s', 'KB/s', 'MB/s', 'GB/s', 'TB/s'];
        const k = 1024;
        const i = Math.min(Math.floor(Math.log(num) / Math.log(k)), units.length - 1);
        const val = num / Math.pow(k, i);

        // Format decimal places
        if (i === 0) {
            return Math.round(val) + ' ' + units[i];
        }
        return (val >= 100 ? val.toFixed(0) : val.toFixed(1)) + ' ' + units[i];
    }

    /**
     * Format latency in milliseconds
     * e.g. 18.4 -> "18 ms", 0.4 -> "< 1 ms", null -> "—"
     */
    function formatLatency(ms) {
        if (ms === null || ms === undefined || isNaN(ms)) {
            return '—';
        }
        const num = Number(ms);
        if (num < 0) return '—';
        if (num < 1) return '< 1 ms';
        return Math.round(num) + ' ms';
    }

    /**
     * Format raw byte count into human-readable representation
     * e.g. 1073741824 -> "1.00 GB"
     */
    function formatBytes(bytes) {
        if (bytes === null || bytes === undefined || isNaN(bytes)) {
            return '0 B';
        }
        const num = Math.max(0, Number(bytes));
        if (num === 0) return '0 B';

        const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
        const k = 1024;
        const i = Math.min(Math.floor(Math.log(num) / Math.log(k)), units.length - 1);
        const val = num / Math.pow(k, i);

        if (i === 0) return Math.round(val) + ' B';
        return (val >= 100 ? val.toFixed(0) : val.toFixed(2)) + ' ' + units[i];
    }

    /* ===== Polling Manager ===== */

    /**
     * Registry of all active polling streams
     * streamId -> StreamState
     */
    const activeStreams = new Map();
    let visibilityListenerAttached = false;
    let uniqueIdCounter = 0;

    /**
     * Handle browser tab visibility changes
     */
    function handleVisibilityChange() {
        const isHidden = typeof document !== 'undefined' && document.visibilityState === 'hidden';

        activeStreams.forEach((stream, streamId) => {
            if (isHidden) {
                // Tab hidden: pause timers to save battery and network
                if (stream.timerId) {
                    clearTimeout(stream.timerId);
                    stream.timerId = null;
                }
                stream.pausedByVisibility = true;
            } else {
                // Tab restored: immediately trigger an update and resume normal polling
                if (stream.pausedByVisibility) {
                    stream.pausedByVisibility = false;
                    if (!stream.manuallyPaused) {
                        // Immediate poll upon refocus
                        executePoll(streamId, true);
                    }
                }
            }
        });
    }

    /**
     * Ensure visibility listener is wired up
     */
    function ensureVisibilityListener() {
        if (!visibilityListenerAttached && typeof document !== 'undefined' && document.addEventListener) {
            document.addEventListener('visibilitychange', handleVisibilityChange);
            visibilityListenerAttached = true;
        }
    }

    /**
     * Execute a single poll tick for a stream
     */
    async function executePoll(streamId, isImmediate = false) {
        const stream = activeStreams.get(streamId);
        if (!stream) return;

        // Skip if tab hidden or manually paused
        if (stream.pausedByVisibility || stream.manuallyPaused) return;

        // Skip if already in flight (prevent overlapping slow requests)
        if (stream.inFlight) return;

        stream.inFlight = true;

        try {
            const result = await Promise.resolve(stream.fetcherFn());

            // Check if stream wasn't removed while in flight
            if (!activeStreams.has(streamId)) return;

            // Success: reset error backoff
            stream.consecutiveErrors = 0;
            stream.currentInterval = stream.baseInterval;

            if (typeof stream.options.onSuccess === 'function') {
                stream.options.onSuccess(result);
            }
        } catch (err) {
            if (!activeStreams.has(streamId)) return;

            stream.consecutiveErrors += 1;
            // Exponential backoff: base -> base*2 -> base*4 up to maxBackoff (default 60s)
            const multiplier = Math.pow(stream.options.backoffMultiplier || 2, Math.min(stream.consecutiveErrors, 6));
            stream.currentInterval = Math.min(stream.options.maxBackoffMs || 60000, stream.baseInterval * multiplier);

            if (typeof stream.options.onError === 'function') {
                stream.options.onError(err, stream.currentInterval);
            }
        } finally {
            stream.inFlight = false;

            // Reschedule next tick if still active and not paused
            if (activeStreams.has(streamId) && !stream.manuallyPaused && !stream.pausedByVisibility) {
                if (stream.timerId) clearTimeout(stream.timerId);
                stream.timerId = setTimeout(() => {
                    executePoll(streamId);
                }, stream.currentInterval);
            }
        }
    }

    /**
     * Start or update a live polling stream
     * @param {string} streamId Unique identifier for this polling task
     * @param {Function} fetcherFn Async or sync function that performs the poll
     * @param {number} [intervalMs=5000] Polling interval in ms
     * @param {Object} [options]
     */
    function poll(streamId, fetcherFn, intervalMs = 5000, options = {}) {
        if (!streamId || typeof fetcherFn !== 'function') {
            throw new Error('Telemetry.poll requires a valid streamId and fetcherFn.');
        }

        ensureVisibilityListener();

        // Stop existing stream if any
        stop(streamId);

        const baseInterval = Math.max(500, parseInt(intervalMs, 10) || 5000);
        const streamState = {
            id: streamId,
            fetcherFn: fetcherFn,
            baseInterval: baseInterval,
            currentInterval: baseInterval,
            consecutiveErrors: 0,
            timerId: null,
            inFlight: false,
            manuallyPaused: false,
            pausedByVisibility: typeof document !== 'undefined' && document.visibilityState === 'hidden',
            options: Object.assign({
                immediate: true,
                maxBackoffMs: 60000,
                backoffMultiplier: 2,
                onError: null,
                onSuccess: null
            }, options)
        };

        activeStreams.set(streamId, streamState);

        if (!streamState.pausedByVisibility) {
            if (streamState.options.immediate) {
                executePoll(streamId, true);
            } else {
                streamState.timerId = setTimeout(() => executePoll(streamId), baseInterval);
            }
        }

        return streamState;
    }

    /**
     * Pause a polling stream
     */
    function pause(streamId) {
        const stream = activeStreams.get(streamId);
        if (!stream) return false;

        stream.manuallyPaused = true;
        if (stream.timerId) {
            clearTimeout(stream.timerId);
            stream.timerId = null;
        }
        return true;
    }

    /**
     * Resume a paused polling stream
     */
    function resume(streamId, immediate = false) {
        const stream = activeStreams.get(streamId);
        if (!stream) return false;

        stream.manuallyPaused = false;
        if (!stream.pausedByVisibility) {
            if (immediate) {
                executePoll(streamId, true);
            } else {
                if (stream.timerId) clearTimeout(stream.timerId);
                stream.timerId = setTimeout(() => executePoll(streamId), stream.currentInterval);
            }
        }
        return true;
    }

    /**
     * Stop and unregister a polling stream
     */
    function stop(streamId) {
        const stream = activeStreams.get(streamId);
        if (!stream) return false;

        if (stream.timerId) {
            clearTimeout(stream.timerId);
            stream.timerId = null;
        }
        activeStreams.delete(streamId);
        return true;
    }

    /**
     * Manually trigger an immediate poll for a stream
     */
    function trigger(streamId) {
        return executePoll(streamId, true);
    }

    /**
     * Return list of active stream IDs
     */
    function getActiveStreams() {
        return Array.from(activeStreams.keys());
    }

    /**
     * Pause all active streams
     */
    function pauseAll() {
        activeStreams.forEach((_, id) => pause(id));
    }

    /**
     * Resume all paused streams
     */
    function resumeAll(immediate = false) {
        activeStreams.forEach((_, id) => resume(id, immediate));
    }

    /**
     * Stop all active streams
     */
    function stopAll() {
        activeStreams.forEach((_, id) => stop(id));
    }

    /* ===== Pure SVG Sparkline Generator ===== */

    /**
     * Color threshold helper for latency / ping mode
     */
    function getLatencyColor(ms) {
        if (ms === null || ms === undefined || isNaN(ms)) return 'var(--text-muted, #94a3b8)';
        if (ms < 50) return 'var(--success, #10b981)';
        if (ms < 150) return 'var(--warning, #f59e0b)';
        return 'var(--danger, #f43f5e)';
    }

    /**
     * Build smooth cubic bezier curve SVG path from array of points
     */
    function buildSmoothPath(coords) {
        if (coords.length === 0) return '';
        if (coords.length === 1) return `M ${coords[0].x} ${coords[0].y}`;
        if (coords.length === 2) return `M ${coords[0].x} ${coords[0].y} L ${coords[1].x} ${coords[1].y}`;

        let d = `M ${coords[0].x.toFixed(1)} ${coords[0].y.toFixed(1)}`;

        for (let i = 0; i < coords.length - 1; i++) {
            const p0 = coords[i === 0 ? 0 : i - 1];
            const p1 = coords[i];
            const p2 = coords[i + 1];
            const p3 = coords[i + 2] || p2;

            // Catmull-Rom to Cubic Bezier conversion
            const cp1x = p1.x + (p2.x - p0.x) / 6;
            const cp1y = p1.y + (p2.y - p0.y) / 6;
            const cp2x = p2.x - (p3.x - p1.x) / 6;
            const cp2y = p2.y - (p3.y - p1.y) / 6;

            d += ` C ${cp1x.toFixed(1)} ${cp1y.toFixed(1)}, ${cp2x.toFixed(1)} ${cp2y.toFixed(1)}, ${p2.x.toFixed(1)} ${p2.y.toFixed(1)}`;
        }

        return d;
    }

    /**
     * Build standard straight polyline path from coords
     */
    function buildStraightPath(coords) {
        if (coords.length === 0) return '';
        return coords.map((pt, i) => `${i === 0 ? 'M' : 'L'} ${pt.x.toFixed(1)} ${pt.y.toFixed(1)}`).join(' ');
    }

    /**
     * Render a pure SVG sparkline into container
     * @param {HTMLElement|string} containerOrSelector Container element or selector
     * @param {Array<number|Object>} points Array of values or { value, timestamp }
     * @param {Object} [options]
     */
    function renderSparkline(containerOrSelector, points, options = {}) {
        const container = typeof containerOrSelector === 'string'
            ? document.querySelector(containerOrSelector)
            : containerOrSelector;

        if (!container) return null;

        const opts = Object.assign({
            width: 120,
            height: 32,
            color: 'var(--accent, #6366f1)',
            showArea: true,
            strokeWidth: 2,
            smooth: true,
            showDots: false,
            mode: 'bandwidth', // 'bandwidth' | 'latency' | 'ping'
            fillOpacity: 0.25,
            min: null,
            max: null,
            tooltip: true
        }, options);

        // Normalize raw data points
        const rawValues = (Array.isArray(points) ? points : []).map(p => {
            if (p !== null && typeof p === 'object' && ('value' in p || 'val' in p)) {
                return Number(p.value !== undefined ? p.value : p.val);
            }
            return Number(p);
        }).filter(v => !isNaN(v));

        const viewBoxWidth = typeof opts.width === 'number' ? opts.width : 120;
        const viewBoxHeight = typeof opts.height === 'number' ? opts.height : 32;

        const padX = opts.strokeWidth + 2;
        const padY = opts.strokeWidth + 2;

        const effectiveW = Math.max(10, viewBoxWidth - padX * 2);
        const effectiveH = Math.max(10, viewBoxHeight - padY * 2);

        // Handle empty or zero data
        const count = rawValues.length;
        let minVal = opts.min !== null ? Number(opts.min) : (count > 0 ? Math.min(...rawValues) : 0);
        let maxVal = opts.max !== null ? Number(opts.max) : (count > 0 ? Math.max(...rawValues) : 1);

        // In latency/bandwidth modes, min is almost always at least 0
        if (opts.min === null && minVal > 0) minVal = 0;
        if (maxVal <= minVal) maxVal = minVal + (minVal === 0 ? 1 : Math.abs(minVal) * 0.2);

        const range = maxVal - minVal;

        // Calculate coordinate positions
        const coords = rawValues.map((val, idx) => {
            const x = count <= 1
                ? viewBoxWidth / 2
                : padX + (idx / (count - 1)) * effectiveW;
            const normalizedY = (val - minVal) / range;
            const y = (viewBoxHeight - padY) - (normalizedY * effectiveH);
            return { x, y, val };
        });

        // Determine main color
        let mainColor = opts.color;
        if (opts.mode === 'latency' || opts.mode === 'ping') {
            const latestVal = count > 0 ? rawValues[count - 1] : 0;
            mainColor = getLatencyColor(latestVal);
        }

        const gradientId = 'spk-grad-' + (++uniqueIdCounter);

        // Build SVG markup
        let svgContent = '';

        // Defs: gradient
        if (opts.showArea && count > 1) {
            svgContent += `
                <defs>
                    <linearGradient id="${gradientId}" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stop-color="${mainColor}" stop-opacity="${opts.fillOpacity}" />
                        <stop offset="100%" stop-color="${mainColor}" stop-opacity="0" />
                    </linearGradient>
                </defs>
            `;
        }

        if (count > 1) {
            const linePath = opts.smooth ? buildSmoothPath(coords) : buildStraightPath(coords);

            // Area path under line
            if (opts.showArea) {
                const first = coords[0];
                const last = coords[coords.length - 1];
                const bottomY = viewBoxHeight;
                const areaD = `${linePath} L ${last.x.toFixed(1)} ${bottomY} L ${first.x.toFixed(1)} ${bottomY} Z`;
                svgContent += `<path class="sparkline-area" d="${areaD}" fill="url(#${gradientId})" stroke="none" />`;
            }

            // Line stroke
            svgContent += `<path class="sparkline-path" d="${linePath}" fill="none" stroke="${mainColor}" stroke-width="${opts.strokeWidth}" stroke-linecap="round" stroke-linejoin="round" />`;
        }

        // Dots
        if (count > 0 && (opts.showDots || opts.showDots === 'last')) {
            const dotsToRender = opts.showDots === 'last' ? [coords[coords.length - 1]] : coords;
            dotsToRender.forEach((pt, i) => {
                let dotColor = mainColor;
                if (opts.mode === 'latency' || opts.mode === 'ping') {
                    dotColor = getLatencyColor(pt.val);
                }
                const formattedVal = opts.mode === 'latency' || opts.mode === 'ping'
                    ? formatLatency(pt.val)
                    : (opts.mode === 'bandwidth' ? formatSpeed(pt.val) : pt.val);

                svgContent += `
                    <circle class="sparkline-dot" cx="${pt.x.toFixed(1)}" cy="${pt.y.toFixed(1)}" r="3" fill="${dotColor}" stroke="var(--bg-surface, #0d0e15)" stroke-width="1.5">
                        ${opts.tooltip ? `<title>${formattedVal}</title>` : ''}
                    </circle>
                `;
            });
        }

        // Wrap in SVG
        const widthAttr = typeof opts.width === 'number' ? `${opts.width}px` : opts.width;
        const heightAttr = typeof opts.height === 'number' ? `${opts.height}px` : opts.height;

        const svgWrapper = `
            <svg class="sparkline-svg" viewBox="0 0 ${viewBoxWidth} ${viewBoxHeight}" width="${widthAttr}" height="${heightAttr}" preserveAspectRatio="none" role="img" aria-label="Sparkline metric chart">
                ${svgContent}
            </svg>
        `;

        container.innerHTML = svgWrapper;
        container.classList.add('sparkline-container');

        return container.querySelector('svg');
    }

    /* ===== Public API Object ===== */

    const Telemetry = {
        // Polling Manager
        poll: poll,
        pause: pause,
        resume: resume,
        stop: stop,
        trigger: trigger,
        getActiveStreams: getActiveStreams,
        pauseAll: pauseAll,
        resumeAll: resumeAll,
        stopAll: stopAll,

        // Sparkline Generator
        renderSparkline: renderSparkline,

        // Formatters
        formatSpeed: formatSpeed,
        formatLatency: formatLatency,
        formatBytes: formatBytes
    };

    return Telemetry;
}));
