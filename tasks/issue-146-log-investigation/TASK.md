# TASK: Deep Investigation of /home/igor/nexus.log and System Performance

## Metadata
- **Task ID**: `TASK-issue-146-log-investigation`
- **GitHub Issue**: [#146](https://github.com/devops-igor/amnezia-nexus/issues/146)
- **Orchestrator**: `pm_bot`
- **Assignee**: `dev_bot` (Lead Developer)
- **Status**: Assigned
- **Created**: 2026-09-15 16:15

## Goal
Conduct a deep investigation of the available logs at `/home/igor/nexus.log` and associated system/container data for potential problems, errors, performance bottlenecks, resource leaks, and abnormal behavior, adhering strictly to the specifications in `tasks/review_logs.md`.

## Core Investigation Areas
1. **Errors and Failures**:
   - Repeated errors, connection resets, upstream failures, timeouts, refused connections, 4xx/5xx spikes.
   - TLS/SSL problems, DNS failures, malformed requests.
   - WAF errors, rule-processing errors, configuration errors, reload failures, crashes/restarts, abnormal exits.
   - Frequency, timeline/start time, trend (increasing/stable), affected domains/clients/upstreams, root cause, severity, recommended actions.

2. **Memory Usage & Possible Memory Leaks**:
   - Evidence of continuously increasing memory usage, baseline memory, large temporary allocations, OOM conditions, container memory pressure.
   - Excessive buffering, large request/response bodies, WAF/CRS memory consumption, HTTP/2 memory growth.
   - Distinguish between normal caching, temporary spikes, sustained growth, and probable leaks. Clearly state required evidence.

3. **CPU & Processing Bottlenecks**:
   - WAF/OWASP CRS rule evaluation, regex-heavy rules, expensive requests, high request rates.
   - HTTP/2 processing, TLS processing, compression, logging, Docker overhead, worker/thread activity.
   - Disproportionately expensive operations.

4. **WAF-Specific Analysis**:
   - Rule matches, false positives, repeated triggering, expensive rules, oversized logs, blocking behavior.
   - Attack traffic vs legitimate traffic, aggressive CRS rules, WAF processing failures/bypasses.

5. **HTTP/1.1 vs HTTP/2 Comparison**:
   - Connection failures, stream resets, protocol errors, GOAWAY frames, connection exhaustion, HPACK/header issues.
   - Request latency comparisons, error rate differences, memory growth differences.

6. **Reverse Proxy & Upstream Performance**:
   - Upstream response times, connection establishment, timeouts, connection pooling, keep-alive, reuse.
   - Distinguish: Client → Proxy vs Proxy → WAF vs Proxy → Upstream vs Upstream → App.

7. **Docker / Container Behavior**:
   - Restarts, health-check failures, OOM kills, throttling, log volume, network issues.

8. **Traffic Anomalies & Correlations**:
   - Spikes, request rates, suspicious IPs, scanning, malformed requests, correlations with CPU/RAM spikes.
   - Event chains (e.g. Traffic spike → WAF overhead → CPU spike → latency → timeouts).

## Deliverable & Reporting Format
Document findings in `tasks/issue-146-log-investigation/DEV_HANDOVER.md` following the exact report structure specified in `tasks/review_logs.md`:
- **Executive Summary** (3–10 most important findings)
- **Critical / High Priority Issues**
- **Resource Bottlenecks** (CPU, RAM, network, disk, WAF, proxy, upstream)
- **WAF Analysis**
- **HTTP/2 Analysis**
- **Reliability Analysis**
- **Timeline**
- **Root Cause Candidates**
- **Recommended Actions** (Immediate fixes, investigation steps, optimizations, long-term improvements)
- **Additional Data Needed**
- **Overall Assessment** (System health, primary bottleneck, memory leak verdict, WAF overhead verdict, HTTP/2 verdict, immediate next steps, what NOT to change prematurely)

## Rules & Constraints
- All intermediate analysis scripts, data extracts, or work files MUST reside in `tasks/issue-146-log-investigation/`.
- Do NOT invent metrics not present in logs.
- Quote or reference exact log entries supporting conclusions.
- Distinguish facts from hypotheses.
- Do NOT commit or push code. Hand off findings via `DEV_HANDOVER.md` and log to `WORKLOG.md`.
