#!/usr/bin/env python3
"""
Deep Analysis of /home/igor/nexus.log for TASK-issue-146-log-investigation
"""
import sys
import os
import re
import datetime
from collections import Counter, defaultdict
import json

LOG_PATH = "/home/igor/nexus.log"

def parse_time(ts_str):
    # Support formats:
    # ISO: 2026-09-14T21:37:31.687Z
    # HTTP log: 2026/09/14 21:37:41
    try:
        if 'T' in ts_str:
            if ts_str.endswith('Z'):
                ts_str = ts_str[:-1]
            return datetime.datetime.fromisoformat(ts_str)
        else:
            return datetime.datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S")
    except Exception as e:
        return None

def parse_duration_us(dur_str):
    # parse: "933.071µs", "1.234ms", "12.34s", "500ns"
    dur_str = dur_str.strip()
    if dur_str.endswith("µs"):
        return float(dur_str[:-2])
    elif dur_str.endswith("ms"):
        return float(dur_str[:-2]) * 1000.0
    elif dur_str.endswith("ns"):
        return float(dur_str[:-2]) / 1000.0
    elif dur_str.endswith("s"):
        return float(dur_str[:-1]) * 1000000.0
    return 0.0

def main():
    slog_re = re.compile(r'time=([^\s]+)\s+level=([A-Z]+)\s+msg="([^"]*)"(.*)')
    http_re = re.compile(r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[([^\]]+)\] "([A-Z]+) ([^\s]+) (HTTP/[^\"]+)" from ([^\s]+) - (\d{3}) ([^\s]+) in ([^\s]+)')

    total_lines = 0
    categories = Counter()
    log_levels = Counter()
    
    # Detailed data structures
    decrypt_fails_by_peer = Counter()
    decrypt_fails_by_err = Counter()
    decrypt_fails_timeline = defaultdict(int) # minute -> count
    
    handshake_rejects_by_ip = Counter()
    handshake_rejects_by_err = Counter()
    handshake_rejects_timeline = defaultdict(int)

    dropped_packets_by_dest = Counter()
    dropped_packets_by_reason = Counter()
    dropped_packets_by_tunnel = Counter()
    dropped_packets_timeline = defaultdict(int)

    probe_failures = []
    
    http_requests = []
    http_by_path = defaultdict(list)
    http_timeline = defaultdict(int)
    http_statuses = Counter()
    http_user_agents = Counter() # if any
    http_clients = Counter()

    first_ts = None
    last_ts = None

    with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
        for line_no, raw_line in enumerate(f, 1):
            total_lines += 1
            line = raw_line.strip()
            if line.startswith("amnezia-nexus  | "):
                line = line[len("amnezia-nexus  | "):]

            m_slog = slog_re.search(line)
            m_http = http_re.search(line)

            if m_slog:
                ts_str, lvl, msg, extra = m_slog.groups()
                log_levels[lvl] += 1
                dt = parse_time(ts_str)
                if dt:
                    if first_ts is None or dt < first_ts:
                        first_ts = dt
                    if last_ts is None or dt > last_ts:
                        last_ts = dt
                    minute_bucket = dt.strftime("%Y-%m-%d %H:%M")
                else:
                    minute_bucket = "unknown"

                if "transport data decryption failed for peer" in msg:
                    categories["VPN_DECRYPT_FAIL"] += 1
                    decrypt_fails_timeline[minute_bucket] += 1
                    # extract peer and error
                    m_peer = re.search(r'peer ([^:]+): (.*)', msg)
                    if m_peer:
                        peer_key, err_text = m_peer.groups()
                        decrypt_fails_by_peer[peer_key.strip()] += 1
                        decrypt_fails_by_err[err_text.strip()] += 1
                    else:
                        decrypt_fails_by_peer["unknown"] += 1

                elif "rejected handshake initiation from" in msg:
                    categories["VPN_REJECT_HANDSHAKE"] += 1
                    handshake_rejects_timeline[minute_bucket] += 1
                    m_hand = re.search(r'from ([^:]+:\d+): (.*)', msg)
                    if m_hand:
                        client_addr, err_text = m_hand.groups()
                        ip = client_addr.split(":")[0]
                        handshake_rejects_by_ip[ip] += 1
                        handshake_rejects_by_err[err_text.strip()] += 1

                elif "dropped backend return packet" in msg:
                    categories["VPN_DROP_BACKEND_PACKET"] += 1
                    dropped_packets_timeline[minute_bucket] += 1
                    m_drop = re.search(r'dropped backend return packet to ([^\s]+) \(backend_tunnel_id=(\d+) server_id=(\d+)\): (.*)', msg)
                    if m_drop:
                        dest_ip, tunnel_id, server_id, reason = m_drop.groups()
                        dropped_packets_by_dest[dest_ip] += 1
                        dropped_packets_by_reason[reason.strip()] += 1
                        dropped_packets_by_tunnel[f"tunnel_{tunnel_id}_server_{server_id}"] += 1
                    else:
                        dropped_packets_by_reason["unparsed"] += 1

                elif "Backend tunnel health probe failed" in msg:
                    categories["VPN_BACKEND_PROBE_FAIL"] += 1
                    probe_failures.append({
                        "line": line_no,
                        "timestamp": ts_str,
                        "extra": extra.strip()
                    })

                elif "reconciled active_connections" in msg:
                    categories["VPN_RECONCILE_CONNECTIONS"] += 1

                elif "Starting background traffic sync" in msg:
                    categories["BG_TRAFFIC_SYNC"] += 1

                elif "Starting background server reachability check" in msg:
                    categories["BG_REACHABILITY_CHECK"] += 1

                else:
                    categories[f"SLOG_{lvl}"] += 1

            elif m_http:
                categories["HTTP_ACCESS"] += 1
                ts_str, req_id, method, url, proto, client, status, size, lat = m_http.groups()
                dt = parse_time(ts_str)
                if dt:
                    if first_ts is None or dt < first_ts:
                        first_ts = dt
                    if last_ts is None or dt > last_ts:
                        last_ts = dt
                    minute_bucket = dt.strftime("%Y-%m-%d %H:%M")
                else:
                    minute_bucket = "unknown"

                lat_us = parse_duration_us(lat)
                client_ip = client.split(":")[0]
                http_statuses[status] += 1
                http_timeline[minute_bucket] += 1
                http_clients[client_ip] += 1

                req_info = {
                    "line": line_no,
                    "timestamp": ts_str,
                    "method": method,
                    "url": url,
                    "proto": proto,
                    "client": client,
                    "client_ip": client_ip,
                    "status": status,
                    "size": size,
                    "lat": lat,
                    "lat_us": lat_us
                }
                http_requests.append(req_info)
                http_by_path[f"{method} {url}"].append(req_info)

            else:
                categories["OTHER"] += 1

    print("=" * 80)
    print("AMNEZIA-NEXUS LOG INVESTIGATION SUMMARY")
    print("=" * 80)
    print(f"Total lines: {total_lines}")
    print(f"Time range: {first_ts} to {last_ts} (Duration: {last_ts - first_ts if first_ts and last_ts else 'N/A'})")
    print("\nLog categories breakdown:")
    for cat, cnt in categories.most_common():
        pct = (cnt / total_lines) * 100
        print(f"  {cat:28s} : {cnt:5d} ({pct:5.2f}%)")

    print("\n" + "-" * 80)
    print("1. DECRYPTION FAILURES ANALYSIS")
    print("-" * 80)
    print(f"Total decryption failure events: {sum(decrypt_fails_by_peer.values())}")
    print("Failures by peer key:")
    for peer, cnt in decrypt_fails_by_peer.most_common():
        pct = (cnt / sum(decrypt_fails_by_peer.values())) * 100
        print(f"  Peer: {peer} : {cnt:5d} ({pct:5.2f}%)")
    print("\nFailures by error message:")
    for err, cnt in decrypt_fails_by_err.most_common():
        print(f"  {err} : {cnt}")

    print("\n" + "-" * 80)
    print("2. HANDSHAKE REJECTIONS ANALYSIS")
    print("-" * 80)
    print(f"Total rejected handshakes logged: {sum(handshake_rejects_by_ip.values())}")
    print("Top rejected client IPs:")
    for ip, cnt in handshake_rejects_by_ip.most_common(10):
        print(f"  {ip:20s} : {cnt:5d}")
    print("\nRejection reasons:")
    for err, cnt in handshake_rejects_by_err.most_common():
        print(f"  {err} : {cnt}")

    print("\n" + "-" * 80)
    print("3. BACKEND RETURN PACKET DROPS ANALYSIS")
    print("-" * 80)
    print(f"Total dropped backend return packets: {sum(dropped_packets_by_dest.values())}")
    print("Drops by destination IP:")
    for dest, cnt in dropped_packets_by_dest.most_common():
        print(f"  Dest IP: {dest:15s} : {cnt:5d}")
    print("\nDrops by reason:")
    for reason, cnt in dropped_packets_by_reason.most_common():
        print(f"  Reason: {reason:30s} : {cnt:5d}")
    print("\nDrops by tunnel / server:")
    for tun, cnt in dropped_packets_by_tunnel.most_common():
        print(f"  {tun:25s} : {cnt:5d}")

    print("\n" + "-" * 80)
    print("4. BACKEND TUNNEL HEALTH PROBE FAILURES")
    print("-" * 80)
    print(f"Total probe failures: {len(probe_failures)}")
    for pf in probe_failures:
        print(f"  Line {pf['line']:4d} | Time: {pf['timestamp']} | Details: {pf['extra']}")

    print("\n" + "-" * 80)
    print("5. HTTP REQUESTS & WEB PANEL ANALYSIS")
    print("-" * 80)
    print(f"Total HTTP requests: {len(http_requests)}")
    print("HTTP Status Codes:")
    for status, cnt in http_statuses.most_common():
        print(f"  Status {status} : {cnt}")
    print("\nTop HTTP Clients:")
    for client, cnt in http_clients.most_common(10):
        print(f"  Client {client:20s} : {cnt:5d}")

    print("\nHTTP Request Latencies by Endpoint (Summary):")
    for endpoint, reqs in sorted(http_by_path.items(), key=lambda x: len(x[1]), reverse=True):
        lats = [r["lat_us"] for r in reqs]
        avg_lat = sum(lats) / len(lats)
        min_lat = min(lats)
        max_lat = max(lats)
        lats_sorted = sorted(lats)
        p50 = lats_sorted[int(len(lats_sorted) * 0.50)]
        p95 = lats_sorted[int(len(lats_sorted) * 0.95)]
        p99 = lats_sorted[min(int(len(lats_sorted) * 0.99), len(lats_sorted)-1)]
        print(f"\n  Endpoint: {endpoint}")
        print(f"    Count: {len(reqs)} | Statuses: {dict(Counter(r['status'] for r in reqs))}")
        print(f"    Latency (µs): min={min_lat:.1f}, p50={p50:.1f}, p95={p95:.1f}, p99={p99:.1f}, max={max_lat:.1f}, avg={avg_lat:.1f}")

if __name__ == "__main__":
    main()
