#!/usr/bin/env python3
"""
Deep Metrics Extractor for /home/igor/nexus.log
Analyzes timelines, bursts, rates, correlations, and latency percentiles.
"""
import sys
import re
import datetime
from collections import Counter, defaultdict
import json

LOG_PATH = "/home/igor/nexus.log"

def parse_iso(ts):
    if ts.endswith("Z"):
        ts = ts[:-1]
    return datetime.datetime.fromisoformat(ts)

def parse_http_time(ts):
    return datetime.datetime.strptime(ts, "%Y/%m/%d %H:%M:%S")

def parse_lat_us(dur):
    dur = dur.strip()
    if dur.endswith("µs"):
        return float(dur[:-2])
    elif dur.endswith("ms"):
        return float(dur[:-2]) * 1000.0
    elif dur.endswith("ns"):
        return float(dur[:-2]) / 1000.0
    elif dur.endswith("s"):
        return float(dur[:-1]) * 1000000.0
    return 0.0

def main():
    slog_re = re.compile(r'time=([^\s]+)\s+level=([A-Z]+)\s+msg="([^"]*)"(.*)')
    http_re = re.compile(r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[([^\]]+)\] "([A-Z]+) ([^\s]+) (HTTP/[^\"]+)" from ([^\s]+) - (\d{3}) ([^\s]+) in ([^\s]+)')

    events_by_hour = defaultdict(lambda: Counter())
    events_by_minute = defaultdict(lambda: Counter())

    all_events = []
    http_latencies_by_endpoint = defaultdict(list)
    healthcheck_latencies = []

    peers_decryption_timeline = defaultdict(lambda: defaultdict(int))
    handshake_ip_timeline = defaultdict(lambda: defaultdict(int))
    drops_dest_timeline = defaultdict(lambda: defaultdict(int))

    with open(LOG_PATH, "r", encoding="utf-8") as f:
        for line_no, raw in enumerate(f, 1):
            raw = raw.strip()
            if raw.startswith("amnezia-nexus  | "):
                line = raw[len("amnezia-nexus  | "):]
            else:
                line = raw

            m_slog = slog_re.search(line)
            m_http = http_re.search(line)

            if m_slog:
                ts_str, lvl, msg, extra = m_slog.groups()
                dt = parse_iso(ts_str)
                hour_key = dt.strftime("%Y-%m-%d %H:00")
                min_key = dt.strftime("%Y-%m-%d %H:%M")

                if "transport data decryption failed for peer" in msg:
                    m_peer = re.search(r'peer ([^:]+):', msg)
                    peer = m_peer.group(1).strip() if m_peer else "unknown"
                    events_by_hour[hour_key]["decrypt_fail"] += 1
                    events_by_minute[min_key]["decrypt_fail"] += 1
                    peers_decryption_timeline[peer][hour_key] += 1
                    all_events.append((dt, "decrypt_fail", peer, line_no))

                elif "rejected handshake initiation from" in msg:
                    m_ip = re.search(r'from ([^:]+):', msg)
                    ip = m_ip.group(1).strip() if m_ip else "unknown"
                    events_by_hour[hour_key]["handshake_reject"] += 1
                    events_by_minute[min_key]["handshake_reject"] += 1
                    handshake_ip_timeline[ip][hour_key] += 1
                    all_events.append((dt, "handshake_reject", ip, line_no))

                elif "dropped backend return packet" in msg:
                    m_drop = re.search(r'dropped backend return packet to ([^\s]+) \(backend_tunnel_id=(\d+) server_id=(\d+)\): (.*)', msg)
                    dest = m_drop.group(1) if m_drop else "unknown"
                    events_by_hour[hour_key]["drop_packet"] += 1
                    events_by_minute[min_key]["drop_packet"] += 1
                    drops_dest_timeline[dest][hour_key] += 1
                    all_events.append((dt, "drop_packet", dest, line_no))

                elif "Backend tunnel health probe failed" in msg:
                    events_by_hour[hour_key]["probe_fail"] += 1
                    events_by_minute[min_key]["probe_fail"] += 1
                    all_events.append((dt, "probe_fail", extra, line_no))

                elif "Starting background traffic sync" in msg:
                    events_by_hour[hour_key]["bg_sync"] += 1
                elif "Starting background server reachability check" in msg:
                    events_by_hour[hour_key]["bg_reach"] += 1
                elif "reconciled active_connections" in msg:
                    events_by_hour[hour_key]["vpn_reconcile"] += 1
                elif "No TLS certificate loaded" in msg:
                    events_by_hour[hour_key]["warn_no_tls"] += 1

            elif m_http:
                ts_str, req_id, method, url, proto, client, status, size, lat = m_http.groups()
                dt = parse_http_time(ts_str)
                hour_key = dt.strftime("%Y-%m-%d %H:00")
                min_key = dt.strftime("%Y-%m-%d %H:%M")

                lat_us = parse_lat_us(lat)
                if "/api/health" in url and "127.0.0.1" in client:
                    events_by_hour[hour_key]["http_health"] += 1
                    events_by_minute[min_key]["http_health"] += 1
                    healthcheck_latencies.append(lat_us)
                else:
                    events_by_hour[hour_key]["http_external"] += 1
                    events_by_minute[min_key]["http_external"] += 1
                    http_latencies_by_endpoint[f"{method} {url}"].append((status, lat_us))

    print("=" * 100)
    print("HOURLY BREAKDOWN OF EVENTS")
    print("=" * 100)
    header = f"{'Hour':16s} | {'DecryptFail':11s} | {'HandshakeRej':12s} | {'DropPkt':7s} | {'ProbeFail':9s} | {'ExtHTTP':7s} | {'HealthChk':9s} | {'Total':5s}"
    print(header)
    print("-" * 100)
    
    sorted_hours = sorted(events_by_hour.keys())
    for h in sorted_hours:
        c = events_by_hour[h]
        tot = sum(c.values())
        print(f"{h:16s} | {c['decrypt_fail']:11d} | {c['handshake_reject']:12d} | {c['drop_packet']:7d} | {c['probe_fail']:9d} | {c['http_external']:7d} | {c['http_health']:9d} | {tot:5d}")

    print("\n" + "=" * 100)
    print("PEER DECRYPTION FAILURES BY HOUR")
    print("=" * 100)
    for peer, timeline in peers_decryption_timeline.items():
        total_p = sum(timeline.values())
        print(f"Peer: {peer} (Total: {total_p})")
        for h in sorted(timeline.keys()):
            print(f"  {h}: {timeline[h]}")

    print("\n" + "=" * 100)
    print("DROPPED BACKEND PACKETS BY HOUR")
    print("=" * 100)
    for dest, timeline in drops_dest_timeline.items():
        total_d = sum(timeline.values())
        print(f"Dest IP: {dest} (Total: {total_d})")
        for h in sorted(timeline.keys()):
            print(f"  {h}: {timeline[h]}")

    print("\n" + "=" * 100)
    print("HANDSHAKE REJECTIONS BY HOUR")
    print("=" * 100)
    for ip, timeline in handshake_ip_timeline.items():
        total_i = sum(timeline.values())
        if total_i >= 5: # only frequent ones
            print(f"IP: {ip:18s} (Total: {total_i})")
            for h in sorted(timeline.keys()):
                print(f"  {h}: {timeline[h]}")

    print("\n" + "=" * 100)
    print("HEALTHCHECK LATENCY DISTRIBUTION (µs)")
    print("=" * 100)
    hc_sorted = sorted(healthcheck_latencies)
    n = len(hc_sorted)
    print(f"Count: {n}")
    print(f"Min:   {hc_sorted[0]:.1f} µs")
    print(f"p25:   {hc_sorted[int(n*0.25)]:.1f} µs")
    print(f"p50:   {hc_sorted[int(n*0.50)]:.1f} µs (median)")
    print(f"p75:   {hc_sorted[int(n*0.75)]:.1f} µs")
    print(f"p90:   {hc_sorted[int(n*0.90)]:.1f} µs")
    print(f"p95:   {hc_sorted[int(n*0.95)]:.1f} µs")
    print(f"p99:   {hc_sorted[int(n*0.99)]:.1f} µs")
    print(f"Max:   {hc_sorted[-1]:.1f} µs ({hc_sorted[-1]/1000.0:.3f} ms)")
    print(f"Avg:   {sum(hc_sorted)/n:.1f} µs")

if __name__ == "__main__":
    main()
