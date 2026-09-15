#!/usr/bin/env python3
import sys
import re
from collections import Counter, defaultdict

LOG_FILE = "/home/igor/nexus.log"

levels = Counter()
modules = Counter()
http_statuses = Counter()
http_paths = Counter()
http_protocols = Counter()
http_latencies = []
http_by_path = defaultdict(list)
messages = Counter()
errors = []
warnings = []
timestamps = []

# Check keywords
waf_mentions = []
memory_mentions = []
h2_mentions = []
proxy_mentions = []
upstream_mentions = []

line_re_slog = re.compile(r'time=([^\s]+)\s+level=([A-Z]+)\s+msg="([^"]*)"(.*)')
line_re_http = re.compile(r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[([^\]]+)\] "([A-Z]+) ([^\s]+) (HTTP/[^\"]+)" from ([^\s]+) - (\d{3}) ([^\s]+) in ([^\s]+)')

with open(LOG_FILE, 'r', encoding='utf-8', errors='replace') as f:
    for idx, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue
        # Strip container prefix
        if line.startswith("amnezia-nexus  | "):
            content = line[len("amnezia-nexus  | "):]
        else:
            content = line

        # Check keywords
        lower = content.lower()
        if any(k in lower for k in ['waf', 'crs', 'coraza', 'modsecurity', 'owasp']):
            waf_mentions.append((idx, content))
        if any(k in lower for k in ['mem', 'oom', 'alloc', 'leak', 'gc', 'heap', 'rss']):
            memory_mentions.append((idx, content))
        if any(k in lower for k in ['http/2', 'h2', 'goaway', 'stream', 'rst_stream', 'hpack']):
            h2_mentions.append((idx, content))
        if any(k in lower for k in ['proxy', 'upstream', 'backend', 'reverse']):
            upstream_mentions.append((idx, content))

        m_slog = line_re_slog.search(content)
        m_http = line_re_http.search(content)

        if m_slog:
            ts, lvl, msg, extra = m_slog.groups()
            levels[lvl] += 1
            timestamps.append(ts)
            # Find module if in msg
            mod_match = re.match(r'(\[[^\]]+\])', msg)
            if mod_match:
                modules[mod_match.group(1)] += 1
            else:
                modules['general'] += 1
            messages[f"[{lvl}] {msg}"] += 1
            if lvl in ('ERROR', 'FATAL'):
                errors.append((idx, ts, lvl, msg, extra))
            elif lvl == 'WARN':
                warnings.append((idx, ts, lvl, msg, extra))
        elif m_http:
            ts, req_id, method, url, proto, client, status, size, lat = m_http.groups()
            levels['HTTP_ACCESS'] += 1
            timestamps.append(ts)
            http_statuses[status] += 1
            http_paths[f"{method} {url}"] += 1
            http_protocols[proto] += 1
            http_latencies.append((method, url, status, lat, size))
            http_by_path[url].append((status, lat, size))
        else:
            levels['OTHER'] += 1
            if 'ERROR' in content:
                errors.append((idx, 'unknown', 'ERROR', content, ''))
            elif 'WARN' in content:
                warnings.append((idx, 'unknown', 'WARN', content, ''))

print(f"Total lines analyzed: {idx}")
print("\nLog Levels count:")
for lvl, cnt in levels.most_common():
    print(f"  {lvl}: {cnt}")

print("\nTimestamps:")
if timestamps:
    print(f"  First: {timestamps[0]}")
    print(f"  Last:  {timestamps[-1]}")

print("\nHTTP Protocols:")
for p, c in http_protocols.most_common():
    print(f"  {p}: {c}")

print("\nHTTP Statuses:")
for s, c in http_statuses.most_common():
    print(f"  {s}: {c}")

print("\nTop HTTP Paths:")
for p, c in http_paths.most_common(15):
    print(f"  {c:4d} | {p}")

print("\nTop Modules:")
for m, c in modules.most_common(15):
    print(f"  {c:4d} | {m}")

print("\nTop Slog Messages:")
for msg, c in messages.most_common(20):
    print(f"  {c:4d} | {msg}")

print(f"\nWAF mentions: {len(waf_mentions)}")
for idx, m in waf_mentions[:10]:
    print(f"  Line {idx}: {m}")

print(f"\nMemory mentions: {len(memory_mentions)}")
for idx, m in memory_mentions[:10]:
    print(f"  Line {idx}: {m}")

print(f"\nHTTP/2 mentions: {len(h2_mentions)}")
for idx, m in h2_mentions[:10]:
    print(f"  Line {idx}: {m}")

print(f"\nUpstream/Backend mentions: {len(upstream_mentions)}")
for idx, m in upstream_mentions[:10]:
    print(f"  Line {idx}: {m}")

print(f"\nErrors count: {len(errors)}")
for e in errors[:10]:
    print(f"  Line {e[0]}: {e}")

print(f"\nWarnings count: {len(warnings)}")
for w in warnings[:10]:
    print(f"  Line {w[0]}: {w}")
