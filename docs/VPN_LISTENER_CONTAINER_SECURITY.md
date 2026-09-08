# Container Security Hardening: VPN Listener & Network Privileges

## 1. Executive Summary

In development, running the `amnezia-panel` container with `user: root` and `cap_add: [NET_ADMIN]` is functional and allows the in-process VPN listener to open `/dev/net/tun` via `ioctl(TUNSETIFF)` for the `awg0` interface. 

However, from a strict production security standpoint (Principle of Least Privilege), running an internet-facing web application as root with network administration capabilities introduces significant privilege escalation and attack surface risks.

---

## 2. Risk Analysis of `user: root` + `CAP_NET_ADMIN`

1. **Combined Web Server and Data Plane**:
   - `amnezia-panel` handles public HTTP/HTTPS traffic, user authentication, session cookies, dynamic templates, and database interactions.
   - If an application-level vulnerability (e.g., dependency vulnerability, remote code execution) is exploited in a process executing as `root`, the attacker immediately gains UID 0 access inside the container.

2. **Privilege Escalation via `CAP_NET_ADMIN`**:
   - `NET_ADMIN` permits manipulation of host/container network interfaces, IP routing tables, firewall (`iptables` / `nftables`) rules, and raw packet crafting.
   - Unless Docker User Namespaces (`userns-remap`) are enabled on the host, UID 0 inside a container maps directly to UID 0 (root) on the host Linux kernel. Any container breakout (e.g. kernel exploit or runc flaw) results in host takeover.

---

## 3. Why `user: root` Was Needed

Creating a Linux TUN interface via `ioctl(fd, TUNSETIFF, ...)` requires the `CAP_NET_ADMIN` capability.

When Docker drops privileges to an unprivileged user (such as `appuser`, `uid: 1000`):
- By default, the Linux kernel clears the **Effective** capability set (`CapEff: 0000000000000000`).
- Even if `cap_add: [NET_ADMIN]` is present in `docker-compose.yaml`, the capability remains in the bounding set (`CapBnd`), but the unprivileged process cannot exercise it without explicit ambient capability inheritance or file capabilities.

---

## 4. Production-Hardened Alternatives (Least Privilege)

### Option A: Ambient Capabilities via `setpriv` (Recommended)

Start the container entrypoint as root, assign `CAP_NET_ADMIN` to the process ambient capability set, and immediately drop UID and GID to `appuser` (UID 1000) before executing the panel:

```bash
#!/bin/sh
# entrypoint.sh

# Retain NET_ADMIN in ambient set while dropping to appuser (uid 1000)
exec setpriv --reuid 1000 --regid 1000 --init-groups \
             --inh-caps +net_admin --ambient-caps +net_admin \
             /app/panel
```

**Benefits**:
- The main panel binary runs as an unprivileged user (`uid=1000`).
- The process cannot read or write root-owned files or secrets.
- `ioctl(TUNSETIFF)` succeeds because `CAP_NET_ADMIN` is preserved in `CapEff`.

---

### Option B: Binary File Capabilities (`setcap`)

Set file capabilities on the executable inside the Docker image:

```dockerfile
RUN apk add --no-cache libcap && \
    setcap cap_net_admin+ep /app/panel && \
    apk del libcap

USER appuser
CMD ["/app/panel"]
```

**Requirements**:
- Ensure the underlying container filesystem or volume is not mounted with the `nosuid` flag.
- Docker compose must still provide `cap_add: [NET_ADMIN]` so the capability is available in the bounding set.

---

### Option C: Docker User Namespaces (`userns-remap`)

Configure Docker daemon user namespace remapping on the host:

Edit `/etc/docker/daemon.json`:
```json
{
  "userns-remap": "default"
}
```

Restart Docker:
```bash
sudo systemctl restart docker
```

**Benefits**:
- Even if the container specifies `user: root`, UID 0 inside the container maps to an unprivileged UID (e.g., UID 100000) on the host.
- A container breakout yields zero root privileges on the host system.

---

### Option D: Architecture Separation (Management Plane vs Data Plane)

Separate concerns into two distinct containers:
1. **`amnezia-panel` (Management Plane)**:
   - Web UI, SQLite database, REST API, authentication.
   - Runs strictly as unprivileged user (`appuser`, UID 1000) with **zero** added capabilities (`cap_drop: [ALL]`).
2. **`amnezia-vpn-router` (Data Plane)**:
   - Lightweight, purpose-built TUN forwarder (or sidecar WireGuard process).
   - Minimal surface area, handles only UDP packet forwarding with `NET_ADMIN`.
   - Communicates with the panel over a protected Unix domain socket or localhost.

---

## 5. Summary Recommendation

| Environment | Configuration | Rationale |
| :--- | :--- | :--- |
| **Development / Testing** | `user: root` + `cap_add: [NET_ADMIN]` | Functional, fast iteration in an isolated, trusted network. |
| **Production (Standard)** | **Option A (`setpriv` ambient caps)** | Runs as non-root `appuser` (UID 1000) with minimal required `NET_ADMIN`. |
| **Production (High Security)**| **Option A + C or Option D** | Combines ambient capabilities with user namespace remapping or process separation. |
