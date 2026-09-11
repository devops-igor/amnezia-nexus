# Amnezia Nexus

Amnezia Nexus is a self-hosted web panel and load balancer built specifically for AmneziaWG.

## Why this exists

In countries with aggressive internet censorship (such as Russia), state firewalls and DPI systems frequently block foreign VPN server IPs and entire hosting subnets.

When users connect directly to a foreign VPS, an IP block takes down everyone's connection at once. Fixing it usually means spinning up a new server, creating new `.conf` files for every user, and sending them out all over again.

**Nexus solves this by separating where users connect from where traffic leaves:**

1. **Nexus runs inside the country**: You host the Nexus portal on a domestic server or VPS inside the local network. Because user connections to Nexus stay inside the country, the national firewall does not block them.
2. **Backends run outside**: Nexus maintains encrypted AmneziaWG tunnels to multiple foreign backend nodes (in Europe, the US, etc.) where the traffic actually exits to the open internet.
3. **Automatic failover when an IP is blocked**: If censors block one of your foreign backend IPs, Nexus immediately detects the failure and shifts traffic to your other working backends.
4. **Users never need new configs**: Clients connect to Nexus with a single configuration file that never changes. Even if you replace, rotate, or add backend servers, users stay connected without touching their apps or re-importing profiles.

---

## What it does

- **VPN load balancing**: Spreads user traffic across multiple backend servers using least connections, sticky sessions, or round-robin.
- **Automatic failover**: Sends health probes to backends every few seconds. If a server stops responding, traffic moves to healthy nodes automatically.
- **AmneziaWG 3.x obfuscation**: Supports ChaCha20 header protection, randomized header ranges (`H1`–`H4`), randomized timing ranges (`RekeyAfterTime`, `RekeyTimeout`, etc.), and junk padding to bypass DPI blocks.
- **Web interface**: Add remote servers over SSH, manage users, and download `.conf` files or scan QR codes.
- **Built-in DNS**: Uses AdGuard DNS by default (`94.140.14.14`, `94.140.15.15`).

## How it works

```text
[Users Inside the Country] 
     │  (Domestic connection — stays unblocked)
     ▼
[Nexus Portal (Hosted Locally)] 
     │  1. Terminates client handshake & decrypts traffic
     │  2. Picks a healthy foreign exit node
     │  3. Re-encrypts traffic for that backend
     ▼
[Backend Node A (Foreign)]   [Backend Node B (Foreign)]
     │  (If Node A gets blocked by DPI, Nexus fails over to Node B)
     ▼
[Open Internet]
```

---

## Server Preparation

Before running Nexus on your Linux server (Ubuntu, Debian, or similar), you need to configure packet forwarding and firewall rules so the server can route traffic.

### 1. Enable packet forwarding and loose reverse path filtering

Run this as `root`:

```bash
sudo tee /etc/sysctl.d/99-nexus.conf << 'EOF'
# Allow packet forwarding
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# Loose reverse path filtering (prevents the kernel from dropping return packets on asymmetric paths)
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
EOF

sudo sysctl --system
```

Check that forwarding is on:

```bash
sysctl net.ipv4.ip_forward
# Should return: net.ipv4.ip_forward = 1
```

> **Why `rp_filter = 2`?** By default, Linux drops packets if their return route does not match the incoming interface. Because VPN traffic enters through a tunnel interface and leaves through your WAN interface, strict filtering will silently drop return traffic. Loose mode (`2`) fixes this.

### 2. Make sure the TUN device is available

Nexus needs `/dev/net/tun` to handle tunnel traffic:

```bash
sudo modprobe tun
echo "tun" | sudo tee -a /etc/modules-load.d/tun.conf
ls -l /dev/net/tun
# Should show: crw-rw-rw- 1 root root ... /dev/net/tun
```

### 3. Configure firewall and forwarding

Your firewall needs to let forwarded traffic through.

#### If you use UFW:

1. Open `/etc/default/ufw` and set:
   ```bash
   DEFAULT_FORWARD_POLICY="ACCEPT"
   ```
2. Open the necessary ports and reload:
   ```bash
   sudo ufw allow 80/tcp     # HTTP (or for reverse proxy)
   sudo ufw allow 443/tcp    # HTTPS
   sudo ufw allow 8080/tcp   # Web panel (if accessing directly)
   sudo ufw allow 51820/udp  # VPN listener port
   sudo ufw reload
   ```

#### If you use standard `iptables`:

Find your primary internet interface (usually `eth0` or `ens3`) and set up forwarding and NAT masquerade:

```bash
WAN_IFACE=$(ip route get 1.1.1.1 | awk '{print $5; exit}')

# Allow forwarded traffic
sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i amn+ -o "$WAN_IFACE" -j ACCEPT
sudo iptables -A FORWARD -i "$WAN_IFACE" -o amn+ -j ACCEPT

# Enable NAT masquerade so packets leave with the server's public IP
sudo iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE

# Save rules so they survive a reboot
sudo apt-get install -y iptables-persistent && sudo netfilter-persistent save
```

### 4. Install Docker

If you don't already have Docker installed:

```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

---

## Quick Start

### 1. Create a `docker-compose.yaml`

Create a folder for the project:

```bash
mkdir -p ~/amnezia-nexus && cd ~/amnezia-nexus
```

Create `docker-compose.yaml`:

```yaml
services:
  amnezia-panel:
    image: ghcr.io/devops-igor/amnezia-nexus:v1.0.0
    container_name: amnezia-panel
    restart: unless-stopped
    user: root
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    ports:
      - "8080:5000"           # Web panel
      - "51820:51820/udp"     # VPN port
    volumes:
      - panel-data:/app/data
    environment:
      - PORT=5000
      - DATA_DIR=/app/data
      - LOG_LEVEL=INFO
      - VPN_ENABLED=true
      - VPN_LISTEN_PORT=51820
      - VPN_SUBNET=10.100.0.0/16
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://127.0.0.1:5000/api/health"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 10s

volumes:
  panel-data:
```

### 2. Start the container

> **Image tags:** the compose file above pins the **stable release** (`v1.0.0`).
> Alternatively, use `:latest` to always track the newest build from `main` —
> recommended only for testing, since it may include unreleased changes.
> Available tags: https://github.com/devops-igor/amnezia-nexus/pkgs/container/amnezia-nexus

```bash
docker compose up -d
```

Check the logs to verify everything started properly:

```bash
docker compose logs -f amnezia-panel
```

You should see logs confirming the database is ready and the VPN endpoint is running on port `51820`.

---

## Configuration (Environment Variables)

You can customize Nexus using the following environment variables in your `docker-compose.yaml`:

| Variable | Default | Description |
| :--- | :--- | :--- |
| **`VPN_ENABLED`** | `false` | Activates the in-process AmneziaWG VPN load balancer (`true` or `false`). |
| **`VPN_LISTEN_PORT`** | `51820` | Ingress UDP port where Nexus listens for client VPN connections. |
| **`VPN_SUBNET`** | `10.100.0.0/16` | Internal private IPv4 subnet assigned to connected VPN clients. |
| **`VPN_PUBLIC_ENDPOINT`** | *(auto-detected)* | Public domain or IP (e.g. `vpn.example.com:51820`) embedded into generated client configs. If unset, Nexus auto-detects the host's public IP. Can also be set in the Web UI. |
| **`PORT`** | `5000` | Internal HTTP port for the web interface and REST API. |
| **`HOST`** | `0.0.0.0` | Bind IP address for the web server. |
| **`LOG_LEVEL`** | `INFO` | Logging verbosity: `DEBUG`, `INFO`, `WARN`, or `ERROR`. |
| **`SECRET_KEY`** | *(auto-generated)* | 64-character hex key for encrypting sessions and credentials. If left empty, Nexus generates one on first boot and saves it in `DATA_DIR/.secret_key`. |
| **`TRUSTED_PROXIES`** | *(empty)* | Comma-separated list of reverse proxy IPs or CIDRs (e.g. `127.0.0.1, 10.0.0.0/8`) to safely extract real client IPs from `X-Forwarded-For`. |
| **`DATA_DIR`** | `/app/data` | Directory where persistent files (database, secret key, backups) live. |
| **`DB_PATH`** | `<DATA_DIR>/panel.db` | Specific file path for the SQLite database. |

### Deployment: Secure cookies behind a TLS-terminating proxy

When the panel runs behind a TLS-terminating reverse proxy (e.g. BunkerWeb,
nginx, Caddy) that forwards plain HTTP to the panel, set `TRUSTED_PROXIES` to
the proxy's network CIDR or IP:

```bash
TRUSTED_PROXIES=10.0.0.0/8        # or the exact proxy IP, e.g. 172.18.0.1
```

With this set, requests forwarded by the trusted proxy with
`X-Forwarded-Proto: https` are treated as secure client connections and session
cookies are issued with the `Secure` attribute — even though the panel's own
socket is plain HTTP. Requests from any other peer carrying
`X-Forwarded-Proto` are **not** trusted. When the panel terminates TLS itself,
cookies are `Secure` automatically (no extra configuration), and
`COOKIE_INSECURE=1` (development only) unconditionally disables `Secure`.

---

## Setting Up Your VPN

1. **Log in**: Open `http://<YOUR_SERVER_IP>:8080` in your browser and complete the initial admin setup.
2. **Add your server**: Go to **Servers** -> **Add Server**. Enter the IP address, SSH port, and SSH credentials of your remote node so Nexus can manage it.
3. **Add it to the VPN pool**: Go to the **VPN** section, click **Add Backend**, choose your server from the dropdown, and click **Enable Backend**. Nexus will connect to the node, verify its AmneziaWG container, set up NAT forwarding rules, and add it to the active load balancing pool.
4. **Create client configs**: Go to **Clients** -> **Create Client**. You can scan the generated QR code with the Amnezia VPN mobile app or download the `.conf` file for your desktop.
