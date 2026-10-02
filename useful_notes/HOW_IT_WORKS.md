# Amnezia Nexus Architecture & How It Works

## Data Plane Architecture

Amnezia Nexus employs a high-performance, userspace in-memory data plane architecture powered by upstream `amneziawg-go` for both client ingress and backend egress:

```text
Ingress Path:

[Client / AmneziaWG Official App]
               │ (AWG 3.x Obfuscated UDP Handshake & Transport)
               ▼
   [Nexus Ingress Engine (amneziawg-go)]
               │ (Decrypted IP Packets via In-Memory Channel Ring)
               ▼
     [VirtualTUN (Userspace Memory)]
               │ (Zero Kernel Copies, Zero /dev/net/tun Dependency)
               ▼
   [Nexus Forwarder & Load Balancer]
               │ (Least Connections / Sticky / Round-Robin L3 Routing)
               ▼
     [VirtualTUN (Userspace Memory)]
               │ (Decrypted IP Packets via In-Memory Channel Ring)
               ▼
   [Nexus Egress Engine (amneziawg-go)]
               │ (AWG 3.x Obfuscated UDP Encrypted Tunnel)
               ▼
[Backend Server Container (Foreign Node)]
               │
               ▼
         [Open Internet]

Return Path:

[Backend Server Container (Foreign Node)]
               │ (AWG 3.x Encrypted Tunnel)
               ▼
   [Nexus Egress Engine (amneziawg-go)]
               │ (Decrypted IP Packets via VirtualTUN)
               ▼
   [Nexus Forwarder]
               │ (Explicit Route Lookup by Destination IP)
               ▼
   [ReturnPath Writer]
               │ (Direct Write via In-Memory Ring)
               ▼
     [VirtualTUN (Userspace Memory)]
               │
               ▼
   [Nexus Ingress Engine (amneziawg-go)]
               │ (AWG 3.x Encrypted UDP Transport)
               ▼
[Client / AmneziaWG Official App]
```

1. **Client Termination**: Nexus terminates client-facing AmneziaWG handshakes and transport encryption using official upstream `amneziawg-go` running in userspace. All cryptographic operations, replay windows, handshake timers, key rotations, and NAT roaming are handled by upstream WireGuard/AmneziaWG protocol logic.
2. **In-Memory VirtualTUN**: Ingress and egress engines interface with the Nexus router via `VirtualTUN`, an ownership-neutral userspace in-memory ring buffer with bounded capacity and zero-allocation fast paths. Zero kernel TUN interfaces or `/dev/net/tun` devices are required.
3. **L3 Routing & Forwarding**: Nexus routes raw L3 IP packets to assigned backend tunnels based on load balancing policy and dynamic health monitoring.
4. **Backend Egress**: Backends run upstream `amneziawg-go` in containers on foreign exit nodes, completely decoupling user configurations from foreign IP addresses.

## Structural Reliability & Issue #383 Resolution

Prior to the upstream migration (Epic #384 / Epic #394), Nexus maintained a custom Go implementation of the WireGuard/AmneziaWG state machine. In production, this resulted in edge-case state desynchronizations cataloged in issue #383. Under the upstream-only architecture, these failure classes are **structurally impossible**:

| #383 Failure Class | Upstream Architecture Elimination Guarantee |
|---|---|
| **Replay misclassification** | Upstream `amneziawg-go` owns all anti-replay bitmap and counter validation. Nexus operates exclusively on decrypted L3 packets via `VirtualTUN`. |
| **Missing return-path transport keys** | Upstream `amneziawg-go` owns and selects client transport keys. Nexus forwarder writes raw IP return packets directly to the explicit `ReturnPath` bound to the IngressEngine. |
| **Key-expiry vs idle-timeout coupling** | AWG key timers, rekey exchanges, and keepalives belong entirely to upstream protocol logic. Nexus session reaping is strictly routing-only and cannot destroy transport key state. |
| **previous/current/next key rollover defects** | Those key slots no longer exist in Nexus; upstream handles the complete Noise IK state machine. |
| **Receiver-index lifecycle defects** | Nexus maintains zero receiver-index tables. Upstream maps incoming receiver indices to peer sessions. |
| **Custom transport decryption failures** | Nexus performs zero client transport encryption/decryption. `amneziawg-go` decrypts all transport packets before passing IP payloads to `VirtualTUN`. |
| **Endpoint roaming defects** | Upstream WireGuard peer state automatically updates peer UDP endpoints on authenticated transport packets. |
| **Self-rebind rejection cycle** | Packet-driven source IP rebinding is permanently deleted. Inbound packet source IPs must match the durable route assigned IP; mismatches are dropped immediately without mutating routing tables. |
