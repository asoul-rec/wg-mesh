# Architecture Overview

This document describes the internal design of the decentralized P2P WireGuard mesh controller, covering its synchronization protocol, encryption model, routing subsystem, and daemon framework.

## System Architecture

The mesh controller runs as an asynchronous Python daemon that bridges the **control plane** (gossip-based state synchronization over UDP port 8080) to the **data plane** (WireGuard tunnels, SRv6 encapsulation, and VRF routing managed via Linux kernel interfaces).

On startup, the controller provisions the WireGuard interface (`ip link add ... type wireguard`), generates or loads cryptographic keys, and begins listening for gossip messages. As peers propagate their state — node identity, public key, endpoint, route costs, and externally reachable subnets — the controller converges the local topology view and applies changes via `wg set`, `nftables`, and `iproute2` commands.

## Mesh Synchronization Protocol

Network state is distributed via an authenticated, flood-based gossip protocol. Three packet types are defined:

| Type | Name | Purpose |
|------|------|---------|
| 1 | Announce | Full topology state (Zstandard-compressed JSON) |
| 2 | ACK | Delivery confirmation with packet tag for RTT measurement |
| 3 | Route Cost | Lightweight per-peer link cost update (uncompressed JSON) |

All packets share a common wire format defined by `MeshPacket`: a 4-byte outer header containing the protocol version, followed by an encrypted inner payload with an 8-byte header (type, origin ID, sequence number, packet tag) and application data.

### Symmetric Authenticated Encryption

All mesh communication is authenticated to prevent injection or forgery.

- **Key Derivation**: A symmetric key is derived by computing `SHA-256` over the recipient's WireGuard public key. Since only legitimate mesh members know each other's public keys, this acts as an implicit pre-shared secret.
- **Confidentiality**: Payloads are encrypted using a SHA-256-based CTR-mode stream cipher keyed with the derived key and a random 8-byte nonce.
- **Integrity**: Each encrypted packet is sealed with an `HMAC-SHA256` tag. Packets failing MAC verification are silently dropped.

### State Synchronization and Conflict Resolution

Without a central authority, nodes resolve conflicting state using two axes:

- **Wrapping Sequence Numbers (32-bit)**: Each node maintains a monotonically increasing sequence number. When a peer receives an announce, it merges the enclosed node records only if the incoming sequence is strictly newer (positive wrapping difference via `wrapping_sub`). Replayed or slightly older packets within the `STALE_TOLERANCE` window (4096) are dropped.
- **UTC Timestamp Verification**: To prevent a node from polluting the network with an artificially advanced sequence number, the protocol performs dual-axis verification. Payloads timestamped more than 60 seconds in the future are rejected. Conversely, if a "newer" sequence carries a timestamp older than 120 seconds relative to the local record, the protocol suspects stale data and may reject or override it.
- **Amnesia Recovery**: If a node suffers total state loss (e.g., restart without persistent storage), it applies a large sequence leap (`2 × STALE_TOLERANCE`) on boot. Peers interpret this gap as an amnesia event and bypass the normal stale-drop window, allowing the revived node to rapidly re-synchronize.

### Reliable Delivery and Traffic Optimization

- **ACK-Based Retransmission**: Each unicast message is sent with up to 3 retry attempts (3-second timeout each). ACK packets carry a `pkt_tag` matching the attempt number, tracked via per-peer `asyncio.Queue` structures.
- **Exponential Self-Correction Backoff**: When a node detects that a peer is broadcasting stale information about itself, it issues a corrective self-announce. To prevent broadcast storms during split-brain events, repeated corrections are throttled via an exponential backoff mechanism based on recent send history.
- **Version Compatibility**: The outer header carries a 4-byte version. Packets are accepted only if the first three version octets match, allowing patch-level differences while rejecting incompatible protocol changes.

## Link Quality Assessment

Each node tracks per-peer RTT measurements from ACK round trips. The `LinkCostSummary.exponential_decay_integral` algorithm computes a weighted-average RTT by integrating an exponential decay PDF across sample midpoints:

- Recent measurements carry higher weight; the half-life is 20 seconds.
- Individual sample weights are capped at 0.2 to prevent outlier dominance.
- Lost packets (timeout) are penalized at 6000 ms internally; the externally reported cost is capped at 3000.
- Route costs are broadcast to all peers via pkt_type 3, forming a distributed link-state database.

## SRv6 Routing Subsystem

An SRv6 NEXT-CSID overlay operates alongside the WireGuard tunnels:

- The `Routing` daemon periodically runs Dijkstra's shortest-path algorithm over the gossip-propagated link-state graph (`route_cost` from all nodes).
- Computed paths are expressed as CSID hop lists and pushed to the kernel's `nftables` `srv6_paths` map via differential updates (add/replace/delete against a cached route table in `Seg6Controller`).
- Topology changes (peer join/leave) and ACK timeouts for previously-reachable peers trigger immediate re-computation via the routing supervisor's event mechanism, debounced by 3 seconds.

## VRF External Route Encapsulation

To expose externally reachable subnets over the mesh without interfering with WireGuard's `allowed-ips` constraints:

- Each node declares `external_routes` in its local configuration, mapping destination prefixes to local device or address options.
- The prefix list is gossip-propagated as `external_ips` in node announcements.
- During WireGuard peer sync, each peer's external prefixes are translated into IPv6 encapsulation routes (`ip route add ... encap ip6 dst <csid_addr>`) within a VRF table (default table 100), with differential sync via `VRFTable.sync_encap_routes`.

## Daemon Framework

Background tasks are managed through a `Daemon` base class (`daemons.py`) that provides a uniform lifecycle (start/stop/is_running) and exception reporting via `asyncio.Task` done callbacks. Three daemons run concurrently:

| Daemon | Trigger | Function |
|--------|---------|----------|
| `OnlineMonitor` | Inbound packet event or timeout | Detects connectivity loss; adjusts keepalive intervals |
| `KeepAlive` | Timer or broadcast event | Fires periodic self-announces to maintain presence |
| `Routing` | WG peer change event, ACK timeout, or 60s timer | Recomputes shortest paths and syncs SRv6 routes |

## Node Identity Protection

Core identity fields (`node_id`, `name`, `pubkey`, `endpoint`, `external_ips`) are marked as protected on the `Node` dataclass. Once `_initialized` is set, writes to these fields raise `AttributeError` unless wrapped in a `_force_write()` context manager. This prevents accidental mutation from gossip processing outside of the explicit merge logic.
