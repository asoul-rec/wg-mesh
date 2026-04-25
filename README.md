# P2P WireGuard Mesh Controller

A decentralized, gossip-based peer-to-peer WireGuard mesh coordination agent. This daemon enables nodes to autonomously discover peers, synchronize topology state, establish SRv6 multi-hop overlays, and route externally mapped subnets through Linux VRFs — all without centralized coordination.

## Features

- **Gossip-Based Mesh Bootstrapping**: Nodes discover and synchronize with each other through authenticated, flood-based UDP gossip. WireGuard peers are provisioned and updated automatically as the topology converges.
- **Conflict-Resilient State Synchronization**: Topology state is distributed using Zstandard-compressed payloads with 32-bit wrapping sequence numbers and UTC timestamp verification to prevent stale replays, split-brain conflicts, and broadcast storms.
- **SRv6 Traffic Engineering**: Constructs Segment Routing over IPv6 (SRv6 NEXT-CSID) overlays. Shortest paths are computed via Dijkstra's algorithm using exponential-decay-weighted RTT measurements collected from peer link telemetry.
- **VRF External Route Encapsulation**: Shares externally reachable subnets (e.g., data center networks, local interfaces) across the mesh via Linux VRF (table 100) with IPv6 encapsulation routes that are differentially synced as the topology changes.
- **Lightweight Runtime**: Pure Python (3.14+) on Linux kernel 6.x+. Relies on `iproute2`, `nftables`, and the kernel WireGuard module with no additional compiled dependencies.

## Documentation

See the [Architecture Overview](docs/architecture.md) for details on the synchronization protocol, encryption model, routing supervisor, and daemon framework.
