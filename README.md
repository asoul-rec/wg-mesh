# P2P WG Mesh Controller

This project implements a decentralized peer-to-peer WireGuard mesh coordination script.
It enables dynamic nodes to discover each other, negotiate public keys and endpoints, and automatically build a full mesh over WireGuard using a resilient Gossip/Flood broadcast protocol without a central server.

## Overview of Operation

The controller listens on UDP port 8080 over the internal network. 
Nodes form a mesh by communicating their current routing state (Name, Public Key, Endpoint) alongside a **monotonically increasing Sequence Number**. 
When a node receives an advertisement (an `Announce` packet) from a peer, it decodes the payload, compares it with its local knowledge, merges the new properties, and strategically propagates updates through the network.

## The Mesh Sync Protocol

### Packets
- **Header Structure**: `(13 bytes)` `[VERSION (4 bytes), type (1 byte), origin_id (4 bytes), seq_num (4 bytes)]`
- **Packet Types**:
  - `1`: `Announce` (Contains the JSON-encoded state table as payload)
  - `2`: `ACK` (Acknowledgement payload to facilitate reliable transmission retries)

### Flood Control & Conflict Resolution Rule
Whenever an `Announce` packet is received from `origin_id`, the receiver inspects the `seq_num` for the originating node and processes the payload table.

1. **Flood Control (Dropping stale messages to prevent broadcast storms):**
   A node drops incoming announcements originating from peer `A` that match or are slightly older (`<= 0`) than the latest sequence number it remembers for `A` (up to a `STALE_TOLERANCE` gap). 
   If the sequence is *drastically* older (e.g. `< -STALE_TOLERANCE`), the node accepts the packet anyways. This represents `A` suffering from "amnesia" (e.g. it crashed, lost its sequence, and rebooted at zero, rolling backwards through the wrap-around gap).

2. **Gossip / Conflict Merging:**
   When iterating over the nodes described in the packet payload:
   - **`d > 0` (Sender's view is newer):** The local node overrides its inner representation with the new data.
   - **`d < 0` (Sender's view is older) OR Missing node:** The local node notices the sender is out-of-date or incomplete (`source_needs_correction = True`).
   - **`d == 0` (Same sequence, differing data on a third-party peer):** If two partitions witness conflicting updates for peer `C` at the exact same sequence number, the node gracefully "steps back" by instantly dropping its own knowledge of `C` (`del self.known_nodes[C]`). This guarantees tie-breaking by forcing the offline conflicting node out of the active mesh or accepting the surviving broadcast.

3. **Re-Broadcasting Activity (`source_needs_correction` flag):**
   - If the local node learned new configurations without noticing any defects in the sender, it safely forwards the broadcast payload to the rest of the mesh.
   - If the local node detected that the sender was missing entries, had older records, or experienced a split-brain `d==0` conflict, the local node increments its own sequence number and explicitly fires a **brand new broadcast** of its *entire* merged knowledge table, correcting all peers on the network.

### Node Initial Boot (Amnesia Leap)
When a node spins up, it increments its sequence by a small fraction, but then immediately performs a **Leap Increment** (`STALE_TOLERANCE * 2`). This forcefully shoves the sequence number entirely out of the standard `STALE_TOLERANCE` drop-window. This ensures that any existing nodes holding an older snapshot of the restarting node will definitively interpret it as an "amnesiac" event instead of silently dropping the advertisement as a delayed replay.
