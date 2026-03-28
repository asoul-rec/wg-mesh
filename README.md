# P2P WireGuard Mesh Controller

This project implements a decentralized peer-to-peer WireGuard mesh coordination agent. It enables independent nodes to autonomously discover each other, securely negotiate tunneling parameters, and programmatically build a resilient full-mesh topology—all without a centralized coordination server or manual `wg-quick` intervention.

## Architectural Overview

The mesh controller operates as an asynchronous, zero-dependency Python daemon that bridges the **Control Plane** (gossip synchronization over UDP 8080) directly to the **Data Plane** (Linux native WireGuard kernel routes). 

When a node spins up, it automatically handles interface provisioning (`ip link`), cryptographic key generation, and background gossip listening. As peers propagate their dynamic states (Name, Public Key, Endpoint, internal IP assignment), the controller continuously converges the network graph and directly dictates `wg set` routing updates to the host OS.

## The Mesh Sync Protocol

The network state is distributed via an authenticated, flood-based gossip protocol.

### 1. Symmetric Authenticated Encryption
To prevent malicious injection or header forgery, all mesh communications are strongly authenticated. 
- **Key Derivation**: The protocol establishes an implicit Presigned Shared Key (PSK) derived from the static WireGuard public key pairing between the sender and receiver.
- **Envelope Security**: Every payload is sealed using `HMAC-SHA256` for integrity and blinded via an XOR-Stream cipher, effectively dropping unauthenticated observers or ghost nodes silently.

### 2. State Synchronization & Conflict Resolution
Because UDP is stateless and gossiping lacks a central authority, nodes rely on two metrics to resolve the absolute "truest" state of the mesh:
- **Modular Sequence Numbers (32-bit)**: Each node monotonically controls its own sequence number. When a receiver gets an advertisement (`Announce`), it merges the attributes if the incoming sequence is strictly newer (`d > 0`).
- **UTC Timestamp Veto**: To prevent an isolated node from accidentally (or maliciously) polluting the network with an infinite "future" sequence number that permanently bricks state propagation, the protocol enforces a dual-axis timestamp verification. It rejects ghost payloads stamped too far into the future (>60s) and aggressively overrides seemingly "newer" sequence payloads if the real-time UTC timestamp represents an ancient state (e.g., >120s old). 
- **Amnesia Leaps**: If a node suffers total state loss, it initiates a massive mathematical "Leap Increment" (`STALE_TOLERANCE * 2`) to its sequence upon boot. Surviving peers interpret this drastic gap as an amnesiac reboot, bypassing traditional stale-drop windows to rapidly re-assimilate the revived peer.

### 3. Traffic Optimization & Broadcast Logic
To prevent broadcast storms during massive topology shifts or amnesia resolution events:
- **Asynchronous DNS Throttling**: The daemon maps `wg set` executions into asynchronous subprocesses. If a peer provides an unresolvable or dead DNS endpoint, the execution strictly times out and cleans up the zombie process, preventing the main gossip loop from hanging.
- **Exponential Self-Correction Backoff**: When a node detects that a peer is broadcasting stale information about it, it instantly issues a self-correction broadcast. If a split-brain event triggers hundreds of overlapping conflicts, the node suppresses the storm via an exponential backoff sleeper queue, naturally waiting for the dust to settle before blasting the absolute newest unified sequence exactly once.
