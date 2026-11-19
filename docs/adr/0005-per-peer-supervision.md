# ADR 0005: One supervision subtree per peer connection, never restarted

## Context

A peer connection is a group of processes: the peer connection itself, one transport per BUNDLE group, a signaling helper when the `signaling` option is used, and short lived workers that open TCP and TLS connections. Rows in the `webrtc_transports` table point at its transports.

A production safety review found that this group did not always end together: the signaling helper outlived `webrtc:close/1`, and table rows survived a `kill` of the peer connection.

A WebRTC session cannot be restarted from its start arguments: its negotiated descriptions, ICE state, DTLS keys and SCTP association are gone with the process, and the remote peer would not accept a new one without new signaling.

## Decision

- `webrtc_pc_sup` (one_for_one) starts one `webrtc_peer_sup` per peer connection.
- `webrtc_peer_sup` is one_for_all with `auto_shutdown => any_significant`. The peer connection is its significant child; transports are added as temporary children and monitored by the peer connection.
- Nothing is restarted. When the peer connection ends, for any reason, the subtree shuts down with its transports and their sockets.
- The signaling helper is linked to the peer connection and also monitors it. Connect workers are linked to their transport.
- `webrtc_registry` owns the `webrtc_transports` table, monitors every peer connection that writes a row, and removes its rows when it ends. A lookup also drops a row whose process is dead.

## Consequences

- The application sees a peer connection end as `{connection_state, failed}` or `closed`, and creates a new one if it wants to reconnect.
- `webrtc:new_peer_connection/1` still returns the peer connection's pid; the supervisor is not part of the API.
- `webrtc_lifecycle_SUITE` checks that close, owner exit, `kill` of the peer connection or a transport, and an application restart leave no process, port or table row behind.
