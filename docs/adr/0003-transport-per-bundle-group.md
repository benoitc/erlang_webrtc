# ADR 0003: One transport process per BUNDLE group

## Context

A WebRTC session usually multiplexes all its media and data on one network path, a BUNDLE group (RFC 9143). It does not have to: an offer can have several groups, or sections outside any group, and each of them then has its own ICE credentials, candidates, DTLS association and SRTP keys (RFC 9429 §5.2.1).

Media is sent and received at packet rate, while signaling (offers, answers, candidates) is rare. Putting both in one process would make each wait for the other.

## Decision

- A transport is one process, `webrtc_transport`, per BUNDLE group or unbundled section: one ICE agent, one DTLS association, its SRTP contexts, its media session and its SCTP association.
- The peer connection process (`webrtc_pc`) handles signaling, starts one transport per group from the negotiated description, and aggregates their states into the connection state.
- Media and data calls find their transport by peer connection and mid in the `webrtc_transports` table and call it directly, without going through `webrtc_pc`.

## Consequences

- With BUNDLE, the default, a peer connection has exactly one transport. `bundle => false` offers every section on its own transport.
- RTP forwarding between peer connections goes from one transport process to another; signaling never blocks it.
- An ICE restart restarts every transport of the peer connection.
- The table of transports has to be kept in step with the processes, which is the job of `webrtc_registry` (see [ADR 0005](0005-per-peer-supervision.md)).
