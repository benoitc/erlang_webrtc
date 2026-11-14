# Transport, multiplexing and cross-layer requirements (RFC 7983, RFC 9443, RFC 8835, RFC 8842, RFC 8261)

| ID | Spec | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| TR-1 | 7983 §7, 9443 §3 | Demultiplex by first byte: STUN 0-3, DTLS 20-63, TURN ChannelData 64-79, RTP/RTCP 128-191, others dropped | webrtc_demux | webrtc_demux_tests | Unit tested |
| TR-2 | 8835 §3.4 | STUN, DTLS, SRTP and SCTP share one UDP 5-tuple per BUNDLE group | webrtc_transport | webrtc_pc_SUITE, webrtc_pc_interop_SUITE | Interoperability tested |
| TR-3 | 8445 §12.2, 8826 §4.2 | Media and DTLS only accepted from validated candidate pairs, direct or relayed through TURN | webrtc_transport | webrtc_security_SUITE:spoofed_traffic_dropped, webrtc_turn_interop_SUITE:relayed_spoofing_dropped | Interoperability tested |
| TR-4 | 7675 | No data sent without fresh consent | webrtc_ice_agent, webrtc_transport | webrtc_ice_net_tests (consent loss) | Unit tested |
| TR-5 | 8842 §4 | DTLS association kept across ICE restarts | webrtc_transport, webrtc_pc | webrtc_pc_SUITE:ice_restart | E2E tested |
| TR-6 | 8842 §5 | DTLS role from a=setup, client starts the handshake once ICE has a pair, early DTLS datagrams buffered (bounded) | webrtc_transport | webrtc_pc_SUITE, interop suites | Interoperability tested |
| TR-7 | 5764 §4.2 | SRTP keys exported from DTLS for the negotiated profile and role | webrtc_transport, webrtc_srtp | webrtc_pc_SUITE:audio_video_rtp, webrtc_pc_interop_SUITE media cases | Interoperability tested |
| TR-8 | 8261 §5 | SCTP packets fit in one DTLS record within a 1200 byte datagram | webrtc_transport | webrtc_impairment_SUITE:path_mtu_1200 | E2E tested |
| TR-9 | 8261 §6.1 | SCTP started over DTLS application data once DTLS is connected | webrtc_transport | webrtc_pc_SUITE | Interoperability tested |
| TR-10 | | Bounded reception: active-N sockets, bounded early buffers, bounded SCTP buffers | webrtc_transport | webrtc_security_SUITE:garbage_flood, unauthenticated_stun_flood | E2E tested |
| TR-11 | | Independent peer connections, no shared state on the packet path | webrtc_pc_sup, webrtc_transport | webrtc_pc_SUITE:concurrent_peer_connections | E2E tested |
| TR-12 | 8835 §3.2 | ICE-TCP and TURN over TCP/TLS | | | Not implemented |
| TR-13 | 8835 §3.5 | HTTP proxy traversal | | | Not implemented |
| TR-14 | 8421 | Multihomed and dual stack host candidates | webrtc_transport, webrtc_ice_candidate | webrtc_ice_net_tests | Unit tested |
| TR-15 | | A transport never outlives its peer connection: it monitors it, and close kills a transport that does not stop within 5 s (sockets, timers and TURN state released) | webrtc_pc, webrtc_transport | webrtc_security_SUITE:stuck_transport_killed_on_close | E2E tested |
| TR-16 | 5246 §7.2.1, 7675 | After DTLS close or failure the transport is finished: SRTP keys and SCTP dropped, ICE closed (no consent checks, TURN deleted), media and data calls return `{error, closed}` | webrtc_transport | webrtc_security_SUITE:nothing_sent_after_peer_close | E2E tested |
| TR-17 | | The API keeps no state in the calling process: transports are found in the `webrtc_transports` table owned by the application supervisor, rows removed when a transport stops; calls on a closed connection return `{error, closed}` | webrtc, webrtc_pc, webrtc_sup | webrtc_security_SUITE:no_state_in_caller | E2E tested |
