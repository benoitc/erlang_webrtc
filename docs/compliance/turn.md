# TURN client (RFC 8656)

This page lists the client-side TURN requirements implemented by `webrtc_turn_client` (UDP, TCP or TLS to the server) and its use by the ICE agent for relayed candidates. Read it before relying on a relay feature. There is no TURN server in the stack; tests run against the test-only server `test/webrtc_test_turn_server.erl`.

## Client

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| TURN-1 | 5 | STUN-formatted messages over UDP with FINGERPRINT; SOFTWARE in Allocate and Refresh | webrtc_turn_client | webrtc_turn_client_tests:allocate_md5_test | Unit tested |
| TURN-2 | 5, RFC 8489 6.2.1 | Request retransmission over UDP, RTO cached per server | webrtc_turn_client, webrtc_stun_tx | webrtc_turn_client_tests:allocate_timeout_test | Unit tested |
| TURN-3 | 7.1 | REQUESTED-TRANSPORT UDP on Allocate; LIFETIME and REQUESTED-ADDRESS-FAMILY when configured | webrtc_turn_client | webrtc_turn_client_tests:allocate_md5_test | Unit tested (the `family` option is implemented, untested) |
| TURN-4 | RFC 8489 9.2.3.1 | First Allocate sent without credentials | webrtc_turn_client | webrtc_turn_client_tests:allocate_md5_test | Unit tested |
| TURN-5 | RFC 8489 9.2.5 | 401 with REALM and NONCE retried once with USERNAME, REALM, NONCE and MESSAGE-INTEGRITY (MD5 key); a second 401 fails | webrtc_turn_client, webrtc_turn_auth | webrtc_turn_client_tests:allocate_md5_test, wrong_password_test | Unit tested |
| TURN-6 | RFC 8489 9.2.5 | PASSWORD-ALGORITHMS echoed, first supported algorithm in PASSWORD-ALGORITHM, MESSAGE-INTEGRITY-SHA256 only afterwards | webrtc_turn_auth | webrtc_turn_client_tests:allocate_sha256_test, auth_algorithm_test_ | Unit tested |
| TURN-7 | RFC 8489 9.2.1 | Nonce cookie: "password algorithms" bit without PASSWORD-ALGORITHMS stops the retry | webrtc_turn_auth | webrtc_turn_client_tests:challenge_with_cookie_without_algorithms_test | Unit tested |
| TURN-8 | RFC 8489 9.2.4 | USERHASH (username anonymity) | webrtc_turn_auth | webrtc_turn_client_tests:auth_algorithm_test_ | Not implemented: a nonce cookie asking for it fails the allocation with `{unsupported, userhash}` |
| TURN-9 | RFC 8489 9.2.5 | 438 retried with the new nonce, at most 3 times in a row, for every request | webrtc_turn_client | webrtc_turn_client_tests:stale_nonce_test, refresh_stale_nonce_test | Unit tested |
| TURN-10 | RFC 8489 9.2.5 | Responses to authenticated requests discarded unless integrity verifies (401 and 438 excepted); unprotected 400 discarded | webrtc_turn_auth | webrtc_turn_client_tests:unauthenticated_success_discarded_test | Unit tested |
| TURN-11 | 7.3 | Relayed address, mapped address and the lifetime granted by the server kept | webrtc_turn_client | webrtc_turn_client_tests:allocate_md5_test | Unit tested |
| TURN-12 | 7.4 | 403, 440, 441, 442, 486, 508 fail the allocation and are reported; no automatic retry | webrtc_turn_client | webrtc_turn_client_tests:allocate_errors_test_ | Unit tested |
| TURN-13 | 7.4 | 300 Try Alternate: the allocation is retried against the ALTERNATE-SERVER with the same credentials, at most three redirections and never back to a server already tried | webrtc_turn_client, webrtc_ice_relay | webrtc_turn_client_tests:try_alternate_test, webrtc_ice_agent_tests:turn_try_alternate_test, turn_alternate_loop_test | Unit tested |
| TURN-14 | 7.4 | 437 on Allocate over UDP: the agent asks its owner for a new local port (`{open_udp, Ref, #{local := IP}}`) and allocates from it, once per server | webrtc_ice_relay, webrtc_ice_agent, webrtc_transport_net | webrtc_ice_agent_tests:turn_allocation_mismatch_test | Unit tested |
| TURN-15 | 7.4 | Allocate timeout reported | webrtc_turn_client | webrtc_turn_client_tests:allocate_timeout_test | Unit tested |
| TURN-16 | 8 | Refresh one minute before expiry (half the lifetime when shorter than two minutes) | webrtc_turn_client | webrtc_turn_client_tests:refresh_test, short_lifetime_refresh_test | Unit tested |
| TURN-17 | 8.3 | 437 to a Refresh: allocation lost; to a deletion: success | webrtc_turn_client | webrtc_turn_client_tests:unauthenticated_success_discarded_test, deallocate_test | Unit tested |
| TURN-18 | 8 | Allocation lost when it expires without a successful Refresh | webrtc_turn_client | webrtc_turn_client_tests:expiry_without_refresh_test | Unit tested |
| TURN-19 | 8.1 | Deallocation with a Refresh of LIFETIME 0 | webrtc_turn_client | webrtc_turn_client_tests:deallocate_test | Unit tested |
| TURN-20 | 9, 10.1 | CreatePermission per peer IP (XOR-PEER-ADDRESS, port ignored), refreshed every 240 s (lifetime 300 s) | webrtc_turn_client | webrtc_turn_client_tests:send_creates_permission_test, permission_refresh_test | Unit tested |
| TURN-21 | 10.3 | Permission errors reported, data queued for the peer dropped | webrtc_turn_client | webrtc_turn_client_tests:forbidden_permission_test | Unit tested |
| TURN-22 | 11.1 | Send indication (XOR-PEER-ADDRESS, DATA) only once the permission is installed; data queued meanwhile (bounded) | webrtc_turn_client | webrtc_turn_client_tests:send_creates_permission_test | Unit tested |
| TURN-23 | 11.4 | Data indication needs XOR-PEER-ADDRESS, a permission for the peer IP and DATA | webrtc_turn_client | webrtc_turn_client_tests:data_indication_checks_test, send_creates_permission_test | Unit tested |
| TURN-24 | 11.6 | ICMP attribute in Data indications | | | Not implemented: such indications are ignored |
| TURN-25 | 12 | Channel numbers 0x4000 to 0x4FFF, one per peer | webrtc_turn_client | webrtc_turn_client_tests:channel_test | Unit tested |
| TURN-26 | 12.1, 12.3 | ChannelBind installs the channel and refreshes the permission; rebound every 540 s (lifetime 600 s) | webrtc_turn_client | webrtc_turn_client_tests:channel_test, channel_refresh_test | Unit tested |
| TURN-27 | 12 | 5 minutes before reusing a channel number or peer after expiry | webrtc_turn_client | webrtc_turn_client_tests:lost_channel_bind_test | Unit tested: bindings in use are refreshed and never expire while the allocation lives; a number whose ChannelBind failed (possibly installed on the server) and its peer are kept apart for 15 minutes (lifetime plus 5), the same peer getting the number back |
| TURN-28 | 12.3 | ChannelBind failure out of sync (400): delete the allocation | webrtc_turn_client | webrtc_turn_client_tests:channel_out_of_sync_test | Unit tested: the allocation is deleted (Refresh with LIFETIME 0) and reported as `{allocation_lost, channel_out_of_sync}`; the ICE agent removes the relayed candidate |
| TURN-29 | 12.4, 12.5 | ChannelData framing, padded to 4 bytes over UDP; Send indications until the binding is confirmed | webrtc_turn_channel, webrtc_turn_client | webrtc_turn_client_tests:channel_test, channel_codec_test_ | Unit tested |
| TURN-30 | 12.6 | ChannelData discarded on reserved numbers, short datagrams, unbound channels or without permission | webrtc_turn_channel, webrtc_turn_client | webrtc_turn_client_tests:channel_codec_test_, channel_data_unknown_channel_test | Unit tested |
| TURN-31 | 21 | Truncated or bit-flipped server messages never crash the client | webrtc_turn_client | webrtc_turn_client_tests:malformed_input_test | Unit tested |
| TURN-32 | 3.1 | TCP and TLS-over-TCP to the server (`transport` of `turn_servers`): STUN and ChannelData framed on the stream, ChannelData padded to 4 bytes, bytes out of step close the connection; no request retransmission on the stream (RFC 8489 §6.2.2, 39.5 s timeout); TLS server certificate verified against the system CA store and the host name or IP address | webrtc_turn_stream, webrtc_ice_relay, webrtc_transport_net | webrtc_turn_stream_tests, webrtc_ice_agent_tests:stream_turn_test, stream_turn_connect_failure_test, webrtc_turn_interop_SUITE:relayed_over_tcp, relayed_over_tls, untrusted_tls_no_relay | Interoperability tested (pion/turn) |
| TURN-36 | 3.1 | DTLS-over-UDP to the server | | | Not implemented: not used by browsers |
| TURN-33 | 7.1 | ADDITIONAL-ADDRESS-FAMILY, EVEN-PORT, RESERVATION-TOKEN, DONT-FRAGMENT | | | Not implemented (optional) |
| TURN-34 | 4, RFC 5928 | Server discovery through DNS: see URI-1 to URI-8 | webrtc_ice_resolve | webrtc_ice_uri_tests | Unit and interoperability tested |
| TURN-35 | RFC 8489 9.2.2 | OpaqueString processing of the realm and password | | | Non-compliant / known limitation: used as given, see STUN-16 |

## ICE integration

The ICE agent owns one `webrtc_turn_client` per (host socket, TURN server) and allocates from every host candidate whose family matches the server. For a server reached over TCP or TLS the agent asks its owner to open a connection from the host address (`{connect, {stream, N}, Params}`), which then plays the role of the host socket; the owner reports it with `stream_up/3` and `stream_down/4`. A relayed candidate is reached through the path `{relay, Socket, ServerAddr}`: checks, consent requests and data sent from it are wrapped by the client and sent to the server over the host socket; datagrams from the server are unwrapped and fed back to the check processing, or emitted as `{data, Via, Peer, Data}` when they are not STUN.

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| TURN-I1 | RFC 8445 5.1.1.2 | Relayed and server-reflexive candidates from a successful Allocate; relay identical to a host candidate discarded | webrtc_ice_relay | webrtc_ice_net_tests:srflx_candidate_test | Unit tested |
| TURN-I2 | RFC 8445 7.2.1 | Permissions for every remote candidate of the relay's family | webrtc_ice_relay | webrtc_ice_net_tests:symmetric_needs_relay_test | Unit tested |
| TURN-I3 | RFC 8445 7.3.1.2 | Requests relayed by the server answered with the peer address the server saw | webrtc_ice_relay | webrtc_ice_net_tests:symmetric_needs_relay_test | Unit tested |
| TURN-I4 | | Channel bound to the peer of a selected relayed pair | webrtc_ice_relay | webrtc_ice_net_tests:symmetric_needs_relay_test | Unit tested |
| TURN-I5 | | Lost allocation removes the relayed candidate and its pairs (`{local_candidate_removed, C}`, `{turn_error, Server, Reason}`) | webrtc_ice_relay | webrtc_ice_net_tests:turn_allocation_lost_test | Unit tested |
| TURN-I6 | | Allocations deleted when the agent closes | webrtc_ice_relay | webrtc_ice_net_tests:close_deletes_allocations_test | Unit tested |
| TURN-I7 | RFC 8445 5.1.2.1 | A relay reached over TCP or TLS has a lower local preference than one reached over UDP, and its own foundation | webrtc_ice_relay | webrtc_ice_agent_tests:stream_turn_test | Unit tested |
| TURN-I8 | | A stream that fails to open ends its gathering job; one that closes loses the allocation and its candidate (`{turn_error, Server, {stream, Reason}}`, `{allocation_lost, {stream, Reason}}`) | webrtc_ice_relay | webrtc_ice_agent_tests:stream_turn_test, stream_turn_connect_failure_test | Unit tested |

## Server URIs and discovery

The `ice_servers` option takes the W3C RTCIceServer list; its URIs are resolved when the peer connection starts (`webrtc_pc`), and the servers join `stun_servers` and `turn_servers`.

| ID | Spec | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| URI-1 | RFC 7064 §3.1 | stun and stuns URIs: host (IPv4, IPv6 in brackets, registered name with percent-encoding), optional port, default 3478 and 5349; no query | webrtc_ice_uri | rfc_examples_test_, hosts_test_, refused_test_ | Unit tested |
| URI-2 | RFC 7065 §3.1 | turn and turns URIs with `?transport=udp` or `tcp`; a transport-ext is refused as unsupported; default ports 3478 and 5349 | webrtc_ice_uri | rfc_examples_test_, unsupported_transport_test_ | Unit tested |
| URI-3 | RFC 7065 §3, RFC 5928 §3 | A URI without transport: UDP for turn, TLS over TCP for turns | webrtc_ice_uri | rfc_examples_test_ | Non-compliant / known limitation: the NAPTR lookup (RFC 5928 step 1, S-NAPTR) is not done, as in browsers |
| URI-4 | RFC 5928 §3 steps 1 to 3, RFC 8489 §8.1 | An IP address is used as is; a name with a port is looked up for A and AAAA (step 2); without a port, SRV `_turn._udp`, `_turn._tcp`, `_turns._tcp` or `_stun._udp` first (targets by priority, then weight), A and AAAA with the default port when there is none (step 3) | webrtc_ice_resolve | literal_test, explicit_port_test, srv_test, srv_names_test_ | Unit tested |
| URI-5 | RFC 8489 §8.1, RFC 8445 §5.1.1.2 | Both A and AAAA queried; the addresses tried | webrtc_ice_resolve | explicit_port_test | Non-compliant / known limitation: the first address of each family is used, matched to the host candidates of that family, and the first SRV target only; there is no fall back to the next one when the server does not answer (the agent takes eight servers at most) |
| URI-6 | RFC 8656 §3.1, RFC 6125 | turns: TLS to the server, the certificate checked against the name in the URI | webrtc_ice_resolve, webrtc_transport_net | webrtc_turn_interop_SUITE:relayed_by_uri_tls | Interoperability tested (pion/turn) |
| URI-7 | W3C webrtc-pc RTCIceServer | `urls` (one or several), `username` and `credential` required for TURN; a malformed list refuses the peer connection (`{badarg, ice_servers}`); a URI that cannot be used is reported as `{ice_server_error, Url, Reason}` and the others kept; eight servers in all at most | webrtc, webrtc_pc, webrtc_ice_uri | servers_test_, peer_connection_test_ | Unit tested |
| URI-8 | RFC 7064 §3.1, RFC 8489 §6.2.3 | stuns (STUN over TLS) | | servers_test_ | Not implemented: reported as unsupported; binding requests go over UDP |

Names resolve in parallel within `ice_server_timeout` (default 2 s), so starting a peer connection waits at most that long. A server given in `stun_servers` or `turn_servers` must be an IP address (`{badarg, {server_address, A}}` otherwise).

## Notes

- Specification status checked on 2026-11-14 at rfc-editor.org: RFC 8656 and RFC 8489 have no update or obsoleting document.
- Per-allocation state is bounded: data queued while a permission is pending (64 datagrams per peer IP), permissions and channels follow the remote candidates the ICE agent keeps (`max_remote`).

| ID | Spec | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| TURN-INTEROP-1 | 7, 9, 11 | Allocate with the 401 retry, permissions for remote candidates and relayed connectivity checks and data, against an independent server (pion/turn v5) | webrtc_turn_client, webrtc_ice_relay | webrtc_turn_interop_SUITE (relay/relay, relay/host, wrong password) | Interoperability tested |
| TURN-INTEROP-2 | 8 | Allocations deleted with a zero lifetime Refresh when the peer connection closes | webrtc_transport, webrtc_ice_relay | webrtc_security_SUITE:turn_allocation_deleted_on_close | E2E tested |
