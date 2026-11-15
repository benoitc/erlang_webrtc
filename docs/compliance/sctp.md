# SCTP (RFC 9260, RFC 3758, RFC 6525, RFC 8260, RFC 8261, RFC 9653)

SCTP runs over DTLS application data (RFC 8261) and is implemented by the sans-IO engine `webrtc_sctp_assoc` with its internal modules: `webrtc_sctp_handshake` (setup, cookies, OOTB), `webrtc_sctp_send` and `webrtc_sctp_pr` (queues, scheduler, PR-SCTP), `webrtc_sctp_ack` (SACK processing, RTO, congestion control), `webrtc_sctp_recv` (TSN tracking, SACK generation, reassembly), `webrtc_sctp_reconfig` (RFC 6525), `webrtc_sctp_cookie`, `webrtc_sctp_out` (bundling). The codec is `webrtc_sctp_chunk`, `webrtc_sctp_param` and `webrtc_sctp_crc32c`. Engine tests run two engines over the seeded lossy in-memory network of `test/webrtc_sctp_net.erl`; "assoc" below means `webrtc_sctp_assoc_tests`, "prop" means `prop_webrtc_sctp`.

## RFC 9260 (base protocol)

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| SCTP-1 | 3.1, 6.8, App. A | Common header; CRC32c over the packet with the checksum field zeroed, stored little endian; bad checksum discarded | webrtc_sctp_chunk, webrtc_sctp_crc32c | webrtc_sctp_crc32c_tests, assoc:bad_checksum_test | Unit tested |
| SCTP-2 | 3.1 | Packets with other source or destination ports are discarded | webrtc_sctp_assoc | | Implemented, untested |
| SCTP-3 | 3.2 | Chunk length >= 4, padding to 4 bytes, no more than 3 pad bytes; truncated or inconsistent chunks rejected | webrtc_sctp_chunk | webrtc_sctp_chunk_tests (all truncations), prop:prop_decode_never_crashes | Unit tested |
| SCTP-4 | 3.2 | Unrecognized chunk types handled by the upper two bits (stop, stop and report, skip, skip and report) | webrtc_sctp_assoc | assoc:unknown_chunk_test | Unit tested |
| SCTP-5 | 3.2.1, 3.2.2 | Unrecognized INIT parameters handled by the upper two bits and reported in INIT ACK | webrtc_sctp_handshake | assoc:init_validation_test | Unit tested |
| SCTP-6 | 3.2.2 | Unrecognized INIT ACK parameters reported in an ERROR chunk bundled with COOKIE ECHO | webrtc_sctp_handshake | | Implemented, untested |
| SCTP-7 | 3.3.2, 3.3.3 | INIT with Initiate Tag 0 silently discarded; OS or MIS 0 answered with ABORT (Invalid Mandatory Parameter); INIT ACK without State Cookie aborted (Missing Mandatory Parameter) | webrtc_sctp_handshake | assoc:init_validation_test | Unit tested |
| SCTP-8 | 3.3.10 | All ERROR causes encoded and decoded | webrtc_sctp_param | webrtc_sctp_chunk_tests, prop:prop_tlv_roundtrip | Unit tested |
| SCTP-9 | 5.1 | Four-way handshake, T1-init and T1-cookie with Max.Init.Retransmits | webrtc_sctp_handshake | assoc:handshake_test, assoc:handshake_timeout_test | Unit tested |
| SCTP-10 | 5.1.3, 5.1.5 | State Cookie with HMAC-SHA256 and lifetime; responder keeps no state until COOKIE ECHO; forged cookies discarded | webrtc_sctp_cookie | assoc:init_validation_test, assoc:bad_cookie_test | Unit tested |
| SCTP-11 | 5.2.1 | INIT in COOKIE-WAIT / COOKIE-ECHOED answered with the original tag (simultaneous open as used by WebRTC) | webrtc_sctp_handshake | assoc:simultaneous_init_test, prop:prop_reliable_delivery | Unit tested |
| SCTP-12 | 5.2.2 | Unexpected INIT in an established association: new tag, tie-tags in cookie, TCB unchanged | webrtc_sctp_handshake | assoc:peer_restart_test | Unit tested |
| SCTP-13 | 5.2.4 | COOKIE ECHO with an existing TCB, Table 12 actions A (restart), B, D | webrtc_sctp_handshake | assoc:peer_restart_test, assoc:simultaneous_init_test | Unit tested |
| SCTP-14 | 5.2.4 | Table 12 action C (late cookie discarded) | webrtc_sctp_handshake | | Implemented, untested |
| SCTP-15 | 5.2.4 | Restart while in SHUTDOWN-ACK-SENT: resend SHUTDOWN ACK and ERROR "Cookie Received While Shutting Down" | webrtc_sctp_handshake | | Implemented, untested |
| SCTP-16 | 5.2.6 | Stale Cookie ERROR, retried with a Cookie Preservative (alternative 3) | webrtc_sctp_handshake | assoc:stale_cookie_test | Unit tested |
| SCTP-17 | 5.3.1 | Verification tags and initial TSNs random (crypto:strong_rand_bytes/1, seedable for tests) | webrtc_sctp_handshake | | Implemented, untested |
| SCTP-18 | 6.1 A | Peer rwnd respected; zero window probing after one RTO with exponential backoff | webrtc_sctp_send | assoc:zero_window_test, assoc:receive_window_test | Unit tested |
| SCTP-19 | 6.1 B, D | cwnd with one packet of overbooking; Max.Burst | webrtc_sctp_send | assoc:loss_10_test_, assoc:loss_30_test_ | Unit tested |
| SCTP-20 | 6.1 C | Retransmissions sent before new data | webrtc_sctp_send | assoc:loss_30_test_ | Unit tested |
| SCTP-21 | 6.1 | SACK bundled with outgoing DATA when an acknowledgement is pending | webrtc_sctp_out | | Implemented, untested |
| SCTP-22 | 6.2 | Delayed SACK within SACK.Delay (200 ms, at most 500), at least every second packet, immediately on gaps, duplicates or the I bit (RFC 7053) | webrtc_sctp_recv | assoc:delayed_sack_test | Unit tested |
| SCTP-23 | 6.2 | Receive window: data beyond the highest TSN dropped when the window is closed; a_rwnd advertised from buffered bytes | webrtc_sctp_recv | assoc:receive_window_test | Unit tested |
| SCTP-24 | 6.2 | DATA without user data answered with ABORT (No User Data) | webrtc_sctp_recv | assoc:no_user_data_test | Unit tested |
| SCTP-25 | 6.2.1 | SACK processing: out of order SACK dropped, gap blocks, reneging, rwnd update | webrtc_sctp_ack | assoc:loss_30_test_, prop:prop_reliable_delivery | Unit tested |
| SCTP-26 | 6.3.1 | RTO from SRTT/RTTVAR, Karn's rule, one measurement per round trip, RTO.Min / RTO.Max | webrtc_sctp_ack | assoc:heartbeat_failure_test (SRTT from heartbeats) | Unit tested |
| SCTP-27 | 6.3.2, 6.3.3 | T3-rtx rules R1 to R4, backoff, retransmission of the earliest chunks | webrtc_sctp_ack, webrtc_sctp_send | assoc:retransmission_limit_test, assoc:loss_30_test_ | Unit tested |
| SCTP-28 | 6.5 | DATA on an invalid stream acknowledged and reported with "Invalid Stream Identifier" | webrtc_sctp_recv | assoc:invalid_stream_test | Unit tested |
| SCTP-29 | 6.6 | Ordered and unordered delivery per stream | webrtc_sctp_recv | assoc:ordered_delivery_with_reordering_test, assoc:unordered_delivery_test | Unit tested |
| SCTP-30 | 6.7 | Gap Ack Blocks and Duplicate TSNs reported, bounded by the MTU | webrtc_sctp_recv | assoc:fast_retransmit_test, assoc:loss_30_test_ | Unit tested |
| SCTP-31 | 6.9 | Fragmentation to the configured MTU and reassembly (TSN based for DATA) | webrtc_sctp_send, webrtc_sctp_recv | assoc:large_message_test, assoc:large_message_small_mtu_test, assoc:unordered_fragmented_test | Unit tested |
| SCTP-32 | 6.10 | Bundling of control and data chunks up to the MTU | webrtc_sctp_out | assoc:many_streams_test_ (no MTU violation) | Unit tested |
| SCTP-33 | 7.2.1, 7.2.2 | Slow start (initial cwnd per §7.2.1, L = 1) and congestion avoidance with partial_bytes_acked | webrtc_sctp_ack | assoc:loss_10_test_ | Unit tested |
| SCTP-34 | 7.2.3, 7.2.4 | Fast retransmit on three miss indications (HTNA), fast recovery, one packet ignoring cwnd | webrtc_sctp_ack, webrtc_sctp_send | assoc:fast_retransmit_test | Unit tested |
| SCTP-35 | 7.2.1 | cwnd decay while the sender is idle: halved per RTO without data, not below 4 MTUs, applied when data starts again | webrtc_sctp_send | webrtc_sctp_assoc_tests:idle_cwnd_decay_test | Unit tested |
| SCTP-36 | 7.3, RFC 8899 §4, §5, §6.2 | Path MTU discovery (PLPMTUD): from the base size (`mtu`), once established, HEARTBEAT and PAD probes of three sizes up to `max_mtu`, three unanswered probes end the search below that size, probe loss does not count toward Association.Max.Retrans, a retransmission timeout above the base goes back to it, the search is repeated every 600 s | webrtc_sctp_pmtu | webrtc_sctp_assoc_tests:pmtu_search_test, pmtu_no_limit_test, pmtu_off_test, pmtu_black_hole_test (a large message across the fall back), pmtu_chunks_stay_base_test, webrtc_impairment_SUITE:path_mtu_1400 | E2E tested; DATA chunks are always cut for the base size, so a fall back never strands one (a chunk keeps its size once sent): larger packets bundle more chunks |
| SCTP-37 | 6.4, 8.2 | Multi-homing and path failover | | | Non-compliant / known limitation: one path only; SCTP over DTLS is single-homed (RFC 8261 §6.1) |
| SCTP-38 | 8.1 | Association.Max.Retrans: association closed after too many consecutive errors (T3, heartbeats, T2, RE-CONFIG) | webrtc_sctp_assoc | assoc:retransmission_limit_test | Unit tested |
| SCTP-39 | 8.3 | HEARTBEAT on an idle path, HEARTBEAT ACK echoes the info, RTT sample, configurable or disabled | webrtc_sctp_assoc | assoc:heartbeat_failure_test | Unit tested |
| SCTP-40 | 8.4 | Out of the blue packets: ABORT and SHUTDOWN COMPLETE with T bit, silent cases | webrtc_sctp_handshake | assoc:ootb_test | Unit tested |
| SCTP-41 | 8.5, 8.5.1 | Verification tag checks, INIT alone with tag 0, ABORT / SHUTDOWN COMPLETE T bit rules | webrtc_sctp_assoc | assoc:bad_vtag_test, assoc:init_validation_test | Unit tested |
| SCTP-42 | 9.1 | ABORT with User-Initiated Abort cause | webrtc_sctp_assoc | assoc:abort_test | Unit tested |
| SCTP-43 | 9.2 | Graceful shutdown: queued data delivered, T2-shutdown, SHUTDOWN in reply to DATA in SHUTDOWN-SENT, SHUTDOWN COMPLETE | webrtc_sctp_assoc | assoc:shutdown_test, assoc:shutdown_lossy_test | Unit tested |
| SCTP-44 | 9.2 | T5-shutdown-guard | | | Not implemented (MAY) |
| SCTP-45 | 12.2.4.2 | SACK acknowledging a TSN never sent aborts the association | webrtc_sctp_ack | assoc:sack_unsent_tsn_test | Unit tested |
| SCTP-46 | 6.1 | Sender silly window avoidance: no DATA chunk is sent into a window smaller than it | webrtc_sctp_send | | Implemented, untested |
| SCTP-47 | 6.2 | Receiver window update SACKs when the application consumes data | | | Non-compliant / known limitation: complete messages are handed to the owner on arrival, so the window only depends on fragments and out of order messages and no separate window update is needed |
| SCTP-48 | RFC 7053 | Sender sets the I bit | | | Not implemented (receive side honours it) |
| SCTP-49 | | ECN, AUTH (RFC 4895), ASCONF (RFC 5061 beyond Supported Extensions) | | | Not implemented (not required by RFC 8831) |
| SCTP-50 | | Robustness: random chunks with a valid tag never crash an established association | webrtc_sctp_assoc | prop:prop_engine_never_crashes | Unit tested |

## RFC 3758 and RFC 7496 (partial reliability)

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| PR-1 | 3.1, 3.3 | Forward-TSN-Supported parameter and FORWARD TSN in Supported Extensions | webrtc_sctp_handshake | assoc:handshake_test | Unit tested |
| PR-2 | 3.2 | FORWARD TSN chunk format | webrtc_sctp_chunk | webrtc_sctp_chunk_tests | Unit tested |
| PR-3 | 3.5 A1 to A3 | Abandoned chunks are no longer outstanding, not credited to cwnd, all fragments of the message abandoned (including unsent ones) | webrtc_sctp_pr | assoc:pr_ordered_max_retransmits_test, assoc:pr_lifetime_loss_test | Unit tested |
| PR-4 | 3.5 C1 to C5, A5 | Advanced.Peer.Ack.Point, FORWARD TSN with the highest SSN per ordered stream, T3 kept running until the FORWARD TSN is acknowledged (also when a SACK leaves nothing in flight), repeated at most once per RTO | webrtc_sctp_pr, webrtc_sctp_ack | assoc:pr_max_retransmits_test, assoc:pr_forward_tsn_lost_test, webrtc_impairment_SUITE:unreliable_channel_under_loss | E2E tested |
| PR-5 | 3.5 C4 | Lower the Advanced.Peer.Ack.Point when the FORWARD TSN does not fit one MTU | | | Not implemented (only reachable with more than about 290 streams abandoning messages at once) |
| PR-6 | 3.6 | Receiver: cumulative TSN moved, stranded fragments removed, ordered streams skipped and waiting messages delivered | webrtc_sctp_recv | assoc:pr_ordered_max_retransmits_test (window fully restored) | Unit tested |
| PR-7 | 4 | Timed reliability (lifetime in ms from the send call), checked before first transmission and before retransmission | webrtc_sctp_send | assoc:pr_lifetime_test, assoc:pr_lifetime_loss_test | Unit tested |
| PR-8 | RFC 7496 §3.1 | Limited retransmissions policy, including 0 retransmissions | webrtc_sctp_send | assoc:pr_max_retransmits_test | Unit tested |

## RFC 6525 (stream reconfiguration)

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| RC-1 | 3, 4 | RE-CONFIG chunk and parameters 13 to 18 | webrtc_sctp_param | webrtc_sctp_chunk_tests | Unit tested |
| RC-2 | 5.1.1 | Support negotiated through Supported Extensions; one request in flight; timer with RTO backoff counted in the error counter | webrtc_sctp_reconfig | assoc:stream_reset_lossy_test_ | Unit tested |
| RC-3 | 5.1.2 | Outgoing SSN Reset Request: new messages held, Sender's Last Assigned TSN, request sent once queued messages have TSNs, stream ids limited to one packet | webrtc_sctp_reconfig, webrtc_sctp_send | assoc:stream_reset_test, assoc:many_streams_test_ | Unit tested |
| RC-4 | 5.2.1 | Request sequence numbers, retransmitted request answered again, bad sequence number | webrtc_sctp_reconfig | assoc:reconf_requests_test | Unit tested |
| RC-5 | 5.2.2 | Incoming Outgoing SSN Reset: deferred until the last TSN arrives ("In progress"), held chunks replayed, success response | webrtc_sctp_reconfig, webrtc_sctp_recv | assoc:stream_reset_deferred_test, assoc:reconf_deferred_requests_test | Unit tested |
| RC-6 | 5.2.3 | Incoming SSN Reset Request answered with an Outgoing SSN Reset Request | webrtc_sctp_reconfig | assoc:reconf_requests_test | Unit tested |
| RC-7 | 5.2.4 | SSN/TSN Reset Request | webrtc_sctp_reconfig | assoc:reconf_requests_test | Non-compliant / known limitation: always answered "Denied" (allowed by §5.2.1) |
| RC-8 | 5.2.5 | Add Outgoing Streams accepted up to 65535 incoming streams | webrtc_sctp_reconfig | assoc:reconf_requests_test | Unit tested |
| RC-9 | 5.2.6 | Add Incoming Streams | webrtc_sctp_reconfig | assoc:reconf_requests_test | Non-compliant / known limitation: always answered "Denied" |
| RC-10 | 5.2.7 | Responses: success resets the streams, "In progress" restarts the timer without counting an error, failures release held data | webrtc_sctp_reconfig | assoc:stream_reset_deferred_test | Unit tested |
| RC-11 | 5.1.3 | Sending Incoming SSN Reset, SSN/TSN Reset and Add Streams requests | | | Not implemented (WebRTC only needs outgoing resets) |
| RC-12 | 5.2.2 E3 | An Outgoing SSN Reset Request with no stream numbers resets every incoming stream, including when no stream has state | webrtc_sctp_recv | webrtc_sctp_recv_tests:reset_all_without_state_test_, assoc:reconf_reset_all_streams_empty_test_, reconf_reset_all_streams_with_state_test_ | Unit tested |

## RFC 8260 (message interleaving)

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| ID-1 | 2.1 | I-DATA chunk format (MID, PPID or FSN) | webrtc_sctp_chunk | webrtc_sctp_chunk_tests | Unit tested |
| ID-2 | 2.2.1 | Used only when both sides list I-DATA (and I-FORWARD-TSN); offered only with the `interleaving` option | webrtc_sctp_handshake | assoc:interleaving_test, assoc:no_interleaving_test | Unit tested |
| ID-3 | 2.2.2 | Late TSN assignment, one message per stream at a time, separate ordered and unordered MID counters | webrtc_sctp_send | assoc:interleaving_lossy_test_, assoc:stream_reset_interleaving_test | Unit tested |
| ID-4 | 2.2.3 | Reassembly by stream, U bit, MID and FSN; DATA and I-DATA mixed abort the association | webrtc_sctp_recv | assoc:interleaving_lossy_test_, assoc:idata_without_negotiation_test | Unit tested |
| ID-5 | 2.3.1 | I-FORWARD-TSN for ordered and unordered messages; FORWARD TSN with I-DATA aborts | webrtc_sctp_pr, webrtc_sctp_recv | assoc:interleaving_pr_test, assoc:forward_tsn_with_idata_test | Unit tested |
| ID-6 | 2.3.2 | Stream reset resets both MID counters | webrtc_sctp_send | assoc:stream_reset_interleaving_test | Unit tested |
| ID-7 | 3.2, 3.6 | Weighted fair queueing between streams (per fragment with I-DATA, per message with DATA); equal weights share by bytes | webrtc_sctp_send | assoc:wfq_interleaved_test, wfq_data_test, wfq_equal_test, interleaving_test | Unit tested |
| ID-8 | 3.1, 3.3 to 3.5 | First come first served, strict priority and fair bandwidth schedulers | | | Not implemented: weighted fair queueing (3.6) is the one used |

## RFC 8261 (SCTP over DTLS)

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| DT-1 | 3 | Each SCTP packet is one DTLS application data record (`{send, Bin}` action, `handle_packet/3` input) | webrtc_sctp_assoc | all engine tests | Unit tested |
| DT-2 | 5 | Safe SCTP packet size: the base is 1200 bytes minus the DTLS record overhead of the negotiated version, suite and CID; larger only once PLPMTUD confirmed it | webrtc_sctp_assoc | assoc:large_message_test, assoc:large_message_small_mtu_test (MTU checked on every packet) | Unit tested |
| DT-3 | 6.1 | Single-homed association, no reliance on ICMP | webrtc_sctp_assoc | | Implemented, untested |
| DT-4 | 6.1 | INIT and INIT ACK carry no IPv4 / IPv6 Address and no Supported Address Types parameters | webrtc_sctp_handshake | assoc:init_validation_test | Unit tested |
| DT-5 | 6.1 | Associations multiplexed over one DTLS connection by SCTP port; packets for other ports discarded | webrtc_sctp_assoc | | Implemented, untested (one engine per association, the owner demultiplexes) |
| DT-6 | 6.1 | On a lower layer path change (ICE selects another pair, or restarts), back to the base path MTU and a new search, initial cwnd and ssthresh, initial RTO and a new RTT estimate | webrtc_sctp_assoc, webrtc_dcep, webrtc_transport_secure | webrtc_sctp_assoc_tests:path_changed_test | Unit tested |
| DT-7 | 6.2 | PAD chunk for PMTU probes: a HEARTBEAT and a PAD chunk make each probe exactly the probed size | webrtc_sctp_pmtu, webrtc_sctp_chunk | webrtc_sctp_chunk_tests, webrtc_sctp_assoc_tests:pmtu_search_test | Unit tested |
| DT-8 | 6.5, 6.6, 6.7 | Partial reliability, stream reset and interleaving extensions over DTLS | webrtc_sctp_assoc | see the RFC 3758, RFC 6525 and RFC 8260 tables | Unit tested |

## RFC 9653 (zero checksum)

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| ZC-1 | 4 | Zero Checksum Acceptable parameter (EDMID 1, SCTP over DTLS) | webrtc_sctp_param | webrtc_sctp_chunk_tests | Unit tested |
| ZC-2 | 5.1 | Announced only when the upper layer allows it (`zero_checksum` option); the WebRTC transport, always over DTLS, enables it | webrtc_sctp_handshake, webrtc_transport | assoc:zero_checksum_one_side_test, the E2E and interop data channel suites | Interoperability tested |
| ZC-3 | 5.2 | Zero checksum sent only after the peer announced DTLS; INIT, INIT ACK, COOKIE ECHO and OOTB responses keep a correct CRC32c | webrtc_sctp_out, webrtc_sctp_handshake | assoc:zero_checksum_test | Unit tested |
| ZC-4 | 5.3 | Zero checksum accepted only after announcing it, correct CRC32c always accepted | webrtc_sctp_assoc | assoc:bad_checksum_test, assoc:zero_checksum_test | Unit tested |
