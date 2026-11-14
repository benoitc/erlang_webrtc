# Data channels (RFC 8831, RFC 8832, RFC 8841)

Data channels are implemented by `webrtc_dcep`: the DCEP codec and a sans-IO manager that owns the SCTP association (`webrtc_sctp_assoc`, see [sctp](sctp.md)) and exposes channels by stream id. Tests are in `webrtc_dcep_tests` ("dcep" below); some use a raw SCTP association as the peer to send messages the manager itself never produces. Parsing the SDP `a=max-message-size` and `a=sctp-port` attributes belongs to the SDP module and is tracked in [sdp](sdp.md).

## RFC 8831 (data channels)

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| DC-1 | 6.1 | SCTP over DTLS with partial reliability (timed and limited retransmissions), stream reconfiguration signalled in Supported Extensions | webrtc_sctp_assoc | webrtc_sctp_assoc_tests:handshake_test | Unit tested |
| DC-2 | 6.1 | Message interleaving (RFC 8260) SHOULD be used | webrtc_sctp_assoc | webrtc_sctp_assoc_tests:interleaving_test | Unit tested (offered only with the `interleaving` SCTP option, off by default like current browsers) |
| DC-3 | 6.2 | 65535 streams negotiated | webrtc_sctp_assoc | webrtc_sctp_assoc_tests:handshake_test | Unit tested |
| DC-4 | 6.2 | Graceful shutdown and abort of the association close every channel | webrtc_dcep | dcep:shutdown_closes_channels_test | Unit tested |
| DC-5 | 6.4 | Reliable or partially reliable (retransmissions or lifetime), ordered or unordered channels | webrtc_dcep | dcep:partial_reliability_channel_test, dcep:negotiated_test | Unit tested |
| DC-6 | 6.4 | Priority carried in DATA_CHANNEL_OPEN and reported | webrtc_dcep | dcep:open_vector_test | Unit tested |
| DC-7 | 6.4 | Priority interpreted as a weighted fair queueing weight by the SCTP scheduler | | | Non-compliant / known limitation: the scheduler is round robin between streams and ignores the priority |
| DC-8 | 6.5 | Channels negotiated out of band on an agreed stream id, without DCEP; reusing a stream of an existing channel fails | webrtc_dcep | dcep:negotiated_test, dcep:id_parity_test | Unit tested |
| DC-9 | 6.6 | One application message per SCTP user message; PPID 51 (string) and 53 (binary) | webrtc_dcep | dcep:open_ack_test | Unit tested |
| DC-10 | 6.6 | Empty messages sent as one zero byte with PPID 56 / 57 and delivered as empty | webrtc_dcep | dcep:empty_messages_test | Unit tested |
| DC-11 | 6.6 | Deprecated PPID 52 / 54 partial messages accepted on receive and joined, bounded by the local maximum message size | webrtc_dcep | dcep:legacy_partial_ppid_test | Unit tested |
| DC-12 | 6.6 | Unsupported PPID closes the channel | webrtc_dcep | dcep:unknown_ppid_closes_test | Unit tested |
| DC-13 | 6.6 | Without interleaving the sender SHOULD keep messages under 16 KB | | | Non-compliant / known limitation: not enforced, the application chooses the message size |
| DC-14 | 6.7 | Closing resets the outgoing stream; a peer reset is answered with our own reset; the channel is closed once both directions are reset and the id can be reused | webrtc_dcep | dcep:close_test, dcep:remote_close_test, dcep:close_lossy_test | Unit tested |
| DC-15 | 6.7 | Messages sent before the close are delivered before it | webrtc_dcep, webrtc_sctp_reconfig | dcep:close_test, dcep:close_lossy_test | Unit tested |
| DC-16 | 7 | A receiver copes with arbitrarily large messages: incoming messages are bounded by the SCTP `max_message_size` option (the advertised limit); a larger one closes its channel only, see MMS-5 | webrtc_sctp_recv, webrtc_dcep | webrtc_sctp_assoc_tests:too_large_*_test | Unit tested |

## RFC 8832 (DCEP)

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| DCEP-1 | 5.1 | DATA_CHANNEL_OPEN with the six channel types, priority, reliability parameter, label and protocol | webrtc_dcep | dcep:open_vector_test, dcep:all_channel_types_test | Unit tested |
| DCEP-2 | 5.1 | Malformed messages rejected (truncation, extra bytes, unknown channel type, invalid UTF-8) | webrtc_dcep | dcep:codec_errors_test | Unit tested |
| DCEP-3 | 5.2 | DATA_CHANNEL_ACK | webrtc_dcep | dcep:ack_test | Unit tested |
| DCEP-4 | 6 | DCEP messages sent ordered and reliable with PPID 50 on the channel's own stream | webrtc_dcep | dcep:legacy_partial_ppid_test (ACK seen by a raw SCTP peer) | Unit tested |
| DCEP-5 | 6 | The DTLS client picks even stream ids, the server odd ones | webrtc_dcep | dcep:id_parity_test | Unit tested |
| DCEP-6 | 6 | OPEN on a used stream, with the wrong parity or malformed: no ACK, the stream is reset | webrtc_dcep | dcep:wrong_parity_open_test, dcep:duplicate_open_test | Unit tested |
| DCEP-7 | 6 | The opener may send right after OPEN; user data goes ordered until the peer sent anything on the channel | webrtc_dcep | dcep:ordered_until_ack_test | Unit tested |
| DCEP-8 | 6 | User data on an unused stream: the stream is reset | webrtc_dcep | dcep:data_on_unused_stream_test | Unit tested |
| DCEP-9 | 6 | Channels opened before the association is up are announced once it is | webrtc_dcep | dcep:open_before_connect_test | Unit tested |
| DCEP-10 | 6 | A stream reset of a channel that was never acknowledged reports the setup failure | webrtc_dcep | dcep:wrong_parity_open_test (raw peer side) | Unit tested |

## RFC 8841 (max-message-size)

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| MMS-1 | 6.1 | Never send a message larger than the peer's max-message-size | webrtc_dcep | dcep:max_message_size_test | Unit tested |
| MMS-2 | 6.1 | Default of 64K when the attribute is absent, 0 means no limit | webrtc_dcep | dcep:max_message_size_test | Unit tested |
| MMS-3 | 6.1 | Our own limit advertised in SDP is the one the SCTP association enforces; the receive window holds at least two such messages; 0 is never advertised (we always have a memory bound) | webrtc_transport, webrtc_jsep, webrtc_sctp_assoc | webrtc_pc_SUITE:max_message_size_wired | E2E tested |
| MMS-5 | 6.1 | A received message over our limit, on any receive path (single chunk, fragmented, unordered DATA, PPID-based partial), closes that channel only (stream reset, `datachannel_error` event); later data on the stream is dropped until the reset | webrtc_sctp_recv, webrtc_dcep | webrtc_sctp_assoc_tests:too_large_*_test, webrtc_dcep_tests:oversize_closes_channel_only_test | Unit tested |
| MMS-4 | 6.2 | SDP attribute syntax | webrtc_sdp | | Not implemented |
