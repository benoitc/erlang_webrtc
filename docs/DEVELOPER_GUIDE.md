# Change the code

This page is for you if you want to change erlang_webrtc: fix a bug, add a protocol feature, or follow a packet through the stack. It maps each part of WebRTC to the directory, modules and tests that implement it, states the rules every module follows, and gives step by step recipes for the common changes. Read [CONCEPTS.md](CONCEPTS.md) and [ARCHITECTURE.md](ARCHITECTURE.md) first; [CONTRIBUTING.md](../CONTRIBUTING.md) says how to send your change.

## Start here

1. [CONCEPTS.md](CONCEPTS.md): the vocabulary (peer connection, transport, mid, SSRC, engine).
2. [ARCHITECTURE.md](ARCHITECTURE.md): the layers, the processes and the packet paths.
3. This page: where things live and how to change them.
4. [TESTING.md](TESTING.md): which test layer to use and how to run it.

## Public API and internal modules

The public API is the `webrtc` module and the `webrtc_media_codec` behaviour. Everything else is internal: you can change it freely, and it may change between releases. A change to `webrtc` or to the plugin behaviour is a change to the API: it needs a line in [CHANGELOG.md](../CHANGELOG.md), and a breaking one is called out in the pull request.

Options and events are listed in [REFERENCE.md](REFERENCE.md); `webrtc_docs_tests` checks that the list matches what `webrtc:new_pc/1` accepts.

## Where things live

Each row names where to start reading, the tests that cover the area, and the page that tracks its requirements.

| Area | Start with | Also | Tests | Requirements |
|---|---|---|---|---|
| Public API, option validation | `src/webrtc.erl` | | `test/e2e/webrtc_pc_SUITE.erl` | [REFERENCE.md](REFERENCE.md) |
| Peer connection process, supervision | `src/pc/webrtc_pc.erl` | `webrtc_peer_sup`, `webrtc_pc_sup`, `src/webrtc_registry.erl` | `webrtc_pc_SUITE`, `webrtc_lifecycle_SUITE` | [ARCHITECTURE.md](ARCHITECTURE.md#processes) |
| Offer and answer (JSEP) | `src/sdp/webrtc_jsep.erl` | `webrtc_jsep_build` (offers, answers), `_params` (what each side negotiated), `_caps` (codecs, extensions, feedback), `_simulcast`, `_transport` (BUNDLE groups) | `webrtc_jsep_tests`, `prop_webrtc_sdp` | [sdp](compliance/sdp.md) |
| SDP text | `src/sdp/webrtc_sdp.erl` | `webrtc_sdp_attr`, `_media`, `_rtp`, `_rid`, `_candidate`, `_lex` | `webrtc_sdp_tests` | [sdp](compliance/sdp.md) |
| Transport process | `src/transport/webrtc_transport.erl` | `_net` (sockets, datagrams, ICE actions), `_secure` (DTLS, SRTP keys, media and SCTP actions), `webrtc_demux` | `webrtc_pc_SUITE`, `webrtc_security_SUITE` | [transport](compliance/transport.md) |
| DSCP marking | `src/transport/webrtc_dscp.erl` | `src/ice/webrtc_ice_marks.erl` | `webrtc_dscp_tests` | [transport](compliance/transport.md), TR-20 and on |
| Candidate names, mDNS | `src/mdns/webrtc_mdns.erl` | `_resolver`, `_responder` (engines), `_client`, `_msg`, `_public` | `webrtc_mdns_SUITE` | [ice](compliance/ice.md) |
| ICE | `src/ice/webrtc_ice_agent.erl` | `_checklist`, `_conncheck`, `_responder`, `_session` (nomination), `_consent`, `_gather`, `_relay`, `_tcp`, `_resolve`, `_uri` | `webrtc_ice_*_tests`, `webrtc_ice_net_tests` | [ice](compliance/ice.md) |
| STUN and TURN | `src/stun/webrtc_stun.erl` | `webrtc_stun_tx`, `webrtc_turn_client`, `_auth`, `_channel`, `_stream` | `webrtc_stun_tests`, `webrtc_turn_*_tests`, `webrtc_turn_interop_SUITE` | [stun](compliance/stun.md), [turn](compliance/turn.md) |
| DTLS | `src/dtls/webrtc_dtls.erl` | `webrtc_dtls12`, `webrtc_dtls13*`, `webrtc_dtls_hs`, `_record`, `_msg`, `_crypto`, `_cert`, `_tickets` | `webrtc_dtls*_tests`, `webrtc_dtls_interop_SUITE`, `webrtc_bogo_SUITE` | [dtls](compliance/dtls.md), [ADR 0001](adr/0001-dtls-in-erlang.md) |
| SRTP | `src/srtp/webrtc_srtp.erl` | `_cipher`, `_kdf`, `_profile`, `_replay` | `webrtc_srtp_tests`, `prop_webrtc_srtp` | [srtp](compliance/srtp.md) |
| Media session | `src/media/webrtc_media.erl` | `webrtc_media_in` (receive), `webrtc_media_out` (send), `_fb` (SLI, RPSI), `_limit` (TMMBR), `_sync` (RFC 6051), `_rid` (simulcast receive), `_pause`, `_report`, `_codec` (plugin behaviour) | `webrtc_media_*_tests` | [rtp](compliance/rtp.md) |
| RTP and RTCP codecs | `src/rtp/webrtc_rtp.erl`, `webrtc_rtcp.erl` | `webrtc_rtcp_fb`, `_xr`, `_twcc`, `_ccfb`, `webrtc_rtp_ext`, `webrtc_rtcp_sched`, `_interval`, `webrtc_rtp_stats` | `webrtc_rtp*_tests`, `webrtc_rtcp*_tests`, `prop_webrtc_rtp`, `webrtc_corpus_tests` | [rtp](compliance/rtp.md) |
| Retransmission, FEC, RED | `src/rtp/webrtc_nack.erl`, `webrtc_nack_buffer.erl` | `webrtc_rtx`, `webrtc_red`, `webrtc_ulpfec`, `webrtc_flexfec` | `webrtc_nack_tests`, `webrtc_ulpfec_tests`, `webrtc_flexfec_tests`, the GStreamer suites | [rtp](compliance/rtp.md) |
| Payload formats | `src/rtp/webrtc_rtp_<codec>.erl` | `webrtc_rtp_vp8`, `_vp9`, `_h264`, `_av1`, `_opus` | `webrtc_rtp_<codec>_tests` | [rtp](compliance/rtp.md) |
| Frames | `src/rtp/webrtc_frame_buffer.erl` | `webrtc_frame_codec` | `webrtc_frame_buffer_tests`, `prop_webrtc_frames`, `webrtc_frames_gst_SUITE` | [rtp](compliance/rtp.md) |
| Bandwidth limits from the peer | `src/rtp/webrtc_tmmbr.erl` | `src/media/webrtc_media_limit.erl`, `src/cc/webrtc_rate_limit.erl` | `webrtc_tmmbr_tests`, `webrtc_media_tmmbr_tests` | [rtp](compliance/rtp.md), CCM rows |
| Congestion control | `src/cc/webrtc_cc.erl` | `webrtc_gcc`, `_delay`, `_aimd`, `webrtc_pacer`, `webrtc_cc_probe`, `webrtc_twcc_*`, `webrtc_ccfb_receiver`, `webrtc_circuit_breaker` | `webrtc_cc_*_tests`, `webrtc_gcc_tests`, `webrtc_rmcat_tests`, `webrtc_cc_SUITE` | [rtp](compliance/rtp.md), RMCAT rows |
| SCTP and data channels | `src/sctp/webrtc_sctp_assoc.erl`, `webrtc_dcep.erl` | `webrtc_sctp_send`, `_recv`, `_ack`, `_pr`, `_reconfig`, `_pmtu`, `_handshake`, `_chunk` | `webrtc_sctp_*_tests`, the ETSI corpus, `webrtc_examples_SUITE` | [sctp](compliance/sctp.md), [guide](guides/data-channels.md) |
| Statistics | `src/pc/webrtc_stats.erl` | `src/media/webrtc_media_report.erl`, `src/rtp/webrtc_rtp_stats.erl` | `webrtc_stats_SUITE` | [stats](compliance/stats.md) |
| Safety: redaction, bounds, lifecycle | `src/webrtc_redact.erl` | `src/webrtc_registry.erl`, the bounds in `src/media/webrtc_media.hrl` | `webrtc_security_SUITE`, `webrtc_lifecycle_SUITE`, `bench/webrtc_soak.erl` | [security](compliance/security.md) |

Test helpers live in `test/support`: `webrtc_impair` (loss, reordering and outages between peers), `webrtc_test_signal` (signaling between two peer connections in a test), `webrtc_test_codec` (a codec plugin), `webrtc_test_turn_udp` (a TURN server) and `webrtc_dtls_sim`.

## The rules

### One responsibility per module

A module does one job that you can say in a sentence: "SCTP send side", "TURN ChannelData framing". Size is a signal to check that, not a limit: when a module grows well past its neighbours, ask whether it now does two jobs, and split it along that line if it does. Codecs (parse and build) stay separate from state machines.

### The engine contract

Every protocol engine is a pure module with `new/1`, `handle_packet`, `handle_timeout/2` and `next_timeout/1`, returning `{State, Actions}`:

```erlang
{St1, Actions} = webrtc_dtls:handle_packet(Datagram, Now, St0),
Deadline = webrtc_dtls:next_timeout(St1).
```

- No sockets, no timers, no clock: the caller passes `Now`.
- No process messages: output is a list of actions.
- Bounded state: every queue, buffer and table has a limit and a documented behaviour when it is reached.
- Malformed input returns `{State, []}` or `{error, _}`, never an exception.

`webrtc_transport` (with `webrtc_transport_net` and `webrtc_transport_secure`, which share its state) is the only place that turns actions into I/O. [ADR 0002](adr/0002-sans-io-engines.md) says why.

### How the layers talk

```
webrtc_pc --configure(Negotiated)--> webrtc_transport
   ^                                     |
   | {webrtc_transport, T, Event}         | ICE valid pair -> DTLS start
   |                                     | DTLS connected -> export SRTP keys -> webrtc_media
   |                                     | DTLS connected + data m= line -> webrtc_dcep connect
application <-- {webrtc, Pc, Event} -----+ (RTP and channel messages go straight here)
```

`webrtc_jsep:negotiated/1` is the contract between negotiation and transport: ICE credentials and candidates, DTLS role and fingerprints, per-mid codecs, extension ids, SSRCs and simulcast layers, SCTP ports and message size. When you add something the transport must know, add it there.

### Compliance rows

Every requirement you implement or change has a row in `docs/compliance/<area>.md`, with the module, the test, and the status the tests justify. A row never claims more than its tests show.

### Conventions

- Module prefix `webrtc_`, `-spec` on every export.
- RFC references name the section (`RFC 8445 §7.2.5`) of the current document; a superseded RFC is named by its replacement.
- Formatting: `rebar3 fmt`.
- OTP 29 and later.

## If you want to...

### Add a protocol feature

1. Find the normative text. Add every MUST and SHOULD to the matching `docs/compliance/<area>.md` page with status "Not implemented".
2. Write the failing test next to the module (`test/<module>_tests.erl`), with the RFC's test vectors when it has some.
3. Implement it in the engine or codec.
4. Add malformed input coverage for any new parser path.
5. If it is visible end to end, add a case to `test/e2e/webrtc_pc_SUITE.erl`, then to an interop suite.
6. Update the rows to the status the tests justify, and [INTEROP.md](INTEROP.md) for interop results.

### Add an RTCP feedback message

1. The codec: a record in `include/webrtc_rtp_rtcp.hrl`, parse and build in `src/rtp/webrtc_rtcp_fb.erl`, tests in `webrtc_rtcp_fb_tests`.
2. The fuzz properties: if the format was kept raw so far, remove its exclusion from `prop_webrtc_rtp`, and give its corpus file a verdict in `webrtc_corpus_tests`.
3. The receive side: a clause in `webrtc_media_in:rtcp_packet2/3`.
4. The negotiation: the `rtcp-fb` value in `src/sdp/webrtc_jsep_caps.erl`; the message is used only when both sides negotiated it.
5. Rows in [rtp](compliance/rtp.md). The SLI and RPSI work (`webrtc_media_fb`) is a complete example.

### Add an RTP header extension

1. The value codec in `src/rtp/webrtc_rtp_ext.erl`, with tests in `webrtc_rtp_ext_tests`.
2. Offer it: `webrtc_jsep_caps:default_extensions/1`.
3. Send it: `webrtc_media_out:header_ext/2`. Read it: `webrtc_media_in`.
4. The rapid synchronisation work (`webrtc_media_sync`, `ntp-64`) is a complete example.

### Add a payload format or a frame codec

1. `src/rtp/webrtc_rtp_<codec>.erl`: packetize and depacketize, key frame detection, with tests built on the format's examples.
2. `webrtc_frame_codec`: map the codec name to the format; `webrtc_frame_buffer` then assembles its frames.
3. Tests: `prop_webrtc_frames` for assembly under loss and reordering, and `webrtc_frames_gst_SUITE` against GStreamer's payloader.

### Add a peer connection option

1. Validate it in `webrtc:new_pc/1`; a bad value returns `{error, {badarg, ...}}`.
2. Pass it on: to JSEP through `webrtc_jsep:new/1`, or to the transport through the options `webrtc_pc` builds for it.
3. Document it in [REFERENCE.md](REFERENCE.md); `webrtc_docs_tests` fails until you do.
4. Add an e2e case in `webrtc_pc_SUITE` that shows its effect.

### Add a transceiver option

1. Accept it in `webrtc_jsep:add_transceiver/3` and keep it in the `#tr{}` record.
2. Put it in the negotiated section: `webrtc_jsep_params:media_params/4`.
3. Use it in the media session. The `priority` option is a complete example.
4. Document it in [REFERENCE.md](REFERENCE.md).

### Add an interop peer

1. An adapter in `interop/<peer>/` that speaks the protocol in [interop/PROTOCOL.md](../interop/PROTOCOL.md).
2. Its start in `test/interop/webrtc_interop_peer.erl`, a group in `webrtc_pc_interop_SUITE`.
3. Its install step in CI, and a section in [INTEROP.md](INTEROP.md).

### Fix an interoperability failure

1. Reproduce it with one interop case (see [TESTING.md](TESTING.md)).
2. Find which side breaks which requirement. Do not change our behaviour because one peer accepts it.
3. Add a regression test at the lowest layer that shows the bug (codec or engine), then fix.
4. If the other implementation is wrong, keep our behaviour and record the deviation in [INTEROP.md](INTEROP.md), with a workaround only if it does not weaken compliance or security.

### Debug a packet through the stack

A received datagram goes through, in order:

1. `webrtc_transport_net:datagram/5`: the socket message.
2. `webrtc_demux:classify/1`: STUN, DTLS, TURN channel data or RTP, by the first byte.
3. `webrtc_transport_secure`: DTLS records, then SRTP for RTP and RTCP.
4. `webrtc_media_in:rtp_in/3`: the stream, RTX and FEC repair, NACK, the frame buffer.
5. The owner: `{webrtc, Pc, {rtp, Mid, Packet}}` or `{webrtc, Pc, {frame, Mid, Frame}}`.

`webrtc:get_stats(Pc)` without options returns the internal counters, which say where packets were dropped. In a test, `webrtc_impair` puts loss, reordering or an outage between two peers.

### Change how the stack behaves under a hostile peer

1. The bounds of the media session are in `src/media/webrtc_media.hrl` (`MAX_STREAMS`, `MAX_ENDED`); each engine documents its own.
2. Tests: `webrtc_media_bounds_tests`, `webrtc_security_SUITE`, and the hostile parsers in `prop_webrtc_parsers` (`make test-security`).
3. For growth over time, `make soak DURATION=10` churns connections with a hostile peer for 10 minutes and fails on growth (see [PERFORMANCE.md](PERFORMANCE.md)).
4. Never raise a bound or drop a check to make a test pass. Record each bound in [security](compliance/security.md).
