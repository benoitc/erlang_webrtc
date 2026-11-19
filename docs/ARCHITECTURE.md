# Architecture

This page explains how the stack is split into layers, which process owns what, and how a packet travels through it. Read it before you change a protocol module or add a new one. If a term is new to you, [CONCEPTS.md](CONCEPTS.md) defines it; [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) then maps each part to its modules and tests.

## Layers

```
            application (SFU, gateway, test peer, ...)
                         |  webrtc API (webrtc.erl), events {webrtc, Pc, Event}
  +----------------------+------------------------------------------+
  | webrtc_pc            JSEP signaling, transceivers, data channels |
  |   webrtc_jsep  webrtc_sdp                                        |
  +----------------------+------------------------------------------+
                         |  commands / events (Erlang messages)
  +----------------------+------------------------------------------+
  | webrtc_transport     one per BUNDLE group (ICE component)        |
  |  owns: UDP sockets, ICE agent, DTLS endpoint, SRTP contexts,     |
  |        SCTP association                                          |
  |                                                                  |
  |  demux (RFC 7983, RFC 9443)                                      |
  |   0..3     -> webrtc_ice_agent  (webrtc_stun, webrtc_turn)       |
  |   20..63   -> webrtc_dtls       -> app data -> webrtc_sctp_assoc |
  |                                                -> webrtc_dcep    |
  |   128..191 -> media session (webrtc_media, src/media)            |
  |               SRTP, RTP / RTCP, retransmission, FEC, frames,     |
  |               congestion control (webrtc_cc), codec plugins      |
  +----------------------+------------------------------------------+
                         |  gen_udp (IPv4 / IPv6)
                       network
```

## Sans-IO protocol engines

Every protocol state machine (ICE agent, STUN transactions, TURN client, DTLS, SRTP, SCTP association, DCEP) is a pure functional module. It never opens sockets, starts timers, reads the clock or sends messages. The owning process feeds it input and executes the actions it returns.

The contract, used by every engine:

```erlang
-spec new(Opts :: map()) -> State.
-spec handle_packet(Packet :: binary(), Now :: integer(), State) -> {State, [Action]}.
-spec handle_timeout(Now :: integer(), State) -> {State, [Action]}.
-spec next_timeout(State) -> integer() | infinity.
```

- `Now` is `erlang:monotonic_time(millisecond)` supplied by the caller. Tests pass a synthetic clock.
- `next_timeout/1` returns an absolute time in the same unit. The owner arms one timer per engine.
- Actions are tuples such as `{send, Bin}`, `{send, Dest, Bin}`, `{event, Event}`. Each engine documents its action and event types in its module doc.
- Random values that affect protocol behavior (tie-breakers, initial sequence numbers, jitter) come from `crypto:strong_rand_bytes/1` by default and can be overridden through `Opts` for reproducible tests. Key material always comes from `crypto:strong_rand_bytes/1`.

This split gives three things:

1. Deterministic tests: an engine can be driven packet by packet with a fake clock, loss and reordering, without sockets or sleeps.
2. One owner per state: no locks, no shared ETS for protocol state.
3. Codecs (`*_chunk`, `webrtc_stun`, `webrtc_rtp`, `webrtc_sdp`) stay separate from state machines.

## Processes

```
webrtc_sup (one_for_one)
  webrtc_registry          owns webrtc_transports, monitors each peer connection
  webrtc_pc_sup (one_for_one, temporary children)
    webrtc_peer_sup        one per peer connection (one_for_all, auto_shutdown any_significant)
      webrtc_pc            significant, temporary (gen_server)
      webrtc_transport     one per BUNDLE group, temporary, monitored by webrtc_pc (gen_server)
```

Who watches whom:

```
webrtc_registry --monitors--> webrtc_pc          drops the pc's rows in webrtc_transports
webrtc_pc       --monitors--> owner process      closes the peer connection when the owner exits
webrtc_pc       --monitors--> webrtc_transport   a transport that dies: connection_state failed, the pc ends
webrtc_pc       --links-----> signaling helper   the helper also monitors webrtc_pc and exits with it
webrtc_transport --links----> TCP and TLS connect workers
```

- `webrtc_pc` owns the signaling state, the local and remote descriptions, the transceivers and the data channel registry. It is the process the application talks to.
- `webrtc_transport` owns the UDP sockets and every engine of the transport. Media send calls go straight from the application to the transport process, so RTP forwarding does not pass through `webrtc_pc`. The process code is split in three modules over one state: `webrtc_transport` (API, callbacks, timer), `webrtc_transport_net` (sockets, received datagrams, ICE actions) and `webrtc_transport_secure` (DTLS, SRTP, media actions, SCTP).
- Each transport process handles one ICE component. With BUNDLE (the WebRTC default) that is one per peer connection. Without it, or with several BUNDLE groups, `webrtc_pc` starts one transport per group or unbundled m= section and routes media calls to it by mid; the connection state aggregates them all.
- Peer connections are independent. There is no global registry on the packet path.
- The subtree of a peer connection ends with it, however it ends: close, crash, owner exit or `kill`. Its transports go with it (they trap exits so that their cleanup, close_notify and TURN deletion, still runs), and `webrtc_registry` removes its rows from `webrtc_transports`. Nothing is restarted: the JSEP and DTLS state of a peer connection cannot be rebuilt.
- The signaling helper (option `signaling`) and the workers opening TCP and TLS connections are short lived processes linked to their owner, which kills them when it stops.
- Crash reports and `sys:get_status/1` show a summary of the peer connection and transport states, never their keys or credentials (`webrtc_redact`).

Sockets are opened in `{active, N}` mode so the transport process gets a bounded burst of datagrams and re-arms. Outgoing queues are bounded. When the SCTP send buffer is full the API returns `{error, buffer_full}` and the application receives a `buffered_amount_low` event when it can send again. When the media pacer queue is full it drops the oldest video packet and counts it (see below).

## How a packet enters and leaves

Inbound:

1. `gen_udp` delivers `{udp, Sock, IP, Port, Bin}` to `webrtc_transport`.
2. `webrtc_demux:classify/1` looks at the first byte (RFC 7983 as updated by RFC 9443).
3. STUN goes to the ICE agent. A valid check from an unknown address creates a peer-reflexive candidate. Consent responses refresh the selected pair.
4. DTLS records go to the DTLS endpoint. Handshake output is sent back through the best valid pair (RFC 8445 §12.1), and kept until one exists. Once connected, application data goes to the SCTP association; the exported keying material configures SRTP.
5. RTP/RTCP is unprotected with the SRTP context of the remote side, parsed, and delivered to the owner as `{webrtc, Pc, {rtp, Mid, Packet}}` (`{rtp, Mid, Rid, Packet}` for a simulcast layer, told apart by its rid header extension) or handed to the RTCP handler.

Outbound follows the reverse path.

### Inside the media session

The media session (`webrtc_media`) is the engine that handles RTP and RTCP for one transport. `webrtc_media_in` holds the receive half and `webrtc_media_out` the send half; the other `webrtc_media_*` modules each hold one feature that both halves use.

Receive path:

```
datagram (128..191)
  -> webrtc_srtp:unprotect_rtp              unknown key or replay: dropped and counted
  -> webrtc_rtp:decode
  -> transport-wide and RFC 8888 arrival    webrtc_cc (feedback to the sender)
  -> route: SSRC, MID extension, payload type, rid (webrtc_media_rid)
  -> RTX unwrap, FEC recovery               webrtc_rtx, webrtc_ulpfec, webrtc_flexfec
  -> receive statistics, NACK generation    webrtc_rtp_stats, webrtc_nack
  -> frames => true ?  webrtc_frame_buffer  (then the codec plugin, if any)
  -> owner: {rtp, Mid, Pkt} | {frame, Mid, Frame} | {decoded, Mid, Media}
```

Send path:

```
owner: send_rtp | send_frame (packetized here) | send_media (plugin encodes) | send_rtp_packet
  -> sender of the mid (or of the simulcast layer): SSRC, sequence number, header extensions,
     RTCP rapid sync (webrtc_media_sync), RED wrap when ULPFEC is negotiated
  -> NACK buffer (webrtc_nack_buffer)       kept for retransmission
  -> TMMBR limit (webrtc_media_limit)       the rate the peer allows
  -> pacer (webrtc_pacer via webrtc_cc)     audio > retransmission > video
  -> circuit breaker check, transport-wide sequence number
  -> webrtc_srtp:protect_rtp -> FEC packets after each frame -> DSCP -> {send, Datagram}
```

RTCP goes through `webrtc_media_in:rtcp_packet2/3` on receive (reports, NACK, PLI, FIR, SLI, RPSI, TMMBR, SR requests) and `webrtc_rtcp_sched` decides when reports go out.

### One transceiver, several RTP streams

A transceiver is one m= section (one mid). On the wire it can be several RTP streams, each with its own SSRC:

```
transceiver mid "1" (video)
  |- media stream        SSRC A                 (one per simulcast layer: rid "h", "m", "l")
  |- retransmissions     SSRC A' (RTX)          one per media stream, repaired-rid on layers
  |- FlexFEC repair      SSRC F                 or ULPFEC inside RED on the media SSRC
```

Received streams are found by SSRC once known; a new SSRC is matched by its MID or rid header extension, or by a payload type that only one section uses (RFC 9143 §9.2). [CONCEPTS.md](CONCEPTS.md) explains each term. DTLS, SRTP and SCTP traffic uses the best valid pair until ICE selects one, then only the selected pair; data is never sent before ICE has a valid pair and consent is fresh (RFC 7675).

## Interaction between ICE, DTLS, SRTP and SCTP

- ICE produces a selected pair. DTLS starts once a pair is valid (RFC 8842: the DTLS role comes from the `a=setup` negotiation, not from the ICE role).
- DTLS verifies the peer certificate against the `a=fingerprint` of the remote description. A mismatch is fatal.
- DTLS-SRTP (RFC 5764) yields the protection profile and the keying material. `webrtc_srtp` derives session keys.
- SCTP runs over DTLS application data (RFC 8261). The data channel protocol (RFC 8832) runs on top of SCTP.
- ICE restarts keep the DTLS association (RFC 8842 §4). Losing consent closes the transport.

## Congestion control and pacing

`webrtc_media` owns one `webrtc_cc` engine per transport. It is sans-IO like the others and is driven from `webrtc_media`'s `send_packet/4`, `handle_packet/3` and `handle_timeout/2`:

```
send_packet ---> NACK buffer ---> webrtc_pacer (audio > rtx > video)
                                        |  released by budget or timeout
                                        v
                      transport-wide seq (webrtc_twcc_sender) -> SRTP -> {send, Bin}

RTCP in: transport-wide feedback -> webrtc_twcc_sender -> webrtc_gcc -> target
         REMB --------------------------------------------> webrtc_gcc
         SR/RR report blocks -> webrtc_circuit_breaker, RTT, loss (no feedback)
target -> pacing rate (2.5 x target), event {bandwidth_estimate, Bps}

RTP in:  transport-wide seq -> webrtc_twcc_receiver -> feedback every 100 ms
```

- The estimator is Google Congestion Control (`webrtc_gcc`): a delay-based controller (`webrtc_gcc_delay`, trendline filter and adaptive over-use threshold; `webrtc_gcc_aimd`, the rate controller) and a loss-based controller. The target is the minimum of both and of a received REMB, within `min_bitrate` and `max_bitrate`.
- One estimate covers every stream of the transport. The application gets `{bandwidth_estimate, Bps}` when it moves by more than 5% and splits it between its encoders; the stack never re-encodes media.
- The pacer (`webrtc_pacer`) is a leaky bucket at 2.5 x the target with a 10 ms burst. It only holds packets back once input backs the estimate (transport-wide feedback, REMB or receiver reports), so a stream is never limited by the start guess; a peer that sends no RTCP at all trips the RTCP timeout breaker. Retransmissions are limited to the target over one second. `webrtc:set_congestion_control/2` turns pacing off or changes the bitrate limits.
- The RTP circuit breakers of RFC 8083 (`webrtc_circuit_breaker`) emit `{circuit_breaker, Mid, Reason}` and `webrtc_cc` acts: the RTCP and media timeout breakers halt the transceiver's RTP until `webrtc:resume_stream/2` (refused during a hold time); the congestion breaker first caps the target at a tenth of the sending rate, then halts if it triggers again.
- A peer that sends receiver reports but no transport-cc feedback or REMB drives the loss-based estimate from the fraction lost; the estimate starts at the rate being sent, so forwarded streams are not cut to the start guess.
- Times are the engine's millisecond clock, so the whole path is tested with a synthetic clock: `test/webrtc_cc_sim.erl` runs flows over a simulated bottleneck (`test/webrtc_cc_link.erl`) through the real engines and RTCP codec.

## Negotiation

`webrtc_jsep` implements the JSEP state machine (RFC 9429) on structured `webrtc_sdp` records, never on strings. Offer and answer generation, BUNDLE (RFC 9143), codec intersection, direction negotiation, rollback and renegotiation all operate on records and are tested without a network.

## Source layout

| Directory          | Contents                                     |
|--------------------|----------------------------------------------|
| `src/stun`         | STUN codec, transactions, TURN client        |
| `src/ice`          | candidates, ICE agent, checklists            |
| `src/dtls`         | DTLS record layer, handshake, key schedule   |
| `src/srtp`         | SRTP/SRTCP protection, key derivation, replay|
| `src/rtp`          | RTP, RTCP, header extensions, payload helpers|
| `src/cc`           | congestion control, pacer, circuit breakers  |
| `src/sctp`         | SCTP chunks, association, DCEP               |
| `src/sdp`          | SDP codec and JSEP                           |
| `src/transport`    | the transport process, demux, DSCP marking   |
| `src/media`        | the media session: receive, send, feedback, limits, sync, codec plugin behaviour |
| `src/mdns`         | mDNS and DNS resolution of candidate names, mDNS responder for our own candidates |
| `src/pc`           | peer connection process, supervision, statistics |
| `src/` (top)       | public API (`webrtc`), application, registry, log redaction |
| `include/`         | records shared between modules and tests     |
| `test/`            | eunit and PropEr conformance tests           |
| `test/support`     | test helpers: impairment, signaling, TURN server, test codec |
| `test/e2e`         | Common Test suites over real UDP sockets     |
| `test/interop`     | interop suites against independent stacks    |
| `interop/`         | the peer adapters (Pion, aiortc, browsers, GStreamer, ...) and their protocol |
| `examples/`        | runnable examples, run by `webrtc_examples_SUITE` |
| `bench/`           | benchmarks and the soak run, never run by the functional suites |
| `docs/`            | guides, reference, compliance pages, ADRs    |
