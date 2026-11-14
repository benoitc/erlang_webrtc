# Architecture

This page explains how the stack is split into layers, which process owns what, and how a packet travels through it. Read it before you change a protocol module or add a new one.

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
  |   128..191 -> webrtc_srtp       -> webrtc_rtp / webrtc_rtcp      |
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
  webrtc_pc_sup (simple_one_for_one, temporary children)
    webrtc_pc            one per peer connection (gen_server)
      webrtc_transport   linked to its webrtc_pc (gen_server)
```

- `webrtc_pc` owns the signaling state, the local and remote descriptions, the transceivers and the data channel registry. It is the process the application talks to.
- `webrtc_transport` owns the UDP sockets and every engine of the transport. Media send calls go straight from the application to the transport process, so RTP forwarding does not pass through `webrtc_pc`.
- Each transport process handles one ICE component. With BUNDLE (the WebRTC default) that is one per peer connection.
- Peer connections are independent. There is no global registry on the packet path.

Sockets are opened in `{active, N}` mode so the transport process gets a bounded burst of datagrams and re-arms. Outgoing queues (SCTP send buffer, pacer) are bounded; when a limit is reached the API returns `{error, buffer_full}` and the application receives a `buffered_amount_low` event when it can send again.

## How a packet enters and leaves

Inbound:

1. `gen_udp` delivers `{udp, Sock, IP, Port, Bin}` to `webrtc_transport`.
2. `webrtc_demux:classify/1` looks at the first byte (RFC 7983 as updated by RFC 9443).
3. STUN goes to the ICE agent. A valid check from an unknown address creates a peer-reflexive candidate. Consent responses refresh the selected pair.
4. DTLS records go to the DTLS endpoint. Handshake output is sent back through the selected pair. Once connected, application data goes to the SCTP association; the exported keying material configures SRTP.
5. RTP/RTCP is unprotected with the SRTP context of the remote side, parsed, and delivered to the owner as `{webrtc, Pc, {rtp, Mid, Packet}}` (`{rtp, Mid, Rid, Packet}` for a simulcast layer, told apart by its rid header extension) or handed to the RTCP handler.

Outbound follows the reverse path. Only the selected candidate pair is used for DTLS, SRTP and SCTP traffic; data is never sent before ICE has a valid pair and consent is fresh (RFC 7675).

## Interaction between ICE, DTLS, SRTP and SCTP

- ICE produces a selected pair. DTLS starts once a pair is valid (RFC 8842: the DTLS role comes from the `a=setup` negotiation, not from the ICE role).
- DTLS verifies the peer certificate against the `a=fingerprint` of the remote description. A mismatch is fatal.
- DTLS-SRTP (RFC 5764) yields the protection profile and the keying material. `webrtc_srtp` derives session keys.
- SCTP runs over DTLS application data (RFC 8261). The data channel protocol (RFC 8832) runs on top of SCTP.
- ICE restarts keep the DTLS association (RFC 8842 §4). Losing consent closes the transport.

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
| `src/sctp`         | SCTP chunks, association, DCEP               |
| `src/sdp`          | SDP codec and JSEP                           |
| `src/transport`    | demux, UDP transport process                 |
| `src/pc`           | peer connection process and supervision      |
| `test/`            | eunit and PropEr conformance tests           |
| `test/e2e`         | Common Test suites over real UDP sockets     |
| `test/interop`     | interop controller and peer adapters         |
| `bench/`           | benchmarks, never run by the functional suites |
