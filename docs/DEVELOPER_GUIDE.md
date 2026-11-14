# Developer guide

This page is for contributors. It says where each protocol lives, how the engines are wired together, and the steps to add or change a protocol feature. Read [ARCHITECTURE.md](ARCHITECTURE.md) first for the big picture.

## Where things live

| You want to change | Look at |
|---|---|
| STUN message format, attributes | `src/stun/webrtc_stun.erl` |
| STUN retransmission | `src/stun/webrtc_stun_tx.erl` |
| TURN client | `src/stun/webrtc_turn_*.erl` |
| ICE checks, nomination, consent | `src/ice/webrtc_ice_*.erl` |
| DTLS records, handshake | `src/dtls/webrtc_dtls*.erl` |
| SRTP | `src/srtp/` |
| RTP, RTCP, NACK, payload formats | `src/rtp/` |
| SCTP and data channels | `src/sctp/` |
| SDP grammar | `src/sdp/webrtc_sdp*.erl` |
| Offer/answer rules | `src/sdp/webrtc_jsep*.erl` |
| Media routing, RTCP reports, retransmission | `src/transport/webrtc_media.erl` |
| Sockets, demux, wiring of engines | `src/transport/webrtc_transport.erl` |
| Peer connection API and states | `src/webrtc.erl`, `src/pc/webrtc_pc.erl` |

## The engine contract

Every protocol engine is a pure module with `new/1`, `handle_packet`, `handle_timeout/2` and `next_timeout/1`, returning `{State, Actions}`:

```erlang
{St1, Actions} = webrtc_dtls:handle_packet(Datagram, Now, St0),
Deadline = webrtc_dtls:next_timeout(St1).
```

Rules for engines:

- No sockets, no timers, no `erlang:monotonic_time/1`: the caller passes `Now`.
- No process messages: output is a list of actions.
- Bounded state: every queue, buffer and table has a limit and a documented behavior when it is reached.
- Malformed input returns `{State, []}` or `{error, _}`, never an exception.

`webrtc_transport` is the only place that turns actions into I/O. It keeps one timer at the earliest `next_timeout/1` of all engines.

## How the layers talk

```
webrtc_pc --configure(Negotiated)--> webrtc_transport
   ^                                     |
   | {webrtc_transport, T, Event}         | ICE selected pair -> DTLS start
   |                                     | DTLS connected -> export SRTP keys -> webrtc_media
   |                                     | DTLS connected + data m= line -> webrtc_dcep connect
application <-- {webrtc, Pc, Event} -----+ (RTP and channel messages go straight here)
```

`webrtc_jsep:negotiated/1` is the contract between negotiation and transport: ICE credentials and candidates, DTLS role and fingerprints, per-mid codecs, extension ids and SSRCs, SCTP ports and message size. Change it in one place and both sides follow.

## Add a protocol feature

1. Find the normative text. Note every MUST and SHOULD in the matching `docs/compliance/<protocol>.md` page with status "Not implemented".
2. Write the failing conformance test next to the module (`test/<module>_tests.erl`). Use the RFC's test vectors when it has some.
3. Implement it in the engine or codec. Keep codecs and state machines in separate modules; split a module before it passes about 500 lines.
4. Add malformed input coverage for any new parser path.
5. If the feature is visible end to end, add a case to `test/e2e/webrtc_pc_SUITE.erl`, then to an interop suite.
6. Update the compliance rows to the status the tests justify, and `docs/INTEROP.md` for interop results.

## Fix an interoperability failure

1. Reproduce it with a single interop case (see [TESTING.md](TESTING.md)).
2. Find which side breaks which requirement. Do not change our behavior because one peer accepts it.
3. Add a regression test at the lowest layer that shows the bug (codec or engine), then fix.
4. If the other implementation is wrong, keep our behavior and record the deviation in `docs/INTEROP.md`, with a workaround only if it does not weaken compliance or security.

## Conventions

- Module prefix `webrtc_`, one responsibility per module, `-spec` on every export.
- RFC references in comments name the section (`RFC 8445 §7.2.5`) of the current document; superseded RFCs are named by their replacement.
- Formatting: `rebar3 fmt`.
- Commits are small and each one passes `rebar3 eunit`.
