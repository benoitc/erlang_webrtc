# ADR 0002: Protocol engines are sans-IO

## Context

A WebRTC transport runs about ten protocols at once on one UDP socket: STUN, ICE, TURN, DTLS, SRTP, RTP and RTCP, SCTP and the data channel protocol, plus congestion control. Each has timers (retransmissions, consent, reports, pacing) and each must behave correctly under loss, reordering and hostile input.

If each protocol were a process with its own socket access and timers, the order of events between them would depend on scheduling, tests would need real sockets and sleeps, and several processes would share the state of one connection.

## Decision

Every protocol state machine is a pure module, an engine, with one contract:

- `new/1`, `handle_packet` (with the current time), `handle_timeout/2`, `next_timeout/1`;
- each call returns the new state and a list of actions (`{send, Bin}`, `{event, E}`);
- no sockets, no timers, no clock and no messages inside an engine.

One process, the transport (`webrtc_transport` with `_net` and `_secure`), owns the engines of one ICE component, feeds them input, performs their actions and arms a single timer at the earliest `next_timeout/1`.

## Consequences

- Engines are tested packet by packet with a synthetic clock, loss and reordering, without sockets (`test/<engine>_tests.erl`). The congestion control simulator (`webrtc_cc_sim`) and the DTLS simulator (`webrtc_dtls_sim`) drive the real engines this way.
- One owner per piece of state: no locks and no shared tables on the packet path.
- Codecs (parse and build) stay separate from state machines, so parsers are fuzzed on their own (`prop_webrtc_parsers`).
- The transport process is the one place where I/O happens, so it is where you look for sockets, DSCP marking and timers.
- An engine that needs a new kind of I/O returns a new action, and the transport learns to perform it.
