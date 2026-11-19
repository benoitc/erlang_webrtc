# Concepts

This page defines the words the rest of the documentation uses, in the order you meet them, and says where each one lives in the code. Read it if you are new to WebRTC or to this code base; after it, [ARCHITECTURE.md](ARCHITECTURE.md) reads without a glossary. If you only want to use the library, the first four sections are enough.

## Peer connection and owner

A **peer connection** is one WebRTC session with one remote peer, the same object a browser calls `RTCPeerConnection`. You create it with `webrtc:new_peer_connection/1` and get a pid back.

The **owner** is the process that receives the peer connection's events as `{webrtc, Pc, Event}` messages: the caller of `new_peer_connection/1` by default. When the owner exits, the peer connection closes.

You exchange session descriptions (SDP offers and answers) and ICE candidates with the remote peer yourself, over any channel you like (HTTP, WebSocket, SIP): that is **signaling**, and the library does not do it for you.

Where: `src/webrtc.erl` (the API), `src/pc/webrtc_pc.erl` (the process).

## Transceiver and mid

A **transceiver** carries one kind of media (audio or video) in both directions, or one of them. Each transceiver is one `m=` section in the SDP, identified by its **mid** (a short binary such as `<<"0">>`). You address media calls by mid: `webrtc:send_rtp(Pc, Mid, ...)`.

Data channels share one more `m=` section (`application`), with its own mid.

Where: `webrtc_jsep` keeps the transceivers; `webrtc:add_transceiver/3` adds one.

## BUNDLE group and transport

Each `m=` section could have its own network path, but WebRTC normally puts them all on one: a **BUNDLE group** (RFC 9143). A **transport** is one network path: one ICE agent, one DTLS association, its SRTP keys and its SCTP association.

In this library a transport is a process, `webrtc_transport`. With BUNDLE (the default) a peer connection has one transport. With several groups, or sections outside any group, it has one transport per group or section, and routes each media call to the right one by mid.

Where: `src/transport/`, and `webrtc_jsep_transport` for the grouping. [ADR 0003](adr/0003-transport-per-bundle-group.md) explains the choice.

## Negotiation

`webrtc_jsep` runs the offer and answer rules (JSEP, RFC 9429) on parsed SDP records. Once both descriptions are set, `webrtc_jsep:negotiated/1` returns what was agreed: credentials, fingerprints, codecs, extension ids, SSRCs. That map is what the transport is configured with.

## SSRC, RTX, FEC and rid

Media travels as RTP packets. Every RTP stream has an **SSRC**, a 32-bit identifier in each packet. One transceiver can produce several streams:

- the media itself;
- **RTX**: retransmissions of lost packets on their own SSRC (RFC 4588);
- **FEC**: repair packets from which a lost packet is rebuilt without a retransmission (FlexFEC on its own SSRC, or ULPFEC inside RED);
- **simulcast**: the same video at several resolutions, each a separate stream named by a **rid** (RFC 8851), each with its own RTX.

You send and receive on the transceiver; the library picks and rewrites SSRCs, sequence numbers and repair streams. Received packets tell you the rid when they belong to a simulcast layer: `{rtp, Mid, Rid, Packet}`.

Where: `webrtc_media_out` (send streams), `webrtc_media_in` and `webrtc_media_rid` (receive streams), `src/rtp/` (the formats).

## The media session

The **media session** is the part of a transport that handles RTP and RTCP: SRTP protection, matching packets to transceivers, reports, retransmission, FEC, keyframe requests, bandwidth limits and congestion control. It is one engine, `webrtc_media`, per transport, split into a receive half (`webrtc_media_in`) and a send half (`webrtc_media_out`), plus one module per feature (`webrtc_media_fb`, `_limit`, `_sync`, `_pause`, `_report`).

Where: `src/media/`. [ARCHITECTURE.md](ARCHITECTURE.md#inside-the-media-session) draws its two paths.

## Packets and frames

By default you receive **packets**: `{webrtc, Pc, {rtp, Mid, Packet}}`, in arrival order, as an SFU wants them for forwarding.

With `frames => true` you receive **frames** instead: the packets of each video frame (or audio packet) put in order, joined, and released at their playout time by a jitter buffer. That is what you want to decode or record. A frame that cannot be completed is dropped and a keyframe is requested.

A **codec plugin** (`webrtc_media_codec`) goes one step further: it decodes received frames and encodes what you send. The library itself never encodes or decodes media; [ADR 0004](adr/0004-no-media-coding.md) says why.

Where: `src/rtp/webrtc_frame_buffer.erl`, `src/media/webrtc_media_codec.erl`. See [the frames guide](guides/frames-and-codec-plugins.md).

## Engines (sans-IO)

Every protocol state machine (ICE, STUN, TURN, DTLS, SRTP, SCTP, the data channel protocol, the media session, congestion control) is an **engine**: a pure module that never opens a socket, starts a timer, reads the clock or sends a message. You feed it a packet or a timeout with the current time, and it returns its new state and a list of actions (`{send, Bin}`, `{event, E}`).

The transport process owns the engines of one transport and is the only place that performs their actions. That gives one owner per piece of state, no locks, and tests that drive an engine packet by packet with a fake clock.

Where: the contract is in [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md#the-engine-contract); [ADR 0002](adr/0002-sans-io-engines.md) says why.

## The registry: why media calls skip the peer connection

The peer connection process handles signaling. If every RTP packet you send went through it, signaling would slow media down and the reverse. So the peer connection registers its transports in an ETS table, `webrtc_transports`, by peer connection and mid, and calls such as `webrtc:send_rtp/4` look the transport up and call it directly.

`webrtc_registry` owns that table, monitors each peer connection and removes its rows when it ends, however it ends.

Where: `src/webrtc_registry.erl`, and the lookups in `src/webrtc.erl`.

## Supervision

Each peer connection runs in its own supervisor, `webrtc_peer_sup`, with its transports. When the peer connection ends, everything under it ends too; nothing is restarted, because the negotiated state of a WebRTC session cannot be rebuilt. [ADR 0005](adr/0005-per-peer-supervision.md) explains this.

Where: `src/pc/webrtc_peer_sup.erl`, the process tree in [ARCHITECTURE.md](ARCHITECTURE.md#processes).

## Read next

- [ARCHITECTURE.md](ARCHITECTURE.md): how these pieces fit together.
- [REFERENCE.md](REFERENCE.md): every option and event.
- The guides, task by task: [send media](guides/send-media.md), [forward media](guides/forward-media.md), [frames and codec plugins](guides/frames-and-codec-plugins.md), [data channels](guides/data-channels.md), [statistics](guides/statistics.md), [bandwidth and QoS](guides/bandwidth-and-qos.md).
