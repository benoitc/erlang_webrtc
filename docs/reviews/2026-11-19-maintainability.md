# Documentation and maintainability review, 2026-11-19

Reviewed: `feature/webrtc-stack` at `4a9aae9`, which is what `main` becomes before the first release (0.1.0). No source code was changed. The next review should start from this page and record what changed since.

## What it found, in short

- The documentation already has a good spine. The README is task-oriented, ARCHITECTURE explains the sans-IO design and the process tree, and the compliance pages track every requirement. Nothing is badly wrong, but several parts no longer match the code. The latest features (TMMBR, rapid sync, DSCP, SLI and RPSI, FEC, frames, codec plugins, the safety work) are missing from the maps a newcomer uses.
- There is no reference for configuration. The 54 options of `new_peer_connection/1` and the events live only in `webrtc.erl`'s edoc, and API docs are not generated.
- `src/transport` holds two subsystems: the transport process (and mDNS) and the media session (`webrtc_media*`, 11 modules). Nothing in the tree or the docs tells them apart.
- Five modules pass 850 lines, and the developer guide asks contributors to split modules at about 500. Thirty modules are past that, so the rule and the code disagree. `webrtc_pc` (1,095 lines, 70 functions) is the one that most needs a map before a change.
- Missing for a public release: a LICENSE file (README and `webrtc.app.src` say Apache 2.0), CONTRIBUTING, CHANGELOG and a security policy.

## Measurements

Lines, functions, exports and the longest function, counted by parsing each module. A function's length runs to the next form, so it includes the comment before that form.

| Module | Lines | Functions | Exports | Longest function |
|---|---|---|---|---|
| `src/pc/webrtc_pc.erl` | 1095 | 70 | 7 | `call_/3`, 100 (every call clause) |
| `src/sdp/webrtc_jsep.erl` | 911 | 63 | 27 | `new/1`, 62 |
| `src/transport/webrtc_media_in.erl` | 907 | 53 | 9 | `deliver1/5`, 51 |
| `src/transport/webrtc_media_out.erl` | 893 | 67 | 25 | `egress/3`, 57 |
| `src/sctp/webrtc_dcep.erl` | 758 | 45 | 18 | `assoc_event/3`, 84 |
| `src/sctp/webrtc_sctp_assoc.erl` | 690 | 39 | 18 | `chunk/4`, 107 |
| `src/transport/webrtc_media.erl` | 681 | 40 | 27 | `configure/2`, 77 |
| `src/ice/webrtc_ice_agent.erl` | 675 | 49 | 35 | `new/1`, 55 |
| `src/sctp/webrtc_sctp_send.erl` | 665 | 44 | 17 | `commit/4`, 111 |
| `src/webrtc.erl` (public API) | 661 | 53 | 44 | `new_peer_connection/0`, 125 (edoc of 54 options) |
| `src/transport/webrtc_transport.erl` | 472 | 45 | 34 | `call_/3`, 135 (every call clause) |
| `src/sctp/webrtc_sctp_crc32c.erl` | 583 | 6 | 2 | `tab/0`, 515 (a table: fine) |

By directory:

| Directory | Modules | Lines |
|---|---|---|
| `src/transport` | 21 | 6425 |
| `src/rtp` | 26 | 6048 |
| `src/sctp` | 14 | 5868 |
| `src/dtls` | 18 | 5534 |
| `src/sdp` | 13 | 4674 |
| `src/ice` | 13 | 3992 |
| `src/cc` | 12 | 2805 |
| `src/stun` | 6 | 1731 |
| `src/pc` | 4 | 1637 |
| `src/srtp` | 5 | 1287 |

Tests: 100 eunit and PropEr modules in `test/`, 7 e2e suites, 11 interop suites, 11 support modules.

## Recommended documentation structure

One path a reader follows, each page short and linking to the next:

1. **README** (keep, trim): what the library is and who it is for, a two-minute example, and a "Read next" list. The long feature tour moves to the guides. *Reader:* someone deciding whether to use it. *After it:* they can run the example and know where the guides are.
2. **Guides** (`docs/guides/`, grow from one to five): task pages in the style of `data-channels.md`.
   - Answer a browser and send media.
   - Forward media (SFU).
   - Receive frames and use a codec plugin.
   - Statistics.
   - Control bandwidth and QoS (TMMBR, DSCP, congestion control).

   *Reader:* developers using the library. *After them:* they can build the common applications. *Next:* the configuration reference.
3. **Configuration and events reference** (`docs/REFERENCE.md`, new): every `new_peer_connection/1` and transceiver option, and every `{webrtc, Pc, Event}`, with a line each and a link to the guide that uses it. Generated from, or checked against, `webrtc.erl`. *Reader:* developers using the library. *After it:* they find any option without reading the source.
4. **Concepts** (`docs/CONCEPTS.md`, new): the vocabulary of WebRTC as this library uses it. *Reader:* someone new to WebRTC or to this code base. *After it:* the architecture page reads without a glossary.
   - What a peer connection, transceiver, mid, BUNDLE group, SSRC, rid and transport are.
   - What an engine is (sans-IO).
   - Where each one lives.
5. **ARCHITECTURE** (keep, refresh): layers, processes, packet path, the engine contract. *Reader:* developers who want to understand how it works.
   - Add the media session as its own box, and the supervision story already written.
   - Add one diagram per path: receive and send.
6. **DEVELOPER_GUIDE** (rewrite as "Change the code"): the "Where things live" map, completed and grouped by subsystem. *Reader:* contributors.
   - "If you want to..." recipes pointing to modules, tests and compliance pages (see below).
   - The engine rules.
7. **TESTING** (keep), **INTEROP**, **COMPLIANCE** and **PERFORMANCE** (keep as references; fix the stale summary).
8. **CONTRIBUTING.md** (new, at the root): how to propose a change, the commit and PR rules, the checks to run, the review expectations.

**Starting point for a new developer:** the README, then CONCEPTS, then ARCHITECTURE. A contributor then reads DEVELOPER_GUIDE and TESTING.

## Existing documents

| Document | Action | Reason |
|---|---|---|
| `README.md` | Rewrite (trim) | Good tone, but it is the whole user guide at once (195 lines). The status line omits Firefox and GStreamer. Media, frames, plugins and stats sections belong in guides. |
| `docs/ARCHITECTURE.md` | Keep, refresh | The layer diagram has no media session (`webrtc_media*`) and no frame buffer. The source layout table omits `examples/`, `interop/`, `test/support`, `docs/`. |
| `docs/DEVELOPER_GUIDE.md` | Rewrite | The "Where things live" table misses the modules added recently: `webrtc_media_limit`, `_sync`, `_fb`, `_report`, `_codec`, `webrtc_dscp`, `webrtc_tmmbr`, `webrtc_frame_buffer`, FEC, `webrtc_redact`, `webrtc_registry`, `webrtc_peer_sup`. The "split before about 500 lines" rule contradicts 30 modules (see questions). It has no "If you want to..." recipes beyond adding a feature and fixing interop. |
| `docs/COMPLIANCE.md` | Keep, fix the summary | The summary says RFC 8867 fails only on different RTTs; RMCAT-5 now passes over 24 seeds. TMMBR, rapid sync, DSCP, SLI/RPSI, ULPFEC and FlexFEC are missing from it. |
| `docs/compliance/*.md` | Keep, fix stale rows | AVPF-6 says RPSI is "kept raw" (implemented in #61); check DTLS-27 against DTLS-56 and DTLS-59 (resumption is implemented). |
| `docs/INTEROP.md` | Keep | Clear. Each section could start with one sentence on why that peer matters. |
| `docs/TESTING.md` | Keep | Good. Add how to choose the layer for a new test. |
| `docs/PERFORMANCE.md` | Keep | Clear, dated results. |
| `docs/guides/data-channels.md` | Keep | The model for the other guides. |
| `docs/adr/0001-dtls-in-erlang.md` | Keep | The only ADR. Other decisions deserve one (see below). |
| `docs/prompts/codec-plugin.md` | Move or remove | A prompt for an AI agent, not a document for people. In a public repository it reads as a design note without context. Turn it into a "Write a codec plugin" guide, or move it out of `docs/`. |
| `interop/PROTOCOL.md`, `interop/*/README.md` | Keep | Right place, right audience. |

## Missing documents

- `LICENSE` (Apache 2.0 text): needed before the repository is public.
- `CONTRIBUTING.md`: workflow, checks, commit and PR rules.
- `CHANGELOG.md`: the release notes for 0.1.0, then one section per release.
- `SECURITY.md`: how to report a vulnerability, and what is in scope (the stack parses hostile input).
- `docs/REFERENCE.md`: options and events (see above).
- `docs/CONCEPTS.md`: vocabulary and mental model.
- Four guides (see the structure above), and "Write a codec plugin".
- ADRs for the decisions that are visible only in code:
  - sans-IO engines;
  - one transport process per BUNDLE group;
  - no media coding in the library (plugins instead);
  - the per-peer supervision subtree and its no-restart rule;
  - redacted logging.

## Concepts that need their own explanation

- Sans-IO engines and why there is one owner process per transport (touched on in ARCHITECTURE, but the "why" for newcomers is short).
- Mid, BUNDLE group and transport: how a section maps to a transport process (`webrtc_jsep:negotiated/1` is the contract).
- SSRC, rid, RTX and FEC streams: how one transceiver becomes several RTP streams (`webrtc_media_rid`, `webrtc_media_out`).
- The media session: what `webrtc_media` owns per transport, and which of its modules handle receive, send, feedback, limits and sync.
- Frames versus packets: when the frame buffer is in the path.
- Owner, events and the registry: why media calls skip the peer connection process.

## Navigation guide

| Concept | Directory, modules | Tests | Docs |
|---|---|---|---|
| Public API and options | `src/webrtc.erl` | `test/e2e/webrtc_pc_SUITE.erl` | README, REFERENCE (new) |
| Signaling (JSEP, SDP) | `src/sdp/webrtc_jsep*.erl`, `webrtc_sdp*.erl` | `webrtc_jsep_tests`, `webrtc_sdp_tests`, `prop_webrtc_sdp` | `compliance/sdp.md` |
| Peer connection process | `src/pc/webrtc_pc.erl`, `webrtc_peer_sup.erl` | `webrtc_pc_SUITE`, `webrtc_lifecycle_SUITE` | ARCHITECTURE "Processes" |
| Transport process | `src/transport/webrtc_transport*.erl`, `webrtc_demux.erl` | `webrtc_pc_SUITE`, `webrtc_security_SUITE` | ARCHITECTURE |
| ICE, STUN, TURN | `src/ice/`, `src/stun/` | `webrtc_ice_*_tests`, `webrtc_ice_net_tests`, `webrtc_turn_interop_SUITE` | `compliance/ice.md`, `turn.md` |
| DTLS | `src/dtls/` | `webrtc_dtls*_tests`, `webrtc_dtls_interop_SUITE`, `webrtc_bogo_SUITE` | `compliance/dtls.md`, ADR 0001 |
| SRTP | `src/srtp/` | `webrtc_srtp_tests`, `prop_webrtc_srtp` | `compliance/srtp.md` |
| Media session (receive, send, feedback) | `src/transport/webrtc_media*.erl` | `webrtc_media_*_tests` | DEVELOPER_GUIDE (to complete) |
| RTP, RTCP, payload formats, FEC | `src/rtp/` | `webrtc_rtp*_tests`, `webrtc_rtcp*_tests`, GStreamer suites | `compliance/rtp.md` |
| Frames | `src/rtp/webrtc_frame_buffer.erl`, `webrtc_frame_codec.erl` | `webrtc_frame_buffer_tests`, `prop_webrtc_frames`, `webrtc_frames_gst_SUITE` | README "Receive frames" |
| Congestion control | `src/cc/` | `webrtc_cc_*_tests`, `webrtc_rmcat_tests`, `webrtc_cc_SUITE` | ARCHITECTURE, `rtp.md` RMCAT rows |
| SCTP, data channels | `src/sctp/` | `webrtc_sctp_*_tests`, ETSI corpus, `webrtc_examples_SUITE` | `guides/data-channels.md`, `compliance/sctp.md` |
| Statistics | `src/pc/webrtc_stats.erl`, `webrtc_media_report.erl` | `webrtc_stats_SUITE` | `compliance/stats.md` |
| Safety (redaction, bounds, lifecycle) | `src/webrtc_redact.erl`, `webrtc_registry.erl` | `webrtc_security_SUITE`, `webrtc_lifecycle_SUITE`, `bench/webrtc_soak.erl` | `compliance/security.md` |

## Modules that need better documentation

- `webrtc_pc`: the module doc says what it owns but not how its parts relate. A map at the top would let a contributor change one part without reading 1,095 lines:
  - negotiation glue;
  - ICE restart, automatic and remote;
  - extra transports when unbundled;
  - candidate handling;
  - the signaling helper.
- `webrtc_media`, `webrtc_media_in` and `webrtc_media_out`: a module doc per file saying which of the media session's jobs it does, plus one diagram of the receive and send paths through them (ARCHITECTURE has only the congestion control one).
- `webrtc_transport`, `_net` and `_secure`: the split is explained in ARCHITECTURE. Each module doc should repeat which state it touches.
- `webrtc_jsep`: what the `negotiated/1` map holds and who reads each key. This is the contract between negotiation and transport.

## Modules worth reviewing for size or responsibilities

These are signals, not defects; each has one coherent area.

| Module | What it holds | Primary problem | Suggested first step |
|---|---|---|---|
| `webrtc_pc` (1095 lines, 70 functions) | signaling calls, ICE restart (automatic, remote, glare), extra transports, candidates, signaling helper, stats calls | module organisation | Document its parts first. A later split could take the ICE restart logic (about 15 functions) and the extra transports (`extra_*`, `transport_params`) into their own modules. Tests: `webrtc_pc_SUITE` restart and unbundled cases. |
| `webrtc_media_in` (907) and `webrtc_media_out` (893) | the receive and send halves of the media session, each with RTCP handling | documentation | Module docs and a path diagram; the halves are already the right split. The newer features already live in their own modules (`webrtc_media_limit`, `_sync`, `_fb`). |
| `webrtc_jsep` (911, 27 exports) | the JSEP state machine and the public JSEP API | documentation | Its helpers are already split out (`_build`, `_params`, `_caps`, `_simulcast`, `_transport`); say so in its module doc. |
| `src/transport` (21 modules) | the transport process, mDNS (6 modules), and the media session (11 modules) | navigation, naming | Say it in DEVELOPER_GUIDE now. Moving `webrtc_media*` to `src/media` and mDNS to `src/mdns` later would make the tree match the architecture; no code changes, only paths (and the `include_lib` of three test modules). |
| `webrtc` (661, 44 exports) | the public API; half the module is the options and events edoc | documentation | Move the option and event reference to `docs/REFERENCE.md` (or generate it), and keep short edoc per function. |

Long functions worth a look when they next change:

- `webrtc_sctp_send:commit/4` (111 lines) and `webrtc_sctp_assoc:chunk/4` (107 lines): one clause per chunk type or state, so these are long dispatch functions. They are readable as they are, but they are the ones to split first if they grow.
- `webrtc_sdp_attr:parse_local/2` (113) and `webrtc_stun:decode_value/3` (97): one clause per attribute, which is the right shape for a parser.
- `webrtc_transport:call_/3` (135) and `webrtc_pc:call_/3` (100): every `handle_call` clause in one function; fine for a gen_server, but each clause should stay a one-line delegation.

## "If you want to..." guides for DEVELOPER_GUIDE

Each points to real modules, tests and docs:

- **Add an RTCP feedback message:**
  - codec in `src/rtp/webrtc_rtcp_fb.erl` and `include/webrtc_rtp_rtcp.hrl`;
  - dispatch in `webrtc_media_in:rtcp_packet2/3`;
  - negotiation in `webrtc_jsep_caps`;
  - tests in `webrtc_rtcp_fb_tests`, a raw-format exclusion in `prop_webrtc_rtp`, and a corpus verdict in `webrtc_corpus_tests`;
  - a row in `compliance/rtp.md`. The SLI/RPSI work (#61) is the worked example.
- **Add an RTP header extension:** `webrtc_rtp_ext`, `webrtc_jsep_caps:default_extensions/1`, `webrtc_media_out:header_ext/2`, `webrtc_media_in`; the rapid sync work (#62) is the example.
- **Add a payload format or frame codec:** `src/rtp/webrtc_rtp_<codec>.erl`, `webrtc_frame_codec`, `webrtc_frame_buffer`, `prop_webrtc_frames`, `webrtc_frames_gst_SUITE`.
- **Add a peer connection option:**
  - validation in `webrtc:new_pc/1`;
  - pass it through `webrtc_pc` to JSEP or the transport (the `TOpts` list);
  - document it in REFERENCE;
  - an e2e case.
- **Add a transceiver option:** `webrtc_jsep:add_transceiver/3`, the `#tr{}` record, `webrtc_jsep_params:media_params/4`, then the media session (`priority` is the example).
- **Add an interop peer:** `interop/<peer>/`, `interop/PROTOCOL.md`, `test/interop/webrtc_interop_peer.erl`, a group in `webrtc_pc_interop_SUITE`, `docs/INTEROP.md`, the CI install step.
- **Debug a packet through the stack:**
  - `webrtc_demux:classify/1`;
  - `webrtc_transport_net:datagram/5`;
  - `webrtc_transport_secure` (DTLS, SRTP);
  - `webrtc_media_in:rtp_in/3`;
  - the owner event.
  - Use `webrtc:get_stats(Pc)` (internal format) for the counters and `webrtc_impair` to inject loss.
- **Change how the stack behaves under a hostile peer:**
  - the bounds in `webrtc_media.hrl` (`MAX_STREAMS`, `MAX_ENDED`);
  - `webrtc_media_bounds_tests`, `webrtc_security_SUITE` and `make soak`.

## Diagrams and examples that would help

- Receive path and send path through the media session: datagram, SRTP, media_in, frame buffer, owner; owner, media_out, limiter, pacer, SRTP, socket.
- The process tree with who monitors whom (ARCHITECTURE has the tree, not the monitors).
- How one transceiver becomes RTP streams: media, RTX, FEC, simulcast layers.
- More examples beside `examples/browser_datachannel`: a browser sending video to Erlang (frames), and an Erlang relay forwarding RTP between two browsers. Each would be run by `webrtc_examples_SUITE`, as the data channel one is.

## Questions for the maintainer

1. **The 500-line rule.** DEVELOPER_GUIDE says to split a module before it passes about 500 lines. Thirty modules are past it. Should the rule go, or become "one responsibility per module" with size as a warning?
2. **`src/transport` layout.** Should the media session and mDNS move to their own directories before 0.1.0, while nobody depends on the paths?
3. **`docs/prompts/`.** Should the codec plugin prompt become a guide, move out of the repository, or stay as it is?
4. **Generated API docs.** Should the release publish edoc or ex_doc (hexdocs), and should REFERENCE be generated from it or written by hand?
5. **Public API surface.** `webrtc.erl` exports 44 functions. Are `webrtc_jsep`, `webrtc_sdp` and the engines meant to be usable on their own, or internal? The answer decides what REFERENCE covers.
6. **Supported OTP versions.** `minimum_otp_vsn` is 29. Is that the support policy for 0.1.0?

## Suggested order

1. Before the repository goes public: LICENSE, SECURITY.md, CONTRIBUTING.md, and fix the stale rows and summary (AVPF-6, DTLS-27, the COMPLIANCE summary, the README status line).
2. Before the release: CHANGELOG with the 0.1.0 section, REFERENCE (options and events), DEVELOPER_GUIDE refreshed with the missing modules and the "If you want to..." recipes, and ARCHITECTURE with the media session.
3. After the release:
   - CONCEPTS and the four guides;
   - the ADRs;
   - module docs and the map in `webrtc_pc`;
   - the path diagrams;
   - more examples;
   - any directory moves the maintainer decides on.
