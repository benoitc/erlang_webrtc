# SDP (RFC 8866) and WebRTC attributes

This page tracks the SDP codec: the RFC 8866 grammar and the attribute syntax WebRTC relies on (ICE, DTLS, SCTP, BUNDLE, RTP, simulcast). It covers parsing and encoding only. Offer/answer and JSEP rules (RFC 3264, RFC 9429, RFC 9143 §7) will be added as rows when `webrtc_jsep` lands.

Tests named `name_test` or `name_test_` live in `webrtc_sdp_tests`, unless prefixed with another module. `prop_*` are PropEr properties in `prop_webrtc_sdp`.

## Grammar (RFC 8866)

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| SDP-1 | 5 | Lines are `<type>=<value>` with a single lowercase type letter and no space around `=` | webrtc_sdp | malformed_test_ (bad_line) | Unit tested |
| SDP-2 | 5 | CRLF line ending; LF alone accepted on parse; CRLF always emitted | webrtc_sdp | lf_only_test_, roundtrip_test_ | Unit tested |
| SDP-3 | 5 | Last line without terminator accepted | webrtc_sdp | missing_final_newline_test | Unit tested |
| SDP-4 | 5 | A type letter that is not understood rejects the description | webrtc_sdp | malformed_test_ (unknown_field) | Unit tested |
| SDP-5 | 5, 9 | Session field order and cardinality: v o s [i] [u] *e *p [c] *b 1*(t *r [z]) [k] *a | webrtc_sdp | malformed_test_, prop_random_lines | Unit tested |
| SDP-6 | 5, 9 | Media field order and cardinality: m [i] *c *b [k] *a | webrtc_sdp | malformed_test_ | Unit tested |
| SDP-7 | 5 | Values contain no NUL, CR or LF (byte-string) | webrtc_sdp | malformed_test_ (bad_character) | Unit tested |
| SDP-8 | 5.1 | `v=0` | webrtc_sdp | malformed_test_ (bad_version) | Unit tested |
| SDP-9 | 5.2 | `o=` username, numeric sess-id and sess-version, nettype, addrtype, address | webrtc_sdp | chrome_offer_test, malformed_test_ | Unit tested |
| SDP-10 | 5.2 | sess-id and sess-version kept as integers | webrtc_sdp | prop_encode_parse | Non-compliant / known limitation: leading zeros are dropped on encode. |
| SDP-11 | 5.3 to 5.6 | `s=`, `i=`, `u=`, `e=`, `p=` | webrtc_sdp | rfc8866_example_test | Unit tested |
| SDP-12 | 5.5, 5.6 | `u=`, `e=` and `p=` sub-grammars (RFC 3986, RFC 5322) | webrtc_sdp | | Non-compliant / known limitation: kept as text, not validated beyond the line rules. An empty `s=` is accepted. |
| SDP-13 | 5.7 | `c=` nettype addrtype connection-address, multicast `/ttl/numaddr` kept as written | webrtc_sdp | rfc8866_example_test | Unit tested |
| SDP-14 | 5.7 | `c=` present at session level or in every media description | | | Not implemented: not enforced by the parser, left to JSEP. |
| SDP-15 | 5.8 | `b=` bwtype `:` bandwidth (AS, TIAS, ...) | webrtc_sdp | ice_lite_answer_test, malformed_test_ | Unit tested |
| SDP-16 | 5.9 | `t=` start and stop are `0` or at least 10 digits | webrtc_sdp | rfc8866_example_test, malformed_test_ | Unit tested |
| SDP-17 | 5.10, 5.11 | `r=` repeat interval and typed times, `z=` adjustments with optional `-` | webrtc_sdp | rfc8866_example_test, prop_encode_parse | Unit tested. A `z=` line right after `t=` (RFC 4566 placement) is also accepted. |
| SDP-18 | 5.12 | `k=` prompt, clear, base64, uri | webrtc_sdp | rfc8866_example_test, malformed_test_ | Unit tested |
| SDP-19 | 5.13 | `a=` attribute-name token with optional value; unknown attributes kept in order | webrtc_sdp_attr | rfc8866_example_test, misc_attributes_test | Unit tested |
| SDP-20 | 5.14 | `m=` media, port 0 to 65535, optional `/count`, proto `token *("/" token)`, at least one fmt | webrtc_sdp | malformed_test_ (bad_media, bad_port, bad_proto) | Unit tested |
| SDP-21 | 6.4, 6.5, 6.13 | `ptime`, `maxptime`, `framerate` as non-zero-int-or-real | webrtc_sdp_attr | rfc8866_example_test, simulcast_paused_test | Unit tested |
| SDP-22 | 6.7 | Direction attributes; default `sendrecv`; session level applies to media | webrtc_sdp_media | chrome_answer_test, rfc8866_example_test | Unit tested |
| SDP-23 | 6.6 | `rtpmap` payload type 0 to 127, encoding name, clock rate, optional channels | webrtc_sdp_rtp | chrome_offer_test, malformed_test_ | Unit tested |
| SDP-24 | 6.15 | `fmtp` format and parameters; parameters split on `;`; received text kept and written back when unchanged | webrtc_sdp_rtp | fmtp_raw_preserved_test, firefox_offer_test | Unit tested |
| SDP-25 | 6.10 | `charset` attribute | | | Non-compliant / known limitation: text is handled as bytes, charset is not interpreted. |
| SDP-26 | | `encode(parse(X))` is byte exact for CRLF input written in canonical form | webrtc_sdp | roundtrip_test_ | Unit tested. Lowercase fingerprint hex, upper-case hash names and leading zeros are rewritten in canonical form. |
| SDP-27 | | `parse(encode(R)) =:= {ok, R}` for any valid record | webrtc_sdp | prop_encode_parse | Unit tested |
| SDP-28 | | Encoder refuses values that would break the line structure (CR, LF, NUL, separators) | webrtc_sdp | encode_rejects_line_injection_test | Unit tested |
| SDP-29 | | Malformed, truncated or random input returns `{error, {Line, Reason}}` and never raises | webrtc_sdp | truncation_test_, prop_random_bytes, prop_mutated_sample, prop_random_attribute | Unit tested |

## ICE attributes (RFC 8839 §5, RFC 8840, RFC 6544)

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| SDP-ICE-1 | 8839 5.1 | `candidate`: foundation 1*32 ice-char, component 1 to 256, transport token, priority 1 to 2^31-1, address, port, `typ` host/srflx/prflx/relay or token | webrtc_sdp_candidate | webrtc_sdp_candidate_tests:errors_test_, roundtrip_test_ | Unit tested |
| SDP-ICE-2 | 8839 5.1 | `raddr` and `rport` in position, other extension attributes kept in order | webrtc_sdp_candidate | webrtc_sdp_candidate_tests:fields_test, trickle_candidates_test | Unit tested |
| SDP-ICE-3 | 8839 5.1 | IPv6 selected by the presence of a colon; IPv4 and IPv6 parsed strictly | webrtc_sdp_candidate | trickle_candidates_test, webrtc_sdp_candidate_tests:errors_test_ | Unit tested |
| SDP-ICE-4 | 8839 5.1 | FQDN and mDNS `.local` addresses kept as names | webrtc_sdp_candidate | trickle_candidates_test, webrtc_sdp_candidate_tests:mdns_test | Unit tested. The transport resolves the names (ice.md SDP-3, MDNS-1). |
| SDP-ICE-5 | 6544 4.5 | `tcptype` active/passive/so | webrtc_sdp_candidate | ice_lite_answer_test, webrtc_sdp_candidate_tests:roundtrip_test_ | Unit tested |
| SDP-ICE-6 | 8840 | Standalone `candidate:` value for trickle signaling | webrtc_sdp_candidate | webrtc_sdp_candidate_tests:forms_test, prop_candidate_roundtrip | Unit tested |
| SDP-ICE-7 | 8840 | `end-of-candidates` | webrtc_sdp_attr | trickle_candidates_test, pion_answer_test | Unit tested |
| SDP-ICE-8 | 8839 5.3 | `ice-lite` (session) and `ice-mismatch` (media) | webrtc_sdp_attr | ice_lite_answer_test, misc_attributes_test | Unit tested |
| SDP-ICE-9 | 8839 5.4 | `ice-ufrag` 4 to 256 and `ice-pwd` 22 to 256 ice-char | webrtc_sdp_attr | malformed_test_ | Unit tested |
| SDP-ICE-10 | 8839 5.4 | Media-level `ice-ufrag`/`ice-pwd` take precedence over session level | webrtc_sdp_media | attribute_helpers_test | Unit tested |
| SDP-ICE-11 | 8839 5.6 | `ice-options` tags (trickle, ice2, renomination), media level over session level | webrtc_sdp_attr | trickle_candidates_test | Unit tested |
| SDP-ICE-12 | 8839 5.2 | `remote-candidates` | | | Not implemented: kept as an untyped attribute. |
| SDP-ICE-13 | 8839 5.5 | `ice-pacing` | | | Not implemented: kept as an untyped attribute. |

## DTLS attributes (RFC 8122, RFC 8842, RFC 4145)

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| SDP-DTLS-1 | 8122 5 | `fingerprint`: hash-func SP 2HEX *(":" 2HEX), value decoded to bytes | webrtc_sdp_attr | chrome_offer_test, malformed_test_ | Unit tested |
| SDP-DTLS-2 | 8122 5 | Digest length matches the hash function (sha-1 to sha-512, md5, md2) | webrtc_sdp_attr | ice_lite_answer_test, malformed_test_ | Unit tested |
| SDP-DTLS-3 | 8122 5 | Upper-case hex | webrtc_sdp_attr | misc_attributes_test | Unit tested. Lowercase hex and hash names are accepted on input and written canonically. |
| SDP-DTLS-4 | 8122 5.1 | Several fingerprints per section, in order | webrtc_sdp_attr | misc_attributes_test | Unit tested |
| SDP-DTLS-5 | 8122 5 | Session-level fingerprint applies when the section has none | webrtc_sdp_media | firefox_offer_test, pion_answer_test | Unit tested |
| SDP-DTLS-6 | 4145 4 | `setup` actpass/active/passive/holdconn, media level over session level | webrtc_sdp_attr, webrtc_sdp_media | chrome_answer_test, malformed_test_ | Unit tested. An absent `setup` is reported, not defaulted (RFC 8842 requires it). |
| SDP-DTLS-7 | 8842 4 | `tls-id` 20 to 255 tls-id-char | webrtc_sdp_attr | rfc8866_example_test, malformed_test_ | Unit tested |
| SDP-DTLS-8 | 4145 5 | `connection` new/existing | webrtc_sdp_attr | rfc8866_example_test | Unit tested |

## SCTP attributes (RFC 8841)

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| SDP-SCTP-1 | 4 | `m=application` proto (`UDP/DTLS/SCTP`, `TCP/DTLS/SCTP`) and fmt `webrtc-datachannel` kept as written | webrtc_sdp | chrome_offer_test | Unit tested |
| SDP-SCTP-2 | 5 | `sctp-port` 0 to 65535 | webrtc_sdp_attr | chrome_offer_test, malformed_test_ | Unit tested |
| SDP-SCTP-3 | 6 | `max-message-size` 1*DIGIT | webrtc_sdp_attr | firefox_offer_test, malformed_test_ | Unit tested |
| SDP-SCTP-4 | 5, 6 | No leading zeros | webrtc_sdp_attr | | Non-compliant / known limitation: accepted on parse, never emitted. |
| SDP-SCTP-5 | | Legacy `sctpmap` (draft-ietf-mmusic-sctp-sdp-05) with `DTLS/SCTP` | webrtc_sdp_attr | firefox_legacy_datachannel_test | Unit tested. Parsed for interop, JSEP is not expected to generate it. |

## BUNDLE and grouping (RFC 9143, RFC 5888)

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| SDP-BUNDLE-1 | 5888 5 | `group` semantics *(SP identification-tag) | webrtc_sdp_attr | chrome_offer_test, malformed_test_ | Unit tested |
| SDP-BUNDLE-2 | 5888 4 | `mid` token | webrtc_sdp_attr | chrome_offer_test, malformed_test_ | Unit tested |
| SDP-BUNDLE-3 | 9143 6 | `bundle-only` | webrtc_sdp_attr | misc_attributes_test | Unit tested |
| SDP-BUNDLE-4 | 5888 4 | mid unique within a description | | | Not implemented: left to JSEP. |

## RTP attributes

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| SDP-RTP-1 | 4585 4.2 | `rtcp-fb` payload type or `*`, feedback type and parameters | webrtc_sdp_rtp | chrome_offer_test, misc_attributes_test | Unit tested |
| SDP-RTP-2 | 4585 4.2 | Wildcard feedback applies to every payload type | webrtc_sdp_media | simulcast_paused_test | Unit tested |
| SDP-RTP-3 | 8285 8 | `extmap` id 1 to 255 or 4096 to 4351, optional direction, URI, extension attributes | webrtc_sdp_rtp | firefox_offer_test, ice_lite_answer_test, malformed_test_ | Unit tested |
| SDP-RTP-4 | 8285 6 | `extmap-allow-mixed` | webrtc_sdp_attr | chrome_offer_test | Unit tested |
| SDP-RTP-5 | 5761, 8858 | `rtcp-mux`, `rtcp-mux-only` | webrtc_sdp_attr | simulcast_paused_test | Unit tested |
| SDP-RTP-6 | 5506 | `rtcp-rsize` | webrtc_sdp_attr | chrome_offer_test | Unit tested |
| SDP-RTP-7 | 3605 2.1 | `rtcp` port with optional address | webrtc_sdp_attr | chrome_offer_test, malformed_test_ | Unit tested |
| SDP-RTP-8 | 8830 2 | `msid` id and optional appdata, 1 to 64 token-char each | webrtc_sdp_rtp | chrome_offer_test, malformed_test_ | Unit tested |
| SDP-RTP-9 | | Legacy `msid-semantic` (WMS), text kept as received | webrtc_sdp_rtp | chrome_answer_test, firefox_offer_test | Unit tested |
| SDP-RTP-10 | 5576 4.1 | `ssrc` id 0 to 2^32-1 with `attribute[:value]` | webrtc_sdp_rtp | chrome_offer_test, pion_answer_test | Unit tested |
| SDP-RTP-11 | 5576 4.2 | `ssrc-group` semantics (FID, SIM, FEC-FR, ...) and ssrc list | webrtc_sdp_rtp | chrome_offer_test, firefox_offer_test | Unit tested |
| SDP-RTP-12 | 5576 6.2 | `previous-ssrc` | | | Not implemented: kept as an untyped attribute. |
| SDP-RTP-13 | 3551 6 | Static payload types used when `rtpmap` is absent | webrtc_sdp_media | rfc8866_example_test | Unit tested |

## RID and simulcast (RFC 8851, RFC 8853)

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| SDP-RID-1 | 8851 4, 10 | `rid` id, send/recv, optional `pt=` list and restrictions | webrtc_sdp_rid | firefox_offer_test, simulcast_paused_test, malformed_test_ | Unit tested |
| SDP-RID-2 | 8851 4, 10 | `depend` restriction is a rid-id list | webrtc_sdp_rid | simulcast_paused_test, malformed_test_ | Unit tested |
| SDP-RID-3 | 8851 4, 10 | Value grammar of known restrictions (int and float values) | webrtc_sdp_rid | | Non-compliant / known limitation: only the generic `param-val` grammar is checked; values are kept as text. |
| SDP-SC-1 | 8853 5.1 | `simulcast` send and/or recv, streams separated by `;`, alternatives by `,` | webrtc_sdp_rid | simulcast_paused_test, firefox_offer_test | Unit tested |
| SDP-SC-2 | 8853 5.1 | Paused streams (`~`) | webrtc_sdp_rid | simulcast_paused_test | Unit tested |
| SDP-SC-3 | | Draft syntax (`a=simulcast: send rid=...`) of old Firefox | | | Non-compliant / known limitation: rejected as a malformed attribute. |
| SDP-RID-4 | 8851 6.2.2 step 1 | A malformed `a=rid` line is discarded, not the description | webrtc_sdp | malformed_test_ | Non-compliant / known limitation: the parser rejects the whole description. |

## Other attributes

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| SDP-MISC-1 | 8827 5 | `identity` assertion (base64) and extensions, parse only | webrtc_sdp_attr | misc_attributes_test | Unit tested |
| SDP-MISC-2 | 4574 | `label` token | webrtc_sdp_attr | rfc8866_example_test | Unit tested |
| SDP-MISC-3 | 4796 | `content` comma-separated list | webrtc_sdp_attr | rfc8866_example_test | Unit tested |

## Helpers for JSEP

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| SDP-API-1 | | Codecs of a section merging rtpmap, fmtp and rtcp-fb, and the inverse | webrtc_sdp_media | codecs_inverse_test_, codec_attributes_order_test | Unit tested |
| SDP-API-2 | | Attribute lookup at media level with session-level fallback | webrtc_sdp_media | attribute_helpers_test | Unit tested |

## JSEP (RFC 9429), offer/answer (RFC 3264), BUNDLE (RFC 9143)

| ID | Spec | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| JSEP-1 | 9429 §3.2 | Signaling state machine, invalid transitions refused | webrtc_jsep | invalid_states_test | Unit tested |
| JSEP-2 | 9429 §4.1.10.2, §5.7 | Rollback in every state but stable (offers and provisional answers), same effect through either setter; restores transceivers, DTLS role, tls-id and ICE credentials; remote rollback removes transceivers created by the offer; a rolled back remote ICE restart never reaches the transport | webrtc_jsep, webrtc_pc | glare_rollback_test, remote_rollback_removes_created_transceivers_test, pranswer_rollback_test, ice_restart_rollback_test, webrtc_pc_SUITE:remote_ice_restart_rolled_back | E2E tested |
| JSEP-3 | 9429 §4.1.10.1 | pranswer in both directions; the transport is configured with the provisional answer (connection and data flow before the final answer) unless it carries an ICE restart, which waits for the final answer | webrtc_jsep, webrtc_pc | pranswer_test, webrtc_pc_SUITE:pranswer_connects | E2E tested |
| JSEP-4 | 9429 §5.2.1 | Offer: mid per m= section, BUNDLE group, rtcp-mux, rtcp-rsize, ice-options trickle, fingerprint, setup actpass | webrtc_jsep_build | basic_test | Unit tested |
| JSEP-5 | 9429 §5.2.2 | Subsequent offers keep m= section order and mids | webrtc_jsep_build | renegotiation_keeps_order_and_role_test | Unit tested |
| JSEP-6 | 9429 §5.2.2 | Stopped transceiver rejected with port 0 and removed from BUNDLE | webrtc_jsep_build | stop_transceiver_test | Unit tested |
| JSEP-7 | 9429 §5.3.1 | Answer: one m= section per offered section, same order and mids | webrtc_jsep_build | browser_offer_test_ | Unit tested |
| JSEP-8 | 3264 §6.1 | Direction negotiation | webrtc_jsep_build | directions_test_ | Unit tested |
| JSEP-9 | 3264 §6.1 | Codec intersection with the offerer's payload types; rtx follows its apt | webrtc_jsep_caps | codec_intersection_test, rtx_follows_primary_test | Unit tested |
| JSEP-10 | 3264 §6 | No common codec: section rejected | webrtc_jsep_build | no_common_codec_rejects_section_test | Unit tested |
| JSEP-11 | 9429 §5.10 | Transceiver association, recvonly transceivers created for unmatched offered sections | webrtc_jsep | answer_creates_recvonly_transceiver_test | Unit tested |
| JSEP-12 | 9429 §5.8 | Remote description validation: mid, ICE credentials, fingerprint, setup, rtcp-mux | webrtc_jsep | validation_test_ | Unit tested |
| JSEP-13 | 8842 §5.3, §5.5 | Answer setup active; established DTLS role kept on renegotiation | webrtc_jsep, webrtc_jsep_build | basic_test, renegotiation_keeps_order_and_role_test | Unit tested |
| JSEP-14 | 9429 §5.2.1, 8445 §9 | ICE restart with new credentials | webrtc_jsep | ice_restart_test | Unit tested |
| JSEP-15 | 8285 §5 | Header extension ids from the offer reused in the answer | webrtc_jsep_caps | basic_test | Unit tested |
| JSEP-16 | 9143 | Media not covered by one BUNDLE group | webrtc_jsep | unbundled_media_rejected_test | Non-compliant / known limitation: one transport per peer connection; offers with several unbundled active sections are refused. Browsers bundle by default. |
| JSEP-17 | 8841 §6 | max-message-size defaults to 64 KiB when absent | webrtc_jsep | | Implemented, untested |
| JSEP-18 | 9429 §5.2.1 | Offer: one `a=rid` send line per encoding and `a=simulcast:send` with several, only when sending; rids from the application or generated from a counter; the same lines in later offers | webrtc_jsep_simulcast | webrtc_jsep_simulcast_tests:offer_test, not_sending_no_rid_lines_test, reoffer_keeps_rid_lines_test, encodings_test | Unit tested |
| JSEP-20 | 9429 §5.8.3 | rid-ids of `a=simulcast` exist as `a=rid` lines, otherwise the description is refused | webrtc_jsep | webrtc_jsep_simulcast_tests:unknown_simulcast_rid_rejected_test | Unit tested |
| JSEP-21 | 8851 §6.2.2, §6.3 | Answer to offered send rids: duplicated rid-ids discarded, `pt=` reduced to answered formats (line dropped when none is left, no `pt=` added), unknown `depend` discarded, direction reversed, restrictions and rid-ids kept | webrtc_jsep_simulcast | webrtc_jsep_simulcast_tests:discarded_rid_lines_test, restrictions_alternatives_and_paused_test | Unit tested. Restrictions are not checked against codec parameters (§6.2.2 step 6, §8). |
| JSEP-22 | 8853 §5.3.2 | Answer: `a=simulcast:recv` with the kept rid-ids and alternatives, never more streams; several `a=simulcast` lines disable simulcast; no stream marked paused without pause/resume | webrtc_jsep_simulcast | webrtc_jsep_simulcast_tests:chrome_simulcast_answer_test, firefox_simulcast_answer_test, two_simulcast_lines_disable_simulcast_test, restrictions_alternatives_and_paused_test | Unit tested. RTP pause/resume (RFC 7728) is not implemented, so the offer's `~` marks are reported in `recv_rids` (`paused`) but not repeated. |
| JSEP-23 | 8851 §6.4 | Offerer: answer rid lines with new restrictions, less restrictive values or a `pt=` the offer did not have are discarded; `pt=` lists compared by codec | webrtc_jsep_simulcast | webrtc_jsep_simulcast_tests:answer_restrictions_test_ | Unit tested |
| JSEP-24 | 8853 §5.3.3, 9429 §3.7 | Offerer: rids removed by the answer are not sent; without `a=simulcast` in the answer only the first encoding is sent; pause marks of the answer reported | webrtc_jsep_simulcast | webrtc_jsep_simulcast_tests:answer_removes_and_pauses_layers_test, answer_without_simulcast_test | Unit tested |
| JSEP-25 | 9429 §5.9, 8852 | Layers are negotiated only with the RtpStreamId header extension, and exposed as `send_rids` / `recv_rids` in `negotiated/1` | webrtc_jsep_simulcast | webrtc_jsep_simulcast_tests:no_rid_extension_no_layers_test, erlang_to_erlang_layers_test | Unit tested |
| JSEP-26 | 9429 §3.7 | Sending simulcast in an answer (offer with `a=rid` recv and `a=simulcast:recv`) | | | Not implemented: JSEP defines no API for it; offered recv rids are discarded. Offering recv simulcast is not available either. |
| JSEP-19 | 7874, 7742 | Mandatory codecs offered: Opus, PCMU, PCMA, VP8, H.264 constrained baseline | webrtc_jsep_caps | basic_test | Unit tested (negotiation only; payloads are forwarded, not decoded) |
| JSEP-27 | 9143 §6, 9429 §5.2.1 | A bundle-only m= section (port 0 and a=bundle-only) of a BUNDLE group is accepted, answered with the bundle port and without bundle-only | webrtc_jsep (bundle_view/1) | bundle_only_section_accepted_test, port_zero_without_bundle_only_rejected_test, webrtc_pc_interop_SUITE firefox group | Interoperability tested |
