# RTP and RTCP (RFC 3550, RFC 8834)

This page tracks the RTP and RTCP requirements implemented under `src/rtp` and `src/cc`: the RTP and RTCP codecs, header extensions, feedback messages, receiver statistics, RTCP timing, retransmission, the payload helpers, and congestion control (bandwidth estimation, pacing, circuit breakers). Read it when you need to know whether a packet type or rule is supported before relying on it. Scheduling decisions (when to send a report, which feedback to merge) belong to the transport process and are marked as not implemented here until that process exists. Test names refer to `test/<module>_tests.erl` and to the properties in `test/prop_webrtc_rtp.erl` and `test/prop_webrtc_cc.erl`.

## RFC 3550: RTP data packets

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| RTP-1 | 5.1 | Fixed header: version 2, P, X, CC, M, PT, sequence, timestamp, SSRC | webrtc_rtp | webrtc_rtp_tests:minimal_test, bad_version_test_, prop_rtp_roundtrip | Unit tested |
| RTP-2 | 5.1 | CSRC list of CC (0..15) entries | webrtc_rtp | csrc_and_marker_test | Unit tested |
| RTP-3 | 5.1, A.1 | Padding: last octet counts the padding including itself, at least 1 and no more than the octets after the header | webrtc_rtp | padding_test, padding_only_test, bad_padding_test_ | Unit tested |
| RTP-4 | 5.3.1, A.1 | Header extension: 16-bit profile, length in 32-bit words, length checked against the packet | webrtc_rtp | extension_length_test_, max_extension_length_test | Unit tested |
| RTP-5 | 5.3.1 | Unknown extension profiles are carried and can be ignored | webrtc_rtp | unknown_profile_kept_raw_test | Unit tested |
| RTP-6 | A.1 | Truncated or malformed packets are rejected, never crash | webrtc_rtp | truncation_test, prop_rtp_decode_never_crashes, prop_rtp_mutation_never_crashes | Unit tested |
| RTP-7 | 5.1 | Sequence numbers and timestamps wrap modulo 2^16 and 2^32 | webrtc_rtp_seq | webrtc_rtp_seq_tests:seq_test_, ts_test_, prop_seq_unwrap | Unit tested |
| RTP-8 | 5.1 | Header fields rewritten in place for forwarding | webrtc_rtp | peek_rewrite_test | Unit tested |
| RTP-9 | A.1 | Source validation: probation of MIN_SEQUENTIAL packets, MAX_DROPOUT, MAX_MISORDER, resync after two sequential packets, cycle count | webrtc_rtp_stats | probation_test, probation_restart_test, wraparound_test, misorder_and_dropout_test | Unit tested |
| RTP-10 | A.3 | Expected, cumulative lost clamped to 24-bit signed, fraction lost per interval | webrtc_rtp_stats | loss_and_fraction_test, duplicates_negative_loss_test, lost_clamp_test | Unit tested |
| RTP-11 | 6.4.1, A.8 | Interarrival jitter in timestamp units, robust to timestamp wrap | webrtc_rtp_stats | jitter_test, jitter_ts_wrap_test, jitter_time_unit_test | Unit tested |
| RTP-12 | 6.4.1 | Sender packet and payload octet counts for SR | webrtc_rtp_stats | sender_test | Unit tested |
| RTP-13 | 8.1, 8.2 | Random SSRC choice and collision detection | | | Not implemented (session layer) |

## RFC 3550: RTCP packets

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| RTCP-1 | 6.4.1 | SR: sender info, up to 31 report blocks, profile-specific extension kept | webrtc_rtcp | webrtc_rtcp_tests:sr_sdes_test, sr_with_reports_and_extension_test | Unit tested |
| RTCP-2 | 6.4.2 | RR with report blocks; cumulative lost is signed 24-bit | webrtc_rtcp | rr_remb_test, negative_lost_test | Unit tested |
| RTCP-3 | 6.4.1 | LSR / DLSR and round-trip time A - LSR - DLSR (RFC example: 6.125 s) | webrtc_rtp_stats | lsr_dlsr_test, rtt_rfc_example_test, rtt_wrap_test | Unit tested |
| RTCP-4 | 6.5 | SDES chunks: items, null terminator, 32-bit padding, CNAME, PRIV prefix | webrtc_rtcp | sdes_items_test, sdes_empty_chunk_layout_test, sdes_errors_test_ | Unit tested |
| RTCP-5 | 6.6 | BYE with SSRC list and optional reason padded with null octets | webrtc_rtcp | bye_test | Unit tested |
| RTCP-6 | 6.7 | APP with subtype, 4-octet name and data | webrtc_rtcp | app_test | Unit tested |
| RTCP-7 | 6.1, A.2 | Version 2 on every packet; lengths add up to the datagram size | webrtc_rtcp | compound_validation_test_, truncation_test_ | Unit tested |
| RTCP-8 | 6.1, A.2 | Compound check (`mode => compound`): first packet SR or RR, padding only on the last packet | webrtc_rtcp | compound_validation_test_ | Unit tested |
| RTCP-9 | 6.1 | Compound packet carries an SDES CNAME (`validate_compound/1`) | webrtc_rtcp | sr_sdes_test, rr_remb_test, has_cname_test | Unit tested |
| RTCP-10 | 6.4.1, A.2 | Padding count valid (1..length) | webrtc_rtcp | padding_test_ | Unit tested |
| RTCP-11 | A.2 | Unknown packet types kept as raw, the others still decoded | webrtc_rtcp | unknown_type_preserved_test, prop_rtcp_roundtrip | Unit tested |
| RTCP-12 | 6.1 | Truncated or corrupted RTCP returns an error, never crashes | webrtc_rtcp | truncation_test_, prop_rtcp_decode_never_crashes, prop_rtcp_mutation_never_crashes | Unit tested |
| RTCP-13 | 6.4.2 | More than 31 sources need several RR packets | webrtc_rtcp | sr_with_reports_and_extension_test (32 blocks rejected) | Not implemented: encode rejects more than 31 blocks, splitting them across packets is left to the caller |
| RTCP-14 | 6.2, 6.3.1, A.7 | Interval: senders / receivers bandwidth split, Tmin, randomisation in [0.5, 1.5), e - 3/2 compensation | webrtc_rtcp_interval | webrtc_rtcp_interval_tests:deterministic_test_, randomised_test_ | Unit tested |
| RTCP-15 | 6.2, A.7 | Initial interval uses half the minimum | webrtc_rtcp_interval | min_interval_test_ | Unit tested |
| RTCP-16 | 6.3.3 | avg_rtcp_size moving average (1/16) | webrtc_rtcp_interval | avpf_helpers_test_ | Unit tested |
| RTCP-17 | 6.3.5 | Participant timeout M * Td, M = 5 | webrtc_rtcp_interval | timeout_test_ | Unit tested |
| RTCP-18 | 6.3.6 | Timer reconsideration on expiry | webrtc_rtcp_interval | reconsider_test_ | Unit tested |
| RTCP-19 | 6.3.4 | Reverse reconsideration after BYE | webrtc_rtcp_interval | reverse_reconsider_test_ | Unit tested |
| RTCP-20 | 6.3, A.7 | RTCP scheduler state: tp, tn, average compound size (lower layers counted), members and senders from the streams, we_sent, RTCP bandwidth 5% of the session (both directions of the send estimate), interval reconsidered at expiry and moved closer when members leave | webrtc_rtcp_sched, webrtc_media | webrtc_rtcp_sched_tests, webrtc_media_tests:many_sources_reported_test | Unit tested; the BYE back-off of §6.3.7 is not needed point to point (we send no BYE flood) |
| RTCP-21 | 6.4, 6.4.2 | Report blocks for every received source: 31 in the first SR or RR, more in RR packets that follow it, each source once per compound, the compound kept under 1150 bytes before SRTCP; when not all fit, the first source reported rotates and a source's interval statistics only advance when it is reported | webrtc_media_out | webrtc_media_tests:many_sources_reported_test | Unit tested |

## RFC 8834: RTP usage in WebRTC

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| WRTP-1 | 4.1 | Send and receive SR, RR, SDES and BYE | webrtc_rtcp | webrtc_rtcp_tests:sr_sdes_test, rr_remb_test, bye_test | Unit tested |
| WRTP-2 | 4.1 | RTCP SDES MID item (RFC 9143 §15.1) | webrtc_rtcp | sdes_items_test | Unit tested |
| WRTP-3 | 4.1 | Reception of CSRC lists | webrtc_rtp | csrc_and_marker_test | Unit tested |
| WRTP-4 | 4.1 | Reduced minimum interval 360 / kbps (RFC 3550 §6.2) | webrtc_rtcp_interval | min_interval_test_ | Unit tested |
| WRTP-5 | 4.1 | Non-reduced minimum used for the participant timeout | webrtc_rtcp_interval | timeout_test_ | Unit tested |
| WRTP-6 | 4.1 | Timer reconsideration and reverse reconsideration | webrtc_rtcp_interval | reconsider_test_, reverse_reconsider_test_ | Unit tested |
| WRTP-7 | 4.1 | Ignore unknown RTCP packet types and header extensions while processing the known ones | webrtc_rtcp, webrtc_rtp | unknown_type_preserved_test, unknown_profile_kept_raw_test | Unit tested |
| WRTP-8 | 4.5 | RTP and RTCP multiplexed on one flow (RFC 5761) | webrtc_rtp | classify_test_ | Unit tested |
| WRTP-9 | 4.6 | Receive and send non-compound RTCP (RFC 5506) | webrtc_rtcp | compound_validation_test_ | Unit tested |
| WRTP-10 | 5.1.1 | Understand FIR | webrtc_rtcp_fb | webrtc_rtcp_fb_tests:fir_test | Unit tested |
| WRTP-11 | 5.1.2 | Understand PLI | webrtc_rtcp_fb | pli_test | Unit tested |
| WRTP-12 | 5.1.3 | SLI | webrtc_rtcp_fb | sli_test | Unit tested |
| WRTP-13 | 5.1.4 | RPSI | webrtc_rtcp_fb | afb_other_raw_test (kept raw) | Not implemented: decoded as `#rtcp_raw{}` |
| WRTP-14 | 5.1.6 | Understand TMMBR, answer with TMMBN | webrtc_rtcp_fb | tmmbr_test, tmmbn_test | Unit tested (codec only; the bounding set of RFC 5104 §3.5.4 is not implemented) |
| WRTP-15 | 5.2 | Header extensions follow RFC 8285 | webrtc_rtp_ext | webrtc_rtp_ext_tests | Unit tested |
| WRTP-16 | 5.2.1 | Rapid synchronisation (RFC 6051) | | | Not implemented |
| WRTP-17 | 5.2.2 | Client-to-mixer audio level (RFC 6464), sent with the `audio_level` option of `send_rtp`, encrypted with RFC 6904 when negotiated (the capability is required, its use recommended) | webrtc_rtp_ext, webrtc_media_out | audio_level_test, webrtc_pc_SUITE:header_extension_encryption, webrtc_pc_interop_SUITE:erlang_sends_audio_level, peer_sends_audio_level | Interoperability tested in clear (Chromium and Firefox read our level, we read theirs); encrypted between Erlang peers |
| WRTP-18 | 5.2.4 | MID header extension | webrtc_rtp_ext | sdes_test | Unit tested |
| WRTP-19 | 5.2.5 | Video orientation (CVO) header extension | webrtc_rtp_ext | video_orientation_test | Unit tested |
| WRTP-20 | 6.1 | Senders understand generic NACK | webrtc_rtcp_fb, webrtc_nack_buffer | nack_test, webrtc_nack_buffer_tests:buffer_test | Unit tested |
| WRTP-21 | 6.1 | Receivers support RTX with SSRC multiplexing (RFC 4588) | webrtc_rtx | webrtc_rtx_tests:rtx_test | Unit tested |
| WRTP-22 | 6.1 | RTT estimate from SR / RR to decide on retransmission | webrtc_rtp_stats, webrtc_nack_buffer | rtt_rfc_example_test, buffer_test | Unit tested |
| WRTP-23 | RFC 3550 §6.6, §6.3.5 | Receive streams end with a BYE or after 60 s without packets: receiver, NACK, rid, RTX and SRTP state removed; at most 16 receive streams per transceiver and 256 per session, packets of further SSRCs dropped (`too_many_streams`); SSRCs learned from packets kept across renegotiation only while live | webrtc_media_in, webrtc_media | webrtc_media_tests:ssrc_churn_bounded_test, bye_removes_stream_test | Unit tested |

## RFC 4585: RTP/AVPF

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| AVPF-1 | 6.1 | Feedback header: FMT, PT 205 / 206, sender and media SSRC | webrtc_rtcp_fb | nack_errors_test_, prop_rtcp_roundtrip | Unit tested |
| AVPF-2 | 6.2.1 | Generic NACK: one or more PID / BLP items | webrtc_rtcp_fb | nack_test, nack_errors_test_ | Unit tested |
| AVPF-3 | 6.2.1 | Conversion between lost sequence numbers and PID / BLP, across wraparound | webrtc_rtcp_fb | nack_helpers_test_, prop_nack_items | Unit tested |
| AVPF-4 | 6.3.1 | PLI has no FCI (length 2) | webrtc_rtcp_fb | pli_test | Unit tested |
| AVPF-5 | 6.3.2 | SLI: First, Number, PictureID | webrtc_rtcp_fb | sli_test | Unit tested |
| AVPF-6 | 6.3.3 | RPSI | | | Not implemented (kept raw) |
| AVPF-7 | 6.4 | Application layer feedback other than REMB kept raw | webrtc_rtcp_fb | afb_other_raw_test | Unit tested |
| AVPF-8 | 3.4 d, 3.5.1 | Initial Tmin 0 point-to-point, 1 s multiparty | webrtc_rtcp_interval | min_interval_test_ | Unit tested |
| AVPF-9 | 3.5.3 | Tmin is 0 after the first regular report | webrtc_rtcp_interval | min_interval_test_ | Unit tested |
| AVPF-10 | 3.5.2 | T_dither_max: 0 point-to-point, l * T_rr with l = 0.5 otherwise | webrtc_rtcp_interval | avpf_helpers_test_ | Unit tested |
| AVPF-11 | 3.5.3 | T_rr_current_interval = RND * T_rr_interval, RND in [0.5, 1.5) | webrtc_rtcp_interval | avpf_helpers_test_ | Unit tested |
| AVPF-12 | 3.5.3 | Timeout uses T_rr_interval instead of Tmin when set | webrtc_rtcp_interval | timeout_test_ | Unit tested |
| AVPF-13 | 3.5.2, 3.5.3 | Feedback point to point (T_dither_max 0): sent at once while the RTCP bandwidth allows (budget of one second of it, at least one datagram), otherwise kept (at most 32 packets) until it does or merged into a regular report that comes first; regular reports no closer than the local T_rr_interval (`rtcp_report_interval`, default 1 s), the first one after the AVPF initial interval | webrtc_rtcp_sched, webrtc_media_out | webrtc_rtcp_sched_tests:feedback_budget_test, report_interval_floor_test, first_report_early_test | Unit tested: feedback over the budget waits for the budget rather than for the next regular report as early mode does, which would make retransmission requests and congestion feedback too late; feedback suppression of multiparty sessions is not implemented |

## RFC 5104: codec control messages

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| CCM-1 | 4.2.1 | TMMBR FCI: SSRC, 6-bit exponent, 17-bit mantissa, 9-bit overhead | webrtc_rtcp_fb | tmmbr_test | Unit tested |
| CCM-2 | 4.2.1.1 | Exponent and mantissa chosen so the encoded rate never exceeds the requested one | webrtc_rtcp_fb | bitrate_precision_test | Unit tested |
| CCM-3 | 4.2.2 | TMMBN, including an empty bounding set | webrtc_rtcp_fb | tmmbn_test | Unit tested |
| CCM-4 | 4.3.1 | FIR: media SSRC 0, FCI SSRC and sequence number, reserved bits ignored | webrtc_rtcp_fb | fir_test | Unit tested |
| CCM-5 | 3.5.4 | TMMBR bounding set computation | | | Not implemented |
| CCM-6 | 4.3.2, 4.3.4 | TSTR / TSTN, VBCM | | | Not implemented (kept raw) |

## RFC 8285: header extensions

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| EXT-1 | 4.2 | One-byte form: profile 0xBEDE, ids 1..14, 1..16 data bytes | webrtc_rtp_ext | one_byte_figure_test, encode_one_byte_test | Unit tested |
| EXT-2 | 4.2 | Id 15 ends processing, its length ignored; earlier elements kept | webrtc_rtp_ext | id15_stops_test | Unit tested |
| EXT-3 | 4.3 | Two-byte form: profile 0x100 + appbits, ids 1..255, 0..255 data bytes, appbits ignored on receive | webrtc_rtp_ext | two_byte_figure_test, encode_forced_form_test_ | Unit tested |
| EXT-4 | 4.1 | Zero padding bytes between elements and up to the 32-bit boundary | webrtc_rtp_ext | one_byte_figure_test, one_byte_errors_test_ | Unit tested |
| EXT-5 | 4.2 | Id 0 is reserved for padding, not an element | webrtc_rtp_ext | one_byte_errors_test_ | Unit tested |
| EXT-6 | 6 | Mixed one-byte / two-byte use (extmap-allow-mixed): the encoder picks the two-byte form only when an element needs it | webrtc_rtp_ext | encode_auto_two_byte_test_, prop_ext_roundtrip | Unit tested |
| EXT-7 | 4.1 | Malformed element lists rejected without crashing | webrtc_rtp_ext | every_truncation_test, bad_rfc8285_ext_test, prop_rtp_mutation_never_crashes | Unit tested |
| EXT-8 | 6 | Only negotiated ids sent; two-byte form only with extmap-allow-mixed | | | Not implemented (SDP layer chooses the form) |

## RFC 4588: retransmission

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| RTX-1 | 4 | Payload is the OSN followed by the original payload | webrtc_rtx | rtx_test | Unit tested |
| RTX-2 | 4 | Timestamp equal to the original timestamp | webrtc_rtx | rtx_test | Unit tested |
| RTX-3 | 4 | SSRC multiplexing: distinct SSRC, own sequence numbers, RTX payload type | webrtc_rtx | rtx_test | Unit tested |
| RTX-4 | 4 | Packets without an OSN (padding only) are not retransmissions | webrtc_rtx | rtx_padding_only_test | Unit tested |
| RTX-5 | 5.3 | Receiver associates the RTX SSRC with the original stream (apt, rid / repaired-rid) | webrtc_media, webrtc_media_rid | webrtc_media_tests:nack_rtx_test, webrtc_media_simulcast_tests:layer_nack_rtx_test | Unit tested: `ssrc-group:FID` when announced, repaired-rid otherwise |
| RTX-6 | 6 | Sender keeps sent packets and avoids resending within one RTT | webrtc_nack_buffer | buffer_test, buffer_max_age_test | Unit tested |

## RFC 8852 and RFC 8853: RTP stream identifiers and simulcast

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| RID-1 | 8851 4, 8852 3.1 | Every layer sent has its own SSRC and RTX SSRC and carries the MID and RtpStreamId header extensions | webrtc_media | webrtc_media_simulcast_tests:send_layers_test | Unit tested |
| RID-2 | 8851 4, 8852 3.2 | Retransmissions of a layer carry RepairedRtpStreamId, not RtpStreamId | webrtc_media | webrtc_media_simulcast_tests:layer_nack_rtx_test | Unit tested |
| RID-3 | 8852 4, 8853 6.1 | RTCP SDES with the MID and RtpStreamId items for every sent layer, and a sender report per layer | webrtc_media | webrtc_media_simulcast_tests:sdes_teaches_layers_test | Unit tested |
| RID-4 | 9143 9.2, 8852 3.1 | Layers without `a=ssrc` lines demultiplexed by MID and rid; the SSRC is learned from the first packet, later packets may omit the extensions | webrtc_media_rid | webrtc_media_simulcast_tests:receive_layers_test, classify_test | Unit tested, E2E (webrtc_pc_SUITE:simulcast_layers), interop (Chromium) |
| RID-5 | 8852 3.2 | RTX stream of a layer bound by repaired-rid; repair packets before their layer is known are dropped | webrtc_media_rid | webrtc_media_simulcast_tests:layer_nack_rtx_test, classify_test | Unit tested |
| RID-6 | 8852 4 | SSRC to rid mapping learned from RTCP SDES | webrtc_media_rid | webrtc_media_simulcast_tests:sdes_test, sdes_teaches_layers_test | Unit tested |
| RID-7 | 8853 5.2 | Streams with a rid that was not negotiated, or without any rid in a simulcast section, are not delivered | webrtc_media_rid | webrtc_media_simulcast_tests:unknown_rid_dropped_test, classify_test | Unit tested (counter `unknown_rid`) |
| RID-8 | 8853 6.1, 4585 | NACK, RTX and PLI per layer SSRC; keyframe request for one layer both ways | webrtc_media | webrtc_media_simulcast_tests:layer_nack_rtx_test, layer_keyframe_test | Unit tested, E2E, interop (Chromium reports the PLI on the requested layer only) |
| RID-9 | 8853 5.2, 5.3, RFC 7728 | Pause and resume of one layer; a layer the answer marks paused (`~`) starts paused and is resumed by RESUME once its SSRC is known from SDES | webrtc_media_pause | webrtc_media_simulcast_tests:layer_pause_test, answer_paused_layer_test, webrtc_pc_SUITE:simulcast_answerer | E2E tested |

## RFC 7728: RTP stream pause and resume

No independent implementation answers these messages (browsers, Pion and aiortc ignore them), so the rows stop at E2E tested.

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| PAUSE-1 | 8.1 | PAUSE-RESUME messages: RTPFB FMT 9, media SSRC 0, Target SSRC, Type, PauseID, PAUSED with the extended sequence number; reserved types ignored, unknown type specific data skipped | webrtc_rtcp_fb | webrtc_rtcp_fb_tests:pause_test, prop_webrtc_rtp:prop_rtcp_roundtrip | Unit tested |
| PAUSE-2 | 9 | `a=rtcp-fb:* ccm pause` offered with `nowait` for video; an offer is answered with the full implementation (config 1), `nowait` only when offered | webrtc_jsep_caps, webrtc_jsep_params | webrtc_jsep_caps_tests | Unit tested |
| PAUSE-3 | 6.2, 8.1 | Sender: PAUSE with the current PauseID pauses (at once with `nowait`, after the hold-off otherwise; a RESUME during the hold-off cancels it), RESUME resumes and moves to the next PauseID, other PauseIDs are refused with REFUSED, a past RESUME while playing is ignored | webrtc_rtp_pause | webrtc_rtp_pause_tests | Unit tested |
| PAUSE-4 | 6.2 | PAUSED sent on pausing and repeated in the next two regular reports | webrtc_rtp_pause, webrtc_media_pause | webrtc_rtp_pause_tests:pause_resume_test | Unit tested |
| PAUSE-5 | 6.1, 6.4 | Requester: PAUSE and RESUME retransmitted after 2 * RTT + T_dither_max (500 ms without an RTT) until PAUSED, REFUSED or, for RESUME, the stream's packets; the PauseID follows PAUSED and REFUSED | webrtc_rtp_pause | webrtc_rtp_pause_tests:requester_test | Unit tested |
| PAUSE-6 | 6.2 | A paused stream is not sent: `send_rtp` returns `{error, paused}` and the application is told (`stream_paused`, `stream_resumed`) | webrtc_media_pause | webrtc_pc_SUITE:pause_resume | E2E tested |
| PAUSE-7 | 6.2 | Local pause by the sender, resume on BYE or time-out of the requester, TMMBR 0 as pause | | | Not implemented |

## RFC 5761 and RFC 8858: rtcp-mux

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| MUX-1 | RFC 5761 §4 | Demultiplex by the second octet: 192..223 is RTCP | webrtc_rtp | classify_test_ | Unit tested |
| MUX-2 | RFC 5761 §4 | RTP payload types 64..95 MUST NOT be used when multiplexing | | | Not implemented: the codec accepts any payload type; the SDP layer must not offer 64..95 |
| MUX-3 | RFC 8858 §4 | rtcp-mux-only negotiation | | | Not implemented (SDP layer) |

## RFC 5506: reduced-size RTCP

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| RSIZE-1 | 3.4.2, 4.1 | Accept RTCP datagrams that do not start with SR / RR | webrtc_rtcp | compound_validation_test_ | Unit tested |
| RSIZE-2 | 5 | Compound checks still available for peers that did not negotiate rtcp-rsize | webrtc_rtcp | compound_validation_test_ | Unit tested |
| RSIZE-3 | 4.1, 5 | Regular reports are always compound; feedback alone only when rtcp-rsize is negotiated on every section, otherwise in a compound with an RR and the CNAME | webrtc_media_out | webrtc_media_tests:compound_feedback_without_rsize_test, reduced_size_feedback_test | Unit tested |

## Congestion control feedback

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| CC-1 | RFC 8888 §3.1 | Report blocks: SSRC, begin_seq, num_reports metric blocks of R, ECN, ATO; report timestamp | webrtc_rtcp_ccfb | webrtc_rtcp_ccfb_tests:ccfb_test, ccfb_multi_and_empty_test | Unit tested |
| CC-2 | RFC 8888 §3.1 | Odd number of metrics followed by 16 bits of zero padding | webrtc_rtcp_ccfb | ccfb_test | Unit tested |
| CC-3 | RFC 8888 §3.1 | R = 0: ECN and ATO ignored | webrtc_rtcp_ccfb | ccfb_not_received_ignores_bits_test | Unit tested |
| CC-4 | RFC 8888 §3.1 | At most 16384 metric blocks per report block | webrtc_rtcp_ccfb | ccfb_limits_test_ | Unit tested |
| CC-5 | RFC 8888 §3.1 | ATO in 1/1024 s; 0x1FFE over range, 0x1FFF unavailable | webrtc_rtcp_ccfb | ato_test_ | Unit tested |
| CC-6 | RFC 8888 §3.1 | num_reports counts metric blocks (range begin_seq to begin_seq + num_reports - 1, reported erratum) | webrtc_rtcp_ccfb | ccfb_test | Unit tested |
| TWCC-1 | draft-holmer-01 §2 | Transport-wide sequence number header extension | webrtc_rtp_ext | twcc_seq_test | Unit tested |
| TWCC-2 | draft-holmer-01 §3.1 | Feedback header: base sequence, status count, 24-bit signed reference time (64 ms), feedback count | webrtc_rtcp_twcc | webrtc_rtcp_twcc_tests:mixed_test | Unit tested |
| TWCC-3 | draft-holmer-01 §3.1.3 | Run length chunks (draft example 1) | webrtc_rtcp_twcc | run_length_example_test, run_length_received_test, long_run_cut_test | Unit tested |
| TWCC-4 | draft-holmer-01 §3.1.4 | One-bit and two-bit status vector chunks (draft example 1); chunks cut at the status count | webrtc_rtcp_twcc | one_bit_vector_example_test, mixed_test, status_count_cuts_vector_test | Unit tested |
| TWCC-5 | draft-holmer-01 §3.1.1 | Symbol 11 is reserved and rejected (draft example 2 uses it) | webrtc_rtcp_twcc | reserved_symbol_test | Unit tested |
| TWCC-6 | draft-holmer-01 §3.1.5 | Receive deltas in 250 us: 8-bit unsigned small, 16-bit signed large | webrtc_rtcp_twcc | mixed_test, prop_twcc_roundtrip | Unit tested |
| TWCC-7 | draft-holmer-01 §3.1.5 | A delta that does not fit 16 bits starts a new feedback message | webrtc_rtcp_twcc | from_arrivals_split_test, prop_twcc_arrivals | Unit tested |
| TWCC-8 | libwebrtc | Padding with zero bytes or with the P bit | webrtc_rtcp_twcc | mixed_test, padding_bit_test | Unit tested |
| CC-7 | RFC 8888 §3, §4 | Generate CCFB for received packets and use received CCFB as estimator input | | | Not implemented: codec only; the estimator uses transport-wide feedback, which every browser sends |
| TWCC-9 | draft-holmer-01 §2 | Every RTP packet of the transport (media and retransmissions, all transceivers) carries the next transport-wide sequence number when the peer accepted the extension | webrtc_cc, webrtc_media | webrtc_media_cc_tests:transport_wide_sequence_test, webrtc_cc_tests:twcc_seq_test | Unit tested |
| TWCC-10 | draft-holmer-01 §3 | Receiver: feedback every 100 ms (`twcc_interval`) and on demand; numbers lost between two messages are reported; a late packet is reported in the next message with the range repeated from a bounded history; bounded pending arrivals | webrtc_twcc_receiver | webrtc_twcc_tests:interval_test, loss_between_feedbacks_test, late_packet_test, bounded_pending_test, gap_is_not_loss_test, prop_webrtc_cc:prop_twcc_feedback_roundtrip | Unit tested |
| TWCC-11 | draft-holmer-01 §3 | Sender: feedback mapped back to send time, arrival time and size; repeated reports ignored, lost then received reported again; bounded history (8192 packets, 10 s) | webrtc_twcc_sender | round_trip_test, wraparound_test, duplicate_feedback_test, unknown_and_old_test, age_limit_test | Unit tested |
| TWCC-12 | draft-holmer-01 §3 | Feedback between two peers over UDP drives the sender's estimate | webrtc_media, webrtc_cc | webrtc_media_cc_tests:feedback_round_trip_test, webrtc_cc_SUITE | E2E tested |
| REMB-1 | draft-alvestrand-rmcat-remb-03 §2.2 | PSFB FMT 15 "REMB": SSRC count, 6-bit exponent, 18-bit mantissa, SSRC list | webrtc_rtcp_fb | remb_test, rr_remb_test | Unit tested |
| REMB-2 | draft-alvestrand-rmcat-remb-03 §2 | A received REMB bounds the estimate; without transport-wide feedback it is the estimate | webrtc_gcc | webrtc_gcc_tests:remb_test, webrtc_media_cc_tests:remb_test | Unit tested |
| XR-1 | RFC 3611 §4.4 | Receiver Reference Time report block | webrtc_rtcp_xr | webrtc_rtcp_xr_tests:xr_test, xr_errors_test_ | Unit tested |
| XR-2 | RFC 3611 §4.5 | DLRR report block with sub-blocks | webrtc_rtcp_xr | xr_test, xr_errors_test_ | Unit tested |
| XR-3 | RFC 3611 §3 | Other block types kept with their type-specific byte | webrtc_rtcp_xr | xr_unknown_block_test | Unit tested |

## Congestion control (RFC 8836, draft-ietf-rmcat-gcc-02)

The estimator is Google Congestion Control on the sender side, fed by transport-wide feedback (`webrtc_gcc`, `webrtc_gcc_delay`, `webrtc_gcc_aimd`). "sim" means the seeded bottleneck simulation of `test/webrtc_cc_sim.erl` and `test/webrtc_cc_link.erl` (one or two flows, 20 ms propagation delay each way, drop-tail queue of 300 ms), run by `webrtc_gcc_tests`.

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| GCC-1 | gcc-02 §5.2 | Pre-filtering: packets sent within burst_time (5 ms) form a group; a burst arriving after an outage is merged; out of order packets ignored | webrtc_gcc_delay | webrtc_gcc_tests:reordering_and_burst_test | Unit tested |
| GCC-2 | gcc-02 §5.3 | Arrival-time filter estimating m(i) from the inter-group delay variation | webrtc_gcc_delay | constant_delay_is_normal_test, growing_queue_is_overuse_test, draining_queue_is_underuse_test | Unit tested: trendline estimator of libwebrtc (window 20, smoothing 0.9, gain 4), which the draft allows ("any adaptive filter"); the Kalman filter of the draft is not implemented |
| GCC-3 | gcc-02 §5.4 | Over-use after overuse_time_th (10 ms) above the adaptive threshold and m(i) not decreasing; under-use below minus the threshold; threshold not updated when the estimate exceeds it by more than 15, clamped to [6, 600], starting at 12.5 | webrtc_gcc_delay | growing_queue_is_overuse_test, draining_queue_is_underuse_test | Unit tested: K_u = 0.0087 and K_d = 0.039 from libwebrtc's trendline detector, not the draft values (0.01, 0.00018) tuned for the Kalman filter output |
| GCC-4 | gcc-02 §5.5 | Hold / Increase / Decrease transition table | webrtc_gcc_aimd | aimd_transitions_test | Unit tested |
| GCC-5 | gcc-02 §5.5 | Multiplicative increase at most 8% per second far from convergence, additive (half a packet per RTT + 100 ms) near the average of previous decreases (EMA 0.95, three standard deviations), A_hat < 1.5 R_hat | webrtc_gcc_aimd | aimd_increase_test | Unit tested; R_hat is the acknowledged rate over 500 ms of arrivals |
| GCC-6 | gcc-02 §5.5 | Decrease to beta R_hat, beta = 0.85 | webrtc_gcc_aimd | aimd_decrease_test | Unit tested; never above the current estimate, again only after one RTT unless R_hat fell below half the estimate (libwebrtc) |
| GCC-7 | gcc-02 §6 | Loss-based controller: below 2% x 1.05, 2% to 10% held, above 10% x (1 - 0.5 p); target = min(delay-based, loss-based) | webrtc_gcc | loss_decrease_test, loss_decrease_negative_clock_test, moderate_loss_holds_test, loss_report_test, loss_report_then_feedback_test, sim random_loss_test_, webrtc_cc_SUITE | E2E tested; the ratio is taken over at least 20 packets or one second, every packet counts until a decrease and only packets sent after it count then, decreases at most once per 300 ms + RTT; RTCP receiver reports are used while no transport-wide feedback arrived, and the first transport-wide feedback releases the estimate they seeded |
| GCC-8 | gcc-02 §5.5 | Bounded memory, deterministic with injected time | webrtc_gcc, webrtc_cc | sim deterministic_test_ | Unit tested |
| R8836-1 | RFC 8836 §2 (1) | Low delay: queuing delay kept low once converged | webrtc_gcc | sim converges_500k_test_, converges_2m_test_, converges_10m_test_ | Simulated: average target 0.95, 0.94 and 0.91 of the capacity at 500 kbps, 2 Mbps and 10 Mbps, average bottleneck queue 22 to 28 ms |
| R8836-2 | RFC 8836 §2 (1c, 1d) | React quickly to a capacity reduction | webrtc_gcc | sim capacity_drop_test_, webrtc_cc_SUITE:estimate_follows_capacity_drop | Simulated and E2E tested: 2 Mbps to 500 kbps, the target is below 600 kbps within 2 s and the queue drains within 4 s |
| R8836-3 | RFC 8836 §2 (2) | Fair to other instances of itself | webrtc_gcc | sim fairness_test_ | Simulated: two flows on 2 Mbps, the second starting 5 s later, share within a factor of 1.3 after a minute (test bound 1.5), using 0.94 of the link together |
| R8836-4 | RFC 8836 §2 (3) | Do not starve competing TCP flows, avoid being starved | | | Not tested: the simulator has no TCP cross traffic |
| R8836-5 | RFC 8836 §2 (4) | Adapt quickly at the start of a flow | webrtc_cc_probe, webrtc_gcc_aimd | sim probing_startup_test_, probing_slow_link_test_, webrtc_cc_SUITE:probing_fills_link_at_start | Simulated and E2E tested: probe clusters at 3 and 6 times the start bitrate, then at twice each good result, take a 2 Mbps link to 70% in 200 ms against 4 s without probing; on a 500 kbps link the result stays at what got through. Later probes (PROBE-6 to PROBE-8) adapt quickly again when the application was limited, after a drop and on a raised maximum |
| R8836-6 | RFC 8836 §2 (5) | Stable when streams pause or are rate limited | webrtc_gcc_aimd | aimd_increase_test | Unit tested: the estimate does not grow beyond 1.5 R_hat + 10 kbps |
| R8836-7 | RFC 8836 §2 (6) | One estimate for all streams of the transport | webrtc_cc | webrtc_media_cc_tests:transport_wide_sequence_test | Implemented: one estimate per BUNDLE transport; the split between streams is left to the application |
| R8836-8 | RFC 8836 §2 (8) | Feedback over RTCP with AVPF | webrtc_media | webrtc_media_cc_tests:feedback_round_trip_test | Unit tested |
| R8836-9 | RFC 8836 §2 (9) | Use DSCP markings | | | Not implemented |
| R8836-10 | RFC 8836 §2 (10) | React to a lack of feedback | webrtc_gcc | feedback_timeout_test | Unit tested: 20% cut per `feedback_timeout` (1.5 s) while sending without feedback |
| R8836-11 | RFC 8836 §2 (11) | Stable with AQM | | | Not tested (drop-tail only) |
| NADA-1 | RFC 8698 | NADA congestion control | | | Not implemented |

## Bandwidth probing

| ID | Source | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| PROBE-1 | libwebrtc ProbeController | With transport-wide feedback, the first video packet starts clusters at 3 and 6 times the start bitrate, each at least 15 ms at its rate and 5 packets, paced at its rate | webrtc_cc_probe | webrtc_cc_probe_tests:initial_clusters_test | Unit tested |
| PROBE-2 | libwebrtc ProbeBitrateEstimator | Result from the cluster's feedback: at least 80% received, send and receive intervals within 1 s, the smaller of the send and receive rates, 95% of the receive rate when below 90% of the send rate | webrtc_cc_probe | estimate_test, lost_probe_test, no_feedback_test | Unit tested |
| PROBE-3 | libwebrtc ProbeController | A result of at least 70% of the probed rate probes again at twice it, up to `max_bitrate` | webrtc_cc_probe | estimate_test | Unit tested |
| PROBE-4 | libwebrtc DelayBasedBwe, SendSideBandwidthEstimation | The delay-based estimate takes a probe result unless over-use is detected; the loss-based estimate is lifted to it too (a lower `max_bitrate` or a feedback timeout may have cut it) | webrtc_gcc | sim probing_startup_test_, webrtc_cc_SUITE:probing_on_raised_maximum | E2E tested |
| PROBE-5 | RFC 3550 §5.1, RFC 4588 | Probes are padding-only packets with transport-wide sequence numbers, on the RTX stream when negotiated, else on the media stream; received padding-only packets are not delivered to the application | webrtc_media_out, webrtc_media_in | webrtc_cc_SUITE:probing_fills_link_at_start | E2E tested |
| PROBE-6 | libwebrtc AlrDetector, ProbeController | Application limited: media (padding left out) under 65% of the estimate for 500 ms, until back over 80%; meanwhile a cluster at twice the estimate every 5 s | webrtc_cc_probe, webrtc_cc | webrtc_cc_probe_tests:alr_probe_test, sim probing_application_limited_test_ | Simulated: a flow sending 400 kbps on a 3 Mbps link sits at 1.5 times what is acked, then the probes take the estimate to the link |
| PROBE-7 | libwebrtc ProbeController | After a drop under 66% of the previous estimate, leaving over-use within 5 s probes at 85% of the rate before the drop, when that would still raise the estimate | webrtc_cc_probe | drop_probe_test, sim probing_after_drop_test_ | Simulated |
| PROBE-8 | libwebrtc ProbeController | A raised `max_bitrate` (`set_congestion_control/2`) probes the new maximum when the estimate sat at the old one | webrtc_cc_probe, webrtc_cc | max_raised_test, webrtc_cc_SUITE:probing_on_raised_maximum | E2E tested |
| PROBE-9 | libwebrtc ProbeController, PacingController | One cluster in flight; probes after the start limited to 10 a minute; media leaving during a cluster is part of it (tagged in the transport-wide history), padding only makes up the difference with the cluster's rate, a cluster is complete with its bytes and 5 packets | webrtc_cc_probe, webrtc_cc | bounds_test, media_in_cluster_test, sim probing_with_media_in_flight_test_ | Simulated: after a dip on a 3 Mbps link still carrying 700 kbps of video the probe measures 2.4 to 2.8 Mbps, against 1.3 to 1.5 Mbps when only padding was counted |

## Pacing

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| PACE-1 | libwebrtc, RFC 8836 §2 (1f) | Leaky bucket at `pacing_factor` (2.5) x target, burst bounded to `burst_ms` (10 ms, at least one packet); never more than rate x interval + burst + one packet | webrtc_pacer | webrtc_pacer_tests:timing_accuracy_test, next_timeout_test, idle_burst_is_bounded_test, prop_webrtc_cc:prop_pacer_conservation | Unit tested |
| PACE-2 | libwebrtc | Audio before retransmissions before video, each in order | webrtc_pacer | priority_test, prop_pacer_accounting | Unit tested |
| PACE-3 | | Bounded queue (1000 packets): the oldest video packet is dropped first, drops counted per class; no packet lost or duplicated otherwise | webrtc_pacer | bounded_queue_drops_oldest_video_test, bounded_queue_without_video_test, prop_pacer_accounting | Unit tested |
| PACE-4 | libwebrtc | Queuing delay bounded by `max_queue_ms` (1000 ms) by sending faster | webrtc_pacer | queue_delay_bound_test | Unit tested |
| PACE-5 | | Pacing applies once feedback backs the estimate; it can be turned off at run time (`webrtc:set_congestion_control/2`) | webrtc_cc | webrtc_cc_tests:unpaced_without_feedback_test, paced_with_estimate_test, pacing_off_test, webrtc_media_cc_tests:pacing_test, webrtc_cc_SUITE:pacing_can_be_disabled | E2E tested |
| PACE-6 | libwebrtc | Retransmissions limited to the target bitrate over one second | webrtc_cc | rtx_limit_test | Unit tested |

## RFC 8083: RTP circuit breakers

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| CB-1 | 4.1 | RTCP timeout: sending without any report on the stream for 3 x Td, Td with Tmin = 5 s (15 s) | webrtc_circuit_breaker | webrtc_circuit_breaker_tests:rtcp_timeout_test, reports_prevent_rtcp_timeout_test, idle_stream_test, webrtc_media_cc_tests:rtcp_timeout_test, reports_keep_breaker_quiet_test | Unit tested |
| CB-2 | 4.2 | Media timeout: MEDIA_TIMEOUT consecutive reports with a non-increasing extended highest sequence number while sending, k = 5 | webrtc_circuit_breaker | media_timeout_test, media_progress_resets_test | Unit tested; Tf (frame interval) is not known to this layer and is left out of MEDIA_TIMEOUT |
| CB-3 | 4.3 | Congestion: sending rate above 10 x the simplified TCP throughput over CB_INTERVAL reports, loss fraction weighted by the reporting intervals | webrtc_circuit_breaker | congestion_test, congestion_needs_rtt_test | Unit tested; the 10 G Tf term of CB_INTERVAL is left out |
| CB-4 | 4.4 | ECN circuit breaker | | | Not implemented |
| CB-5 | 4.5 | Cease transmission when the RTCP or media timeout breaker triggers; no automatic restart; restart rate limited | webrtc_cc, webrtc_media | webrtc_cc_tests:circuit_breaker_halts_test, webrtc_cc_SUITE:circuit_breaker_halts_stream | E2E tested: RTP of the transceiver stops (`send_rtp` returns `{error, {circuit_breaker, Reason}}`, queued packets are dropped), RTCP continues; `webrtc:resume_stream/2` is refused for `circuit_breaker_hold` (15 s) |
| CB-6 | 4.3 | Congestion breaker: the sender MAY first cut its rate by ten, and MUST cease if it triggers again over the next CB_INTERVAL | webrtc_cc | webrtc_cc_tests:congestion_breaker_two_steps_test, webrtc_cc_SUITE:estimate_follows_capacity_drop | Unit tested: first trigger caps the target at a tenth of the sending rate and re-arms, second trigger halts; the cap is lifted after the hold time without a new trigger |
| CB-7 | RFC 8834 §7.1 | WebRTC endpoints implement the circuit breaker; with peers that only send receiver reports the sender stays within its limits | webrtc_cc, webrtc_gcc | webrtc_gcc_tests:rr_only_peer_test | Unit tested: receiver reports drive the loss-based estimate, seeded with the sending rate, and pacing applies |

## Payload formats

| ID | Section | Requirement | Module | Test | Status |
|---|---|---|---|---|---|
| VP8-1 | RFC 7741 §4.2 | Payload descriptor: X, N, S, PID, I (7 or 15-bit picture ID), L, T, K | webrtc_rtp_vp8 | webrtc_rtp_vp8_tests:vp8_parse_test, vp8_minimal_test, vp8_truncated_test_ | Unit tested |
| VP8-2 | RFC 7741 §4.3 | Key frame: S = 1, PID = 0, P bit of the payload header 0 | webrtc_rtp_vp8 | vp8_parse_test, vp8_minimal_test | Unit tested |
| VP8-3 | RFC 7741 §4.2 | Picture ID and TL0PICIDX rewritten keeping the field width | webrtc_rtp_vp8 | vp8_rewrite_test | Unit tested |
| VP8-4 | RFC 7741 §4.4 | Frame split into payloads with S set on the first | webrtc_rtp_vp8 | vp8_packetize_test | Unit tested |
| H264-1 | RFC 6184 §5.6 | Single NAL unit packets | webrtc_rtp_h264 | webrtc_rtp_h264_tests:single_nal_test | Unit tested |
| H264-2 | RFC 6184 §5.7.1 | STAP-A: F is the OR, NRI the maximum of the aggregated units | webrtc_rtp_h264 | stap_a_test | Unit tested |
| H264-3 | RFC 6184 §5.8 | FU-A fragmentation and reassembly; S and E never both set | webrtc_rtp_h264 | fu_a_test, h264_errors_test_ | Unit tested |
| H264-4 | RFC 6184 §5.8 | Fragments of a NAL unit with a lost fragment are discarded | webrtc_rtp_h264 | fu_a_test | Unit tested |
| H264-5 | RFC 6184 §5.7.1, §6.4 | Interleaved mode: STAP-B with its DON, a unit alone in a STAP-B since single NAL unit packets and STAP-A are not allowed | webrtc_rtp_h264 | stap_b_test, interleaved_errors_test_ | Unit tested |
| H264-7 | RFC 6184 §5.7.2 | MTAP16 and MTAP24: DONB the first unit in decoding order, DOND and timestamp offset per unit | webrtc_rtp_h264 | mtap_test | Unit tested |
| H264-8 | RFC 6184 §5.8 | FU-B for the first fragment with the DON, FU-A for the others; S and E never both set | webrtc_rtp_h264 | fu_b_test, deinterleave_fragments_test | Unit tested |
| H264-10 | RFC 6184 §8.2.2 | packetization-mode 2 negotiated as its own codec when the application configures it (`codecs` option), never against mode 1 | webrtc_jsep_caps | webrtc_jsep_caps_tests:h264_interleaved_test | Unit tested |
| H264-9 | RFC 6184 §5.5, §7.2 | De-interleaving: units leave in DON order once sprop-interleaving-depth + 1 VCL units wait, the rest on flush | webrtc_rtp_h264 | deinterleave_test, prop_webrtc_rtp:prop_h264_interleaved_roundtrip | Unit tested; no peer we test against sends mode 2, and the buffer ignores sprop-deint-buf-req, sprop-init-buf-time and sprop-max-don-diff |
| H264-6 | RFC 6184 §5.3 | Key frame detection by IDR (type 5), including STAP-A and FU-A start | webrtc_rtp_h264 | stap_a_test, fu_a_test | Unit tested |
| OPUS-1 | RFC 7587 §4.2 | One Opus packet per RTP payload, never fragmented | webrtc_rtp_opus | webrtc_rtp_opus_tests:opus_test_ | Unit tested |
| OPUS-2 | RFC 7587 §4.1 | RTP clock rate 48000 | webrtc_rtp_opus | opus_test_ | Unit tested |
| OPUS-3 | RFC 6716 §3.1, §3.2 | Packet duration from the TOC byte and frame count, at most 120 ms | webrtc_rtp_opus | opus_test_ | Unit tested |
| VP9-1 | RFC 9628 §4.2 | Key frame: P = 0, B = 1, spatial layer 0 | webrtc_rtp_vp9 | webrtc_rtp_vp9_tests:vp9_test_ | Unit tested |
| AV1-1 | AV1 RTP v1.0.0 §4.4 | Aggregation header; key frame by N = 1 | webrtc_rtp_av1 | webrtc_rtp_av1_tests:av1_test_ | Unit tested |

## Known limitations

- Congestion control clocks are integer milliseconds: arrival times in transport-wide feedback are multiples of 1 ms although the format carries 250 us.
- Probing happens at the start only: no periodic probing in application limited periods (libwebrtc's ALR probing) and no probing after a capacity drop recovers.

- `webrtc_rtp:encode/1` does not check that the payload type avoids 64..95 (MUX-2); the SDP layer must enforce it.
- The RTCP and AVPF scheduling state machines (RTCP-20, AVPF-13, RSIZE-3) are not implemented; `webrtc_rtcp_interval` provides the pure computations they need.
- `webrtc_nack` (receiver NACK generation) follows RFC 4585 §6.2.1 for the message and libwebrtc for the retry policy (retry every max(RTT, min interval), give up after `max_retries` or `max_age`, request a key frame when more than `max_missing` packets are missing); RFC 4585 does not specify this policy.
| NACK-10 | RFC 4585 §6.2.1, RFC 3711 §3.3 | NACK answered without RTX: the exact SRTP bytes of the first transmission are resent (no second protection of the same index) | webrtc_media_out | webrtc_media_tests:nack_without_rtx_test | Unit tested |
