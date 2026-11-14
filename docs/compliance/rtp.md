# RTP and RTCP (RFC 3550, RFC 8834)

This page tracks the RTP and RTCP requirements implemented under `src/rtp`: the RTP and RTCP codecs, header extensions, feedback messages, receiver statistics, RTCP timing, retransmission and the payload helpers. Read it when you need to know whether a packet type or rule is supported before relying on it. Scheduling decisions (when to send a report, which feedback to merge) belong to the transport process and are marked as not implemented here until that process exists. Test names refer to `test/<module>_tests.erl` and to the properties in `test/prop_webrtc_rtp.erl`.

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
| RTCP-20 | 6.3 | RTCP scheduler state (members, senders, tp, tn, BYE back-off of 6.3.7) | | | Not implemented (transport process) |

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
| WRTP-17 | 5.2.2 | Client-to-mixer audio level (RFC 6464) | webrtc_rtp_ext | audio_level_test | Unit tested (header extension encryption, RFC 6904, belongs to SRTP and is not implemented) |
| WRTP-18 | 5.2.4 | MID header extension | webrtc_rtp_ext | sdes_test | Unit tested |
| WRTP-19 | 5.2.5 | Video orientation (CVO) header extension | webrtc_rtp_ext | video_orientation_test | Unit tested |
| WRTP-20 | 6.1 | Senders understand generic NACK | webrtc_rtcp_fb, webrtc_nack_buffer | nack_test, webrtc_nack_buffer_tests:buffer_test | Unit tested |
| WRTP-21 | 6.1 | Receivers support RTX with SSRC multiplexing (RFC 4588) | webrtc_rtx | webrtc_rtx_tests:rtx_test | Unit tested |
| WRTP-22 | 6.1 | RTT estimate from SR / RR to decide on retransmission | webrtc_rtp_stats, webrtc_nack_buffer | rtt_rfc_example_test, buffer_test | Unit tested |

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
| AVPF-13 | 3.5.2 | Early feedback scheduling (allow_early, merge into the scheduled packet, suppression) | | | Not implemented (transport process) |

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
| RID-9 | 8853 5.2, RFC 7728 | Pause and resume of layers | | | Not implemented |

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
| RSIZE-3 | 4.1 | Regular reports are always compound; reduced-size only for feedback | | | Not implemented (transport process) |

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
| REMB-1 | draft-alvestrand-rmcat-remb-03 §2.2 | PSFB FMT 15 "REMB": SSRC count, 6-bit exponent, 18-bit mantissa, SSRC list | webrtc_rtcp_fb | remb_test, rr_remb_test | Unit tested |
| XR-1 | RFC 3611 §4.4 | Receiver Reference Time report block | webrtc_rtcp_xr | webrtc_rtcp_xr_tests:xr_test, xr_errors_test_ | Unit tested |
| XR-2 | RFC 3611 §4.5 | DLRR report block with sub-blocks | webrtc_rtcp_xr | xr_test, xr_errors_test_ | Unit tested |
| XR-3 | RFC 3611 §3 | Other block types kept with their type-specific byte | webrtc_rtcp_xr | xr_unknown_block_test | Unit tested |

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
| H264-5 | RFC 6184 §5.4, §6.4 | Interleaved mode (STAP-B, MTAP, FU-B); mode 1 (§6.3) is the one implemented | webrtc_rtp_h264 | h264_errors_test_ | Not implemented: rejected as unsupported |
| H264-6 | RFC 6184 §5.3 | Key frame detection by IDR (type 5), including STAP-A and FU-A start | webrtc_rtp_h264 | stap_a_test, fu_a_test | Unit tested |
| OPUS-1 | RFC 7587 §4.2 | One Opus packet per RTP payload, never fragmented | webrtc_rtp_opus | webrtc_rtp_opus_tests:opus_test_ | Unit tested |
| OPUS-2 | RFC 7587 §4.1 | RTP clock rate 48000 | webrtc_rtp_opus | opus_test_ | Unit tested |
| OPUS-3 | RFC 6716 §3.1, §3.2 | Packet duration from the TOC byte and frame count, at most 120 ms | webrtc_rtp_opus | opus_test_ | Unit tested |
| VP9-1 | RFC 9628 §4.2 | Key frame: P = 0, B = 1, spatial layer 0 | webrtc_rtp_vp9 | webrtc_rtp_vp9_tests:vp9_test_ | Unit tested |
| AV1-1 | AV1 RTP v1.0.0 §4.4 | Aggregation header; key frame by N = 1 | webrtc_rtp_av1 | webrtc_rtp_av1_tests:av1_test_ | Unit tested |

## Known limitations

- `webrtc_rtp:encode/1` does not check that the payload type avoids 64..95 (MUX-2); the SDP layer must enforce it.
- The RTCP and AVPF scheduling state machines (RTCP-20, AVPF-13, RSIZE-3) are not implemented; `webrtc_rtcp_interval` provides the pure computations they need.
- `webrtc_nack` (receiver NACK generation) follows RFC 4585 §6.2.1 for the message and libwebrtc for the retry policy (retry every max(RTT, min interval), give up after `max_retries` or `max_age`, request a key frame when more than `max_missing` packets are missing); RFC 4585 does not specify this policy.
