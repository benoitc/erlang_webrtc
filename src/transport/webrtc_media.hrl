%% Private state of the media session (webrtc_media, webrtc_media_in,
%% webrtc_media_out).

-define(URI_MID, <<"urn:ietf:params:rtp-hdrext:sdes:mid">>).
-define(URI_AUDIO_LEVEL, <<"urn:ietf:params:rtp-hdrext:ssrc-audio-level">>).
-define(URI_RID, <<"urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id">>).
-define(URI_RRID, <<"urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id">>).
-define(URI_TWCC, <<"http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01">>).
-define(URI_PLAYOUT_DELAY, <<"http://www.webrtc.org/experiments/rtp-hdrext/playout-delay">>).
%% Feedback packets kept while the RTCP bandwidth does not allow them.
-define(MAX_PENDING_FEEDBACK, 32).
-define(BUFFER_SIZE, 512).
%% Receive streams: idle time after which one is forgotten, and the
%% number kept per transceiver (simulcast layers and RTX) and in total.
-define(RECV_IDLE, 60000).
-define(MAX_MID_STREAMS, 16).
-define(MAX_STREAMS, 256).
%% Size limit of an RTCP compound before SRTCP (tag and index), so the
%% protected packet stays within a 1200 byte path MTU.
-define(RTCP_BUDGET, 1150).

-record(snd, {
    mid :: binary(),
    kind :: audio | video,
    ssrc :: non_neg_integer(),
    rtx_ssrc :: non_neg_integer(),
    codecs :: [map()],
    %% Negotiated rtx payload type per primary payload type.
    rtx :: #{0..127 => 0..127},
    mid_ext :: undefined | pos_integer(),
    twcc_ext :: undefined | pos_integer(),
    seq :: 0..65535,
    rtx_seq :: 0..65535,
    last_ts = 0 :: non_neg_integer(),
    last_ts_at :: undefined | integer(),
    tx :: term(),
    buffer :: term(),
    %% Simulcast layer (RFC 8853) and the RtpStreamId and
    %% RepairedRtpStreamId extension ids (RFC 8852).
    rid :: undefined | binary(),
    rid_ext :: undefined | pos_integer(),
    rrid_ext :: undefined | pos_integer(),
    %% RFC 6464 audio level extension id, when negotiated.
    audio_level_ext :: undefined | pos_integer(),
    %% RFC 7728 pause state when negotiated, the hold-off before pausing
    %% (0 with nowait) and the sequence number cycles, for PAUSED.
    pause :: undefined | webrtc_rtp_pause:sender(),
    hold_off = 0 :: non_neg_integer(),
    cycles = 0 :: non_neg_integer(),
    %% The previous payload sent, {Pt, Ts, Data}, repeated in the next
    %% RED packet (RFC 2198) when the send asks for redundancy.
    red_prev :: undefined | {0..127, non_neg_integer(), binary()},
    %% The next VP8 and VP9 picture ID of send_frame, and the codec
    %% plugin encoding what send_media gets.
    picture_id = 0 :: 0..16#7FFF,
    %% ULPFEC: the packets of the frame being sent, as protected.
    fec_group = [] :: [{0..65535, binary()}],
    plugin :: undefined | {module(), term()} | {off, term()}
}).

-record(rcv, {
    mid :: binary(),
    clock_rate :: pos_integer(),
    rx :: term(),
    nack :: undefined | term(),
    %% The last {Seq, Ts} received, newest first (at most 64): a
    %% redundant block repairs only a packet not among them, and their
    %% timestamps give the packet a block repeats.
    recent = [] :: webrtc_red:history(),
    %% Frame assembly when the transceiver asked for frames.
    frames :: undefined | webrtc_frame_buffer:state(),
    %% Key frame requests the stream accepts (RFC 4585 PLI, RFC 5104
    %% FIR) and the sequence number of our next FIR (§4.3.1.2).
    keyframe = [] :: [pli | fir],
    fir_seq = 0 :: 0..255,
    %% The codec plugin decoding the frames, with the codec it was
    %% started for.
    plugin :: undefined | {module(), term(), binary()} | {off, term()},
    %% ULPFEC recovery (RFC 5109), when ulpfec is negotiated.
    fec :: undefined | webrtc_ulpfec:receiver()
}).

-record(media, {
    cname :: binary(),
    %% The socket reads and sets ECN marks (RFC 6679).
    ecn = false :: boolean(),
    rtcp_ssrc :: non_neg_integer(),
    out :: undefined | term(),
    in :: undefined | term(),
    senders = #{} :: #{sender_key() => #snd{}},
    %% Incoming streams by SSRC.
    receivers = #{} :: #{non_neg_integer() => #rcv{}},
    %% Demultiplexing tables, rebuilt on every negotiation. ssrc_mid also
    %% holds the SSRCs learned from accepted packets; signaled are the
    %% ones of the remote description.
    ssrc_mid = #{} :: #{non_neg_integer() => binary()},
    signaled = #{} :: #{non_neg_integer() => binary()},
    %% Time of the last accepted packet of every learned SSRC.
    last_seen = #{} :: #{non_neg_integer() => integer()},
    rtx_ssrc = #{} :: #{non_neg_integer() => non_neg_integer()},
    pt_mid = #{} :: #{0..127 => binary()},
    mid_ext = #{} :: #{binary() => pos_integer()},
    recv = #{} :: #{binary() => map()},
    rids = webrtc_media_rid:new() :: webrtc_media_rid:state(),
    %% Transport-wide-cc extension ids we accept on incoming packets.
    twcc_ids = [] :: [pos_integer()],
    cc :: webrtc_cc:state(),
    %% RTCP scheduler, from the SRTP keys on (webrtc_rtcp_sched).
    rtcp :: undefined | webrtc_rtcp_sched:state(),
    rtcp_opts = #{} :: map(),
    %% Feedback waiting for the RTCP bandwidth, oldest first.
    pending_fb = [] :: list(),
    %% Every section negotiated rtcp-rsize (RFC 5506).
    reduced_size = false :: boolean(),
    %% Every section negotiated cryptex (RFC 9335): what we send has its
    %% CSRCs and header extensions encrypted.
    cryptex = false :: boolean(),
    %% RFC 6904: ids of the extensions encrypted in each direction.
    send_encrypted = [] :: [pos_integer()],
    recv_encrypted = [] :: [pos_integer()],
    %% RTP packets sent at the last regular report (we_sent, §6.3).
    rtp_sent_mark = 0 :: non_neg_integer(),
    %% First source to report next when they do not all fit.
    rtcp_rot = 0 :: non_neg_integer(),
    %% Our PAUSE and RESUME requests by remote SSRC (RFC 7728).
    pause_req = #{} :: #{non_neg_integer() => webrtc_rtp_pause:requester()},
    counters = #{} :: map(),
    %% RFC 3611 §4.4 Receiver Reference Times received, by the SSRC that
    %% sent them: the middle 32 bits and when they came, answered with a
    %% DLRR block (§4.5) in the next regular report.
    xr_rrtr = #{} :: #{non_neg_integer() => {0..16#FFFFFFFF, integer()}},
    %% W3C media-source and media-playout members reported by mid
    %% (webrtc_media_report).
    sources = #{} :: #{binary() => map()},
    %% The decrypted bytes of the packet being dispatched: ULPFEC protects
    %% the packets as sent.
    raw :: undefined | binary(),
    %% FEC packets per video packet sent with ULPFEC: `auto' follows the
    %% loss the peer reports.
    video_fec = auto :: auto | float(),
    playouts = #{} :: #{binary() => map()},
    %% Per stream, for the W3C statistics: counters and the last reports
    %% by {in, RemoteSsrc} or {out, OurSsrc} (webrtc_stats).
    streams = #{} :: #{{in | out, non_neg_integer()} => map()}
}).

-type sender_key() :: binary() | {binary(), binary()}.
