%% Private state of the media session (webrtc_media, webrtc_media_in,
%% webrtc_media_out).

-define(URI_MID, <<"urn:ietf:params:rtp-hdrext:sdes:mid">>).
-define(URI_RID, <<"urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id">>).
-define(URI_RRID, <<"urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id">>).
-define(URI_TWCC, <<"http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01">>).
-define(RTCP_INTERVAL, 1000).
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
    rrid_ext :: undefined | pos_integer()
}).

-record(rcv, {
    mid :: binary(),
    clock_rate :: pos_integer(),
    rx :: term(),
    nack :: undefined | term()
}).

-record(media, {
    cname :: binary(),
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
    rtcp_at = infinity :: integer() | infinity,
    %% First source to report next when they do not all fit.
    rtcp_rot = 0 :: non_neg_integer(),
    counters = #{} :: map()
}).

-type sender_key() :: binary() | {binary(), binary()}.
