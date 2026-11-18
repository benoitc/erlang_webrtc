%% RTCP packet representation (RFC 3550 §6, RFC 4585, RFC 5104,
%% RFC 3611, RFC 8888, draft-holmer-rmcat-transport-wide-cc-extensions,
%% draft-alvestrand-rmcat-remb).
-ifndef(WEBRTC_RTP_RTCP_HRL).
-define(WEBRTC_RTP_RTCP_HRL, true).

%% Packet types.
-define(RTCP_SR, 200).
-define(RTCP_RR, 201).
-define(RTCP_SDES, 202).
-define(RTCP_BYE, 203).
-define(RTCP_APP, 204).
-define(RTCP_RTPFB, 205).
-define(RTCP_PSFB, 206).
-define(RTCP_XR, 207).

%% RTPFB FMT values.
-define(RTPFB_NACK, 1).
-define(RTPFB_TMMBR, 3).
-define(RTPFB_TMMBN, 4).
-define(RTPFB_SRREQ, 5).
-define(RTPFB_PAUSE, 9).
-define(RTPFB_CCFB, 11).
-define(RTPFB_TWCC, 15).

%% PSFB FMT values.
-define(PSFB_PLI, 1).
-define(PSFB_SLI, 2).
-define(PSFB_RPSI, 3).
-define(PSFB_FIR, 4).
-define(PSFB_AFB, 15).

-type rtcp_u32() :: 0..16#FFFFFFFF.

%% Reception report block (RFC 3550 §6.4.1).
-record(rtcp_rb, {
    ssrc = 0 :: rtcp_u32(),
    fraction_lost = 0 :: 0..255,
    %% Signed 24-bit cumulative number of packets lost.
    lost = 0 :: -16#800000..16#7FFFFF,
    %% Extended highest sequence number received.
    ext_seq = 0 :: rtcp_u32(),
    jitter = 0 :: rtcp_u32(),
    lsr = 0 :: rtcp_u32(),
    dlsr = 0 :: rtcp_u32()
}).

-record(rtcp_sr, {
    ssrc = 0 :: rtcp_u32(),
    %% 64-bit NTP timestamp.
    ntp = 0 :: 0..16#FFFFFFFFFFFFFFFF,
    rtp_ts = 0 :: rtcp_u32(),
    packets = 0 :: rtcp_u32(),
    octets = 0 :: rtcp_u32(),
    reports = [] :: [#rtcp_rb{}],
    %% Profile-specific extension, kept raw (multiple of 4 bytes).
    ext = <<>> :: binary()
}).

-record(rtcp_rr, {
    ssrc = 0 :: rtcp_u32(),
    reports = [] :: [#rtcp_rb{}],
    ext = <<>> :: binary()
}).

%% Items: cname, name, email, phone, loc, tool, note, mid (RFC 9143 §15.1),
%% rid and repaired_rid (RFC 8852) as atoms; priv as {priv, Prefix};
%% other item types as their integer code.
-record(rtcp_sdes, {
    chunks = [] :: [{rtcp_u32(), [{webrtc_rtcp:sdes_item(), binary()}]}]
}).

-record(rtcp_bye, {
    ssrcs = [] :: [rtcp_u32()],
    reason = undefined :: undefined | binary()
}).

-record(rtcp_app, {
    subtype = 0 :: 0..31,
    ssrc = 0 :: rtcp_u32(),
    name = <<"    ">> :: <<_:32>>,
    %% Application data, a multiple of 4 bytes.
    data = <<>> :: binary()
}).

%% Generic NACK (RFC 4585 §6.2.1): items are {PID, BLP}.
-record(rtcp_nack, {
    sender_ssrc = 0 :: rtcp_u32(),
    media_ssrc = 0 :: rtcp_u32(),
    items = [] :: [{0..65535, 0..65535}]
}).

%% TMMBR / TMMBN (RFC 5104 §4.2.1, §4.2.2): entries are
%% {Ssrc, MaxBitrateBps, MeasuredOverhead}.
-record(rtcp_tmmbr, {
    sender_ssrc = 0 :: rtcp_u32(),
    media_ssrc = 0 :: rtcp_u32(),
    entries = [] :: [{rtcp_u32(), non_neg_integer(), 0..511}]
}).

-record(rtcp_tmmbn, {
    sender_ssrc = 0 :: rtcp_u32(),
    media_ssrc = 0 :: rtcp_u32(),
    entries = [] :: [{rtcp_u32(), non_neg_integer(), 0..511}]
}).

%% PAUSE-RESUME (RFC 7728 §8): {TargetSsrc, Type, PauseId, Seq}, Seq the
%% extended sequence number of the last packet sent before a PAUSED,
%% undefined for the other types. The media SSRC is not used (0).
-record(rtcp_pause, {
    sender_ssrc = 0 :: rtcp_u32(),
    entries = [] :: [{rtcp_u32(), pause | resume | paused | refused, 0..65535, undefined | rtcp_u32()}]
}).

%% Transport-wide congestion control feedback
%% (draft-holmer-rmcat-transport-wide-cc-extensions-01 §3.1).
%% packets lists, from base_seq on, either not_received or the receive
%% delta in multiples of 250 microseconds.
-record(rtcp_twcc, {
    sender_ssrc = 0 :: rtcp_u32(),
    media_ssrc = 0 :: rtcp_u32(),
    base_seq = 0 :: 0..65535,
    %% Signed 24-bit reference time in multiples of 64 ms.
    ref_time = 0 :: -16#800000..16#7FFFFF,
    fb_count = 0 :: 0..255,
    packets = [] :: [{0..65535, not_received | -32768..32767}]
}).

%% RFC 8888 congestion control feedback. Each report is
%% {Ssrc, BeginSeq, Metrics}; a metric is not_received or
%% {Ecn :: 0..3, ArrivalTimeOffset :: 0..8191}.
-record(rtcp_ccfb, {
    sender_ssrc = 0 :: rtcp_u32(),
    reports = [] ::
        [{rtcp_u32(), 0..65535, [not_received | {0..3, 0..16#1FFF}]}],
    %% Middle 32 bits of an NTP timestamp.
    timestamp = 0 :: rtcp_u32()
}).

%% Picture loss indication (RFC 4585 §6.3.1).
-record(rtcp_pli, {
    sender_ssrc = 0 :: rtcp_u32(),
    media_ssrc = 0 :: rtcp_u32()
}).

%% RTCP rapid resynchronisation request (RFC 6051 §3.2): the receiver
%% asks the sender of media_ssrc for an SR. No FCI.
-record(rtcp_srreq, {
    sender_ssrc = 0 :: rtcp_u32(),
    media_ssrc = 0 :: rtcp_u32()
}).

%% Slice loss indication (RFC 4585 §6.3.2): {First, Number, PictureId}.
-record(rtcp_sli, {
    sender_ssrc = 0 :: rtcp_u32(),
    media_ssrc = 0 :: rtcp_u32(),
    entries = [] :: [{0..8191, 0..8191, 0..63}]
}).

%% Reference picture selection indication (RFC 4585 §6.3.3): the payload
%% type and the native RPSI bit string, its meaning defined by the codec.
-record(rtcp_rpsi, {
    sender_ssrc = 0 :: rtcp_u32(),
    media_ssrc = 0 :: rtcp_u32(),
    pt = 0 :: 0..127,
    bits = <<>> :: bitstring()
}).

%% Full intra request (RFC 5104 §4.3.1): entries are {Ssrc, SeqNr}.
-record(rtcp_fir, {
    sender_ssrc = 0 :: rtcp_u32(),
    media_ssrc = 0 :: rtcp_u32(),
    entries = [] :: [{rtcp_u32(), 0..255}]
}).

%% Receiver estimated maximum bitrate (draft-alvestrand-rmcat-remb-03).
-record(rtcp_remb, {
    sender_ssrc = 0 :: rtcp_u32(),
    media_ssrc = 0 :: rtcp_u32(),
    bitrate = 0 :: non_neg_integer(),
    ssrcs = [] :: [rtcp_u32()]
}).

%% Extended reports (RFC 3611). Blocks:
%% {rrtr, Ntp64} (§4.4), {dlrr, [{Ssrc, LastRR, DelaySinceLastRR}]}
%% (§4.5), or {BlockType, TypeSpecific, Body} for other block types.
-record(rtcp_xr, {
    ssrc = 0 :: rtcp_u32(),
    blocks = [] :: [webrtc_rtcp_xr:block()]
}).

%% Packet with an unknown type or feedback format, body kept as is
%% (padding removed). count is the 5-bit count / FMT / subtype field.
-record(rtcp_raw, {
    pt = 0 :: 0..255,
    count = 0 :: 0..31,
    body = <<>> :: binary()
}).

-endif.
