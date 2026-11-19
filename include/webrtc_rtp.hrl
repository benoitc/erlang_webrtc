%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% RTP packet representation (RFC 3550 §5.1).
-ifndef(WEBRTC_RTP_HRL).
-define(WEBRTC_RTP_HRL, true).

-define(RTP_VERSION, 2).
-define(RTP_HEADER_SIZE, 12).
-define(RTP_SEQ_MOD, 65536).

%% RFC 8285 header extension profiles.
-define(RTP_EXT_ONE_BYTE, 16#BEDE).
%% Two-byte form: 0x100 followed by 4 appbits (0x1000..0x100F).
-define(RTP_EXT_TWO_BYTE, 16#100).

-record(rtp, {
    version = 2 :: 2,
    %% Number of padding octets at the end of the packet, including the
    %% final count octet. 0 means the P bit is clear.
    padding = 0 :: 0..255,
    marker = false :: boolean(),
    pt = 0 :: 0..127,
    seq = 0 :: 0..65535,
    ts = 0 :: 0..16#FFFFFFFF,
    ssrc = 0 :: 0..16#FFFFFFFF,
    csrcs = [] :: [0..16#FFFFFFFF],
    %% undefined when the X bit is clear. decode/1 returns the raw form
    %% {Profile, Data}; decode/2 with #{extensions => parse} returns the
    %% RFC 8285 elements. encode/1 accepts both.
    ext = undefined ::
        undefined
        | {Profile :: 0..65535, Data :: binary()}
        | [webrtc_rtp_ext:element()],
    payload = <<>> :: binary()
}).

-endif.
