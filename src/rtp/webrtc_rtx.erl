%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc RTP retransmission payload format (RFC 4588 §4).
%%
%% A retransmission packet carries the original sequence number (OSN)
%% in the first two payload octets, followed by the original payload.
%% WebRTC uses SSRC multiplexing (RFC 8834 §6.1): the retransmission
%% stream has its own SSRC in the same RTP session, the RTX payload type
%% negotiated through `a=fmtp:<rtx> apt=<pt>' and its own sequence
%% numbers, which the caller supplies. The timestamp (RFC 4588 §4 MUST),
%% marker bit, CSRC list and header extensions are those of the original
%% packet. Padding of the original packet is not copied.
-module(webrtc_rtx).

-include("webrtc_rtp.hrl").

-export([encapsulate/2, decapsulate/2, osn/1]).

-type rtx_params() :: #{ssrc := 0..16#FFFFFFFF, pt := 0..127, seq := 0..65535}.
-type orig_params() :: #{ssrc := 0..16#FFFFFFFF, pt := 0..127}.

-export_type([rtx_params/0, orig_params/0]).

%% @doc Wrap an original packet into a retransmission packet.
-spec encapsulate(#rtp{}, rtx_params()) -> #rtp{}.
encapsulate(#rtp{seq = Osn, payload = Payload} = Orig, #{ssrc := Ssrc, pt := PT, seq := Seq}) ->
    Orig#rtp{
        ssrc = Ssrc,
        pt = PT,
        seq = Seq,
        padding = 0,
        payload = <<Osn:16, Payload/binary>>
    }.

%% @doc Recover the original packet from a retransmission packet, given
%% the SSRC and payload type of the original stream. RTX packets without
%% an OSN (padding-only packets, used for bandwidth probing) return
%% `{error, no_osn}'.
-spec decapsulate(#rtp{}, orig_params()) -> {ok, #rtp{}} | {error, no_osn}.
decapsulate(#rtp{payload = <<Osn:16, Payload/binary>>} = Rtx, #{ssrc := Ssrc, pt := PT}) ->
    {ok, Rtx#rtp{ssrc = Ssrc, pt = PT, seq = Osn, padding = 0, payload = Payload}};
decapsulate(#rtp{}, _) ->
    {error, no_osn}.

%% @doc Original sequence number of a retransmission packet.
-spec osn(#rtp{}) -> {ok, 0..65535} | {error, no_osn}.
osn(#rtp{payload = <<Osn:16, _/binary>>}) -> {ok, Osn};
osn(#rtp{}) -> {error, no_osn}.
