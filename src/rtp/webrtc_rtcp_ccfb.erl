%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc RTP Control Protocol feedback for congestion control (RFC 8888),
%% RTPFB FMT 11.
%%
%% The packet is the sender SSRC, one report block per RTP stream and a
%% 32-bit report timestamp (middle bits of an NTP time). Each report
%% block holds the stream SSRC, `begin_seq', `num_reports' and one 16-bit
%% metric per packet: R (received), ECN (2 bits) and the arrival time
%% offset in 1/1024 s before the report timestamp (13 bits). An odd
%% number of metrics is followed by 16 bits of zero padding.
%%
%% `num_reports' is the number of metric blocks, covering `begin_seq' up
%% to but not including `begin_seq + num_reports', as clarified by the
%% reported erratum on §3.1 and implemented by libwebrtc. A report
%% block MUST NOT carry more than 16384 metrics; longer blocks are
%% rejected on decode and on encode. Metrics with R = 0 decode to
%% `not_received' and their ECN and ATO bits are ignored, as required.
-module(webrtc_rtcp_ccfb).

-include("webrtc_rtp_rtcp.hrl").

-export([decode/1, encode/1, ato/1]).

-define(MAX_METRICS, 16384).
%% ATO values with a special meaning (RFC 8888 §3.1).
-define(ATO_OVER_RANGE, 16#1FFE).
-define(ATO_UNAVAILABLE, 16#1FFF).

-export_type([metric/0]).
-type metric() :: not_received | {0..3, 0..16#1FFF}.

%% @doc Decode the body of a CCFB packet (after the common header).
-spec decode(binary()) -> {ok, #rtcp_ccfb{}} | {error, term()}.
decode(<<Sender:32, Rest/binary>>) when byte_size(Rest) >= 4 ->
    Size = byte_size(Rest) - 4,
    <<Blocks:Size/binary, Ts:32>> = Rest,
    case blocks(Blocks, []) of
        {ok, Reports} -> {ok, #rtcp_ccfb{sender_ssrc = Sender, reports = Reports, timestamp = Ts}};
        Err -> Err
    end;
decode(_) ->
    {error, truncated}.

blocks(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
blocks(<<_Ssrc:32, _Begin:16, Num:16, _/binary>>, _) when Num > ?MAX_METRICS ->
    {error, too_many_metrics};
blocks(<<Ssrc:32, Begin:16, Num:16, Rest/binary>>, Acc) ->
    Size = Num * 2 + (Num rem 2) * 2,
    case Rest of
        <<Metrics:(Num * 2)/binary, _Pad:((Num rem 2) * 2)/binary, Rest1/binary>> when
            byte_size(Rest) >= Size
        ->
            blocks(Rest1, [{Ssrc, Begin, [metric(M) || <<M:16>> <= Metrics]} | Acc]);
        _ ->
            {error, truncated}
    end;
blocks(_, _) ->
    {error, truncated}.

metric(<<0:1, _:15>>) -> not_received;
metric(<<1:1, Ecn:2, Ato:13>>) -> {Ecn, Ato};
metric(M) when is_integer(M) -> metric(<<M:16>>).

%% @doc Arrival time offset field for a packet that arrived `OffsetUs'
%% microseconds before the report timestamp: 1/1024 s units, 0x1FFE when
%% over range and 0x1FFF when the packet arrived after the report time
%% (RFC 8888 §3.1).
-spec ato(integer()) -> 0..16#1FFF.
ato(OffsetUs) when is_integer(OffsetUs), OffsetUs < 0 ->
    ?ATO_UNAVAILABLE;
ato(OffsetUs) when is_integer(OffsetUs) ->
    case (OffsetUs * 1024 + 500000) div 1000000 of
        V when V > 16#1FFD -> ?ATO_OVER_RANGE;
        V -> V
    end.

%% @doc Encode a CCFB packet body (everything after the common header).
-spec encode(#rtcp_ccfb{}) -> binary().
encode(#rtcp_ccfb{sender_ssrc = S, reports = Reports, timestamp = Ts}) when
    is_integer(S), S >= 0, S =< 16#FFFFFFFF, is_integer(Ts), Ts >= 0, Ts =< 16#FFFFFFFF
->
    iolist_to_binary([<<S:32>>, [block(R) || R <- Reports], <<Ts:32>>]);
encode(_) ->
    error(badarg).

block({Ssrc, Begin, Metrics}) when
    is_integer(Ssrc),
    Ssrc >= 0,
    Ssrc =< 16#FFFFFFFF,
    is_integer(Begin),
    Begin >= 0,
    Begin =< 16#FFFF,
    length(Metrics) =< ?MAX_METRICS
->
    Num = length(Metrics),
    [
        <<Ssrc:32, Begin:16, Num:16>>,
        [encode_metric(M) || M <- Metrics],
        <<0:((Num rem 2) * 16)>>
    ];
block(_) ->
    error(badarg).

encode_metric(not_received) ->
    <<0:16>>;
encode_metric({Ecn, Ato}) when
    is_integer(Ecn), Ecn >= 0, Ecn =< 3, is_integer(Ato), Ato >= 0, Ato =< 16#1FFF
->
    <<1:1, Ecn:2, Ato:13>>;
encode_metric(_) ->
    error(badarg).
