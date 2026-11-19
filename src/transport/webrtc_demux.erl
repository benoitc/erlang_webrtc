%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Classify a datagram received on a WebRTC transport by its first
%% byte (RFC 7983 §7 as updated by RFC 9443 §3).
%%
%% ```
%%          +----------------+
%%          |        [0..3] -+--> STUN
%%          |      [16..19] -+--> ZRTP (not used, dropped)
%%          |      [20..63] -+--> DTLS
%%          |      [64..79] -+--> TURN ChannelData
%%          |    [128..191] -+--> RTP/RTCP
%%          |  [80..127], other -+--> QUIC or unknown (dropped)
%%          +----------------+
%% '''
-module(webrtc_demux).

-export([classify/1]).

-type class() :: stun | dtls | turn_channel | rtp | unknown.

-spec classify(binary()) -> class().
classify(<<B, _/binary>>) when B =< 3 -> stun;
classify(<<B, _/binary>>) when B >= 20, B =< 63 -> dtls;
classify(<<B, _/binary>>) when B >= 64, B =< 79 -> turn_channel;
classify(<<B, _/binary>>) when B >= 128, B =< 191 -> rtp;
classify(_) -> unknown.
