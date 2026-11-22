%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% A codec plugin with the callbacks of 0.2.0 only (no control/2, no
%% terminate/1): what the library gives the newer callbacks must not
%% reach it, and it keeps working.
-module(webrtc_test_codec_plain).
-behaviour(webrtc_media_codec).

-export([init/3, decode/2, encode/2, info/1]).

init(_Kind, _Codec, _Opts) -> {ok, 0}.

decode(#{data := D}, N) -> {ok, [{size, byte_size(D)}], #{framesDecoded => 1}, N + 1}.

encode({frame, D, K, Ts}, N) -> {ok, [#{data => D, keyframe => K, timestamp => Ts}], #{framesEncoded => 1}, N + 1}.

info(_) -> #{implementation => <<"plain">>}.
