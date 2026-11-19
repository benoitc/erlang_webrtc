%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Tests for webrtc_rtp_vp9 key frame detection (RFC 9628 §4.2).
-module(webrtc_rtp_vp9_tests).
-include_lib("eunit/include/eunit.hrl").

vp9_test_() ->
    V = webrtc_rtp_vp9,
    [
        %% I=1 P=0 L=1 F=0 B=1 E=0: 15-bit picture ID, layers SID 0, TL0PICIDX
        ?_assert(V:is_keyframe(<<2#10101000, 16#80, 16#01, 2#00000000, 9>>)),
        ?_assertMatch(
            {ok, #{picture_id := {15, 1}, sid := 0, tid := 0, tl0picidx := 9, start := true}},
            V:parse(<<2#10101000, 16#80, 16#01, 2#00000000, 9>>)
        ),
        %% spatial layer 1 is not a base key frame
        ?_assertNot(V:is_keyframe(<<2#10101000, 16#80, 16#01, 2#00000010, 9>>)),
        %% inter-predicted
        ?_assertNot(V:is_keyframe(<<2#11001000, 16#05>>)),
        %% not the start of a frame
        ?_assertNot(V:is_keyframe(<<2#00000100>>)),
        %% no picture ID, no layers
        ?_assert(V:is_keyframe(<<2#00001000>>)),
        %% flexible mode has no TL0PICIDX
        ?_assertMatch({ok, #{sid := 0, tl0picidx := undefined}}, V:parse(<<2#00111000, 0>>)),
        ?_assertEqual({error, truncated}, V:parse(<<2#10000000>>)),
        ?_assertEqual({error, truncated}, V:parse(<<2#00100000, 0>>)),
        ?_assertNot(V:is_keyframe(<<>>))
    ].
