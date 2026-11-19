%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Tests for webrtc_rtp_vp8 (RFC 7741).
-module(webrtc_rtp_vp8_tests).
-include_lib("eunit/include/eunit.hrl").

-import(webrtc_test_hex, [b/1]).

never_crashes(Fun, Bin) ->
    [_ = Fun(binary:part(Bin, 0, N)) || N <- lists:seq(0, byte_size(Bin))],
    ok.

-define(VP8, webrtc_rtp_vp8).

%% X=1 S=1 PID=0; I L T K; 15-bit picture ID 0x1234; TL0PICIDX 5;
%% TID 2 Y=1 KEYIDX 3; then a key frame payload header (P bit 0).
vp8_full() ->
    b("90 f0 92 34 05 a3 10 02 9d 01 2a").

vp8_parse_test() ->
    {ok, D, Rest} = ?VP8:parse(vp8_full()),
    ?assertEqual(
        #{
            non_reference => false,
            start => true,
            partition => 0,
            picture_id => {15, 16#1234},
            tl0picidx => 5,
            tid => 2,
            layer_sync => true,
            keyidx => 3,
            size => 6
        },
        D
    ),
    ?assertEqual(b("10 02 9d 01 2a"), Rest),
    ?assert(?VP8:is_keyframe(vp8_full())).

vp8_minimal_test() ->
    %% S=1, no extension, inter frame (P bit 1)
    ?assertMatch(
        {ok, #{start := true, picture_id := undefined, size := 1}, <<16#11>>},
        ?VP8:parse(<<16#10, 16#11>>)
    ),
    ?assertNot(?VP8:is_keyframe(<<16#10, 16#11>>)),
    ?assert(?VP8:is_keyframe(<<16#10, 16#10>>)),
    %% not the start of partition 0
    ?assertNot(?VP8:is_keyframe(<<16#00, 16#10>>)),
    ?assertNot(?VP8:is_keyframe(<<16#11, 16#10>>)),
    ?assertNot(?VP8:is_keyframe(<<16#10>>)),
    %% 7-bit picture ID
    ?assertMatch({ok, #{picture_id := {7, 5}}, <<>>}, ?VP8:parse(<<16#90, 16#80, 16#05>>)),
    %% K without T
    ?assertMatch(
        {ok, #{tid := undefined, keyidx := 7, size := 3}, <<>>}, ?VP8:parse(<<16#80, 16#10, 16#07>>)
    ).

vp8_truncated_test_() ->
    [
        ?_assertEqual({error, truncated}, ?VP8:parse(<<>>)),
        ?_assertEqual({error, truncated}, ?VP8:parse(<<16#80>>)),
        ?_assertEqual({error, truncated}, ?VP8:parse(<<16#80, 16#80>>)),
        ?_assertEqual({error, truncated}, ?VP8:parse(<<16#80, 16#80, 16#80>>)),
        ?_assertEqual({error, truncated}, ?VP8:parse(<<16#80, 16#40>>)),
        ?_assertEqual({error, truncated}, ?VP8:parse(<<16#80, 16#20>>)),
        ?_test(never_crashes(fun ?VP8:parse/1, vp8_full())),
        ?_test(never_crashes(fun ?VP8:is_keyframe/1, vp8_full()))
    ].

vp8_rewrite_test() ->
    {ok, P} = ?VP8:rewrite(vp8_full(), #{picture_id => 16#8001, tl0picidx => 200}),
    {ok, D, Rest} = ?VP8:parse(P),
    ?assertMatch(#{picture_id := {15, 1}, tl0picidx := 200, tid := 2, keyidx := 3}, D),
    ?assertEqual(b("10 02 9d 01 2a"), Rest),
    %% 7-bit picture IDs keep their width
    {ok, P7} = ?VP8:rewrite(<<16#90, 16#C0, 16#05, 16#AA, 16#BB>>, #{
        picture_id => 130, tl0picidx => 1
    }),
    ?assertEqual(<<16#90, 16#C0, 2, 1, 16#BB>>, P7),
    ?assertEqual({error, {absent, picture_id}}, ?VP8:rewrite(<<16#10, 0>>, #{picture_id => 1})),
    ?assertEqual(
        {error, {absent, tl0picidx}}, ?VP8:rewrite(<<16#90, 16#80, 1>>, #{tl0picidx => 1})
    ),
    ?assertEqual({ok, <<16#10, 0>>}, ?VP8:rewrite(<<16#10, 0>>, #{})).

vp8_packetize_test() ->
    Frame = binary:copy(<<1, 2, 3>>, 100),
    Payloads = ?VP8:packetize(Frame, 100, #{picture_id => 77, tl0picidx => 3}),
    ?assert(lists:all(fun(P) -> byte_size(P) =< 100 end, Payloads)),
    Parsed = [?VP8:parse(P) || P <- Payloads],
    [{ok, #{start := true}, _} | Others] = Parsed,
    ?assert(
        lists:all(
            fun({ok, #{start := S, picture_id := {15, 77}, tl0picidx := 3}, _}) -> not S end, Others
        )
    ),
    ?assertEqual(Frame, iolist_to_binary([R || {ok, _, R} <- Parsed])),
    [Single] = ?VP8:packetize(<<"x">>, 100, #{}),
    ?assertEqual(<<16#10, "x">>, Single).
