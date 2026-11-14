%% Tests for webrtc_nack_buffer, the sender-side retransmission buffer.
-module(webrtc_nack_buffer_tests).
-include_lib("eunit/include/eunit.hrl").

-define(B, webrtc_nack_buffer).

buffer_test() ->
    B0 = ?B:new(#{size => 4, rtt => 50}),
    B1 = lists:foldl(fun(S, B) -> ?B:store(S, {pkt, S}, 0, B) end, B0, [65534, 65535, 0, 1]),
    ?assertEqual(4, ?B:count(B1)),
    ?assertEqual({ok, {pkt, 65535}}, ?B:lookup(65535, B1)),
    %% 2 overwrites the slot of 65534
    B2 = ?B:store(2, {pkt, 2}, 0, B1),
    ?assertEqual(error, ?B:lookup(65534, B2)),
    ?assertEqual({ok, {pkt, 2}}, ?B:lookup(2, B2)),
    {Out, B3} = ?B:retransmit([0, 65534, 1], 10, B2),
    ?assertEqual([{0, {pkt, 0}}, {1, {pkt, 1}}], Out),
    %% asked again within one RTT: suppressed
    {[], B4} = ?B:retransmit([0], 30, B3),
    {[{0, {pkt, 0}}], _} = ?B:retransmit([0], 60, B4).

buffer_max_age_test() ->
    B = ?B:store(1, p, 0, ?B:new(#{max_age => 100})),
    ?assertMatch({[{1, p}], _}, ?B:retransmit([1], 100, B)),
    ?assertMatch({[], _}, ?B:retransmit([1], 101, B)),
    ?assertMatch(
        {[{1, p}], _}, ?B:retransmit([1], 100000, ?B:store(1, p, 0, ?B:new(#{max_age => infinity})))
    ),
    ?assertError(_, ?B:new(#{size => 0})).
