%% Tests for webrtc_nack, the receiver-side NACK generator.
-module(webrtc_nack_tests).
-include_lib("eunit/include/eunit.hrl").

-define(N, webrtc_nack).

feed(Seqs, Now, S) ->
    lists:foldl(
        fun(Seq, {St, Acc}) ->
            {St1, A} = ?N:packet(Seq, Now, St),
            {St1, Acc ++ A}
        end,
        {S, []},
        Seqs
    ).

gap_and_retry_test() ->
    {S1, A1} = feed([1, 2, 3, 6], 0, ?N:new(#{rtt => 100})),
    ?assertEqual([{nack, [4, 5]}], A1),
    ?assertEqual([4, 5], ?N:missing(S1)),
    ?assertEqual(100, ?N:next_timeout(S1)),
    ?assertMatch({_, []}, ?N:handle_timeout(50, S1)),
    {S2, A2} = ?N:handle_timeout(100, S1),
    ?assertEqual([{nack, [4, 5]}], A2),
    %% 4 arrives (reordered or retransmitted)
    {S3, A3} = ?N:packet(4, 120, S2),
    ?assertEqual([], A3),
    ?assertEqual([5], ?N:missing(S3)),
    ?assertEqual(200, ?N:next_timeout(S3)).

max_retries_test() ->
    {S1, [{nack, [2]}]} = feed([1, 3], 0, ?N:new(#{rtt => 10, max_retries => 2})),
    {S2, [{nack, [2]}]} = ?N:handle_timeout(10, S1),
    {S3, A3} = ?N:handle_timeout(20, S2),
    ?assertEqual([{give_up, [2]}], A3),
    ?assertEqual([], ?N:missing(S3)),
    ?assertEqual(infinity, ?N:next_timeout(S3)).

max_age_test() ->
    {S1, _} = feed([1, 3], 0, ?N:new(#{rtt => 400, max_age => 500})),
    {S2, [{nack, [2]}]} = ?N:handle_timeout(400, S1),
    ?assertEqual(501, ?N:next_timeout(S2)),
    {S3, A3} = ?N:handle_timeout(501, S2),
    ?assertEqual([{give_up, [2]}], A3),
    ?assertEqual([], ?N:missing(S3)).

rtt_floor_test() ->
    %% with RTT 0 the minimum interval spaces the requests
    {S1, _} = feed([1, 3], 0, ?N:new(#{rtt => 0, min_interval => 5})),
    ?assertEqual(5, ?N:next_timeout(S1)),
    S2 = ?N:set_rtt(50, S1),
    ?assertEqual(50, ?N:next_timeout(S2)).

reorder_delay_test() ->
    {S1, A1} = feed([1, 3], 0, ?N:new(#{reorder_delay => 20})),
    ?assertEqual([], A1),
    ?assertEqual(20, ?N:next_timeout(S1)),
    %% reordered packet arrives in time: no NACK at all
    {S2, []} = ?N:packet(2, 10, S1),
    ?assertEqual(infinity, ?N:next_timeout(S2)).

wraparound_test() ->
    {S1, A1} = feed([65534, 65535, 2], 0, ?N:new(#{})),
    ?assertEqual([{nack, [0, 1]}], A1),
    ?assertEqual([0, 1], ?N:missing(S1)).

large_gap_keyframe_test() ->
    {S1, A1} = feed([1, 2000], 0, ?N:new(#{max_missing => 100})),
    ?assertEqual([request_keyframe], A1),
    ?assertEqual([], ?N:missing(S1)),
    %% the stream continues from the new position
    {_, A2} = ?N:packet(2002, 1, S1),
    ?assertEqual([{nack, [2001]}], A2).

trim_oldest_test() ->
    {S1, A1} = feed([1, 5, 8], 0, ?N:new(#{max_missing => 4})),
    %% 2,3,4 then 6,7: the oldest one is dropped
    ?assert(lists:member(request_keyframe, A1)),
    ?assertEqual([3, 4, 6, 7], ?N:missing(S1)).

old_packets_ignored_test() ->
    {S1, []} = feed([10, 11, 12], 0, ?N:new(#{})),
    {S2, []} = ?N:packet(5, 1, S1),
    {_, []} = ?N:packet(12, 1, S2).
