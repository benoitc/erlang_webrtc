%% One-shot mDNS resolver (RFC 6762 §5.1, §6.7, §18) driven with a
%% synthetic clock.
-module(webrtc_mdns_resolver_tests).
-include_lib("eunit/include/eunit.hrl").

-define(R, webrtc_mdns_resolver).
-define(MSG, webrtc_mdns_msg).
-define(NAME, <<"5f0e7a2c-8a61-4d2b-b3c4-9e8d7c6b5a41.local">>).
-define(ID, 16#4242).

new() -> new(#{}).
new(Opts) -> ?R:new(maps:merge(#{ids => fun() -> ?ID end}, Opts)).

sends(Acts) -> [?MSG:decode(B) || {send, B} <- Acts].

legacy(Id, Name, Answers) ->
    ?MSG:encode_response(Id, [{Name, a}], Answers, []).

multicast(Answers) ->
    ?MSG:encode_response(0, [], Answers, []).

query_test() ->
    {R1, Acts} = ?R:resolve(?NAME, 0, new()),
    %% One question per message, A then AAAA, QU set on the first one.
    ?assertMatch(
        [
            {ok, #{id := ?ID, qr := false, questions := [#{name := ?NAME, type := a, unicast := true}]}},
            {ok, #{id := ?ID, questions := [#{name := ?NAME, type := aaaa, unicast := true}]}}
        ],
        sends(Acts)
    ),
    ?assertEqual(250, ?R:next_timeout(R1)),
    ?assertEqual([?NAME], ?R:pending(R1)).

retransmit_then_timeout_test() ->
    {R1, _} = ?R:resolve(?NAME, 0, new()),
    {R1, []} = ?R:handle_timeout(100, R1),
    {R2, A2} = ?R:handle_timeout(250, R1),
    %% Retransmissions clear the QU bit (RFC 6762 §5.4).
    ?assertMatch([{ok, #{questions := [#{unicast := false}]}}, {ok, #{questions := [#{unicast := false}]}}], sends(A2)),
    ?assertEqual(1250, ?R:next_timeout(R2)),
    {R3, A3} = ?R:handle_timeout(1250, R2),
    ?assertEqual(2, length(sends(A3))),
    ?assertEqual(3250, ?R:next_timeout(R3)),
    {R4, A4} = ?R:handle_timeout(3250, R3),
    ?assertEqual([{result, ?NAME, {error, timeout}}], A4),
    ?assertEqual(infinity, ?R:next_timeout(R4)),
    ?assertEqual([], ?R:pending(R4)).

legacy_unicast_answer_test() ->
    {R1, _} = ?R:resolve(?NAME, 0, new()),
    Resp = legacy(?ID, ?NAME, [{?NAME, {192, 168, 1, 7}, 10, false}]),
    {R2, Acts} = ?R:handle_packet(unicast, Resp, 30, R1),
    ?assertEqual([{result, ?NAME, {ok, [{192, 168, 1, 7}]}}], Acts),
    ?assertEqual(infinity, ?R:next_timeout(R2)),
    %% Cached for its TTL.
    ?assertEqual({ok, [{192, 168, 1, 7}]}, ?R:cached(?NAME, 5000, R2)),
    ?assertMatch({_, [{result, ?NAME, {ok, [{192, 168, 1, 7}]}}]}, ?R:resolve(?NAME, 9000, R2)),
    ?assertEqual(error, ?R:cached(?NAME, 10030, R2)),
    {_, Again} = ?R:resolve(?NAME, 10030, R2),
    ?assertEqual(2, length(sends(Again))).

legacy_answer_needs_id_and_question_test() ->
    {R1, _} = ?R:resolve(?NAME, 0, new()),
    Ans = [{?NAME, {192, 168, 1, 7}, 10, false}],
    ?assertEqual({R1, []}, ?R:handle_packet(unicast, legacy(?ID + 1, ?NAME, Ans), 1, R1)),
    ?assertEqual({R1, []}, ?R:handle_packet(unicast, multicast(Ans), 1, R1)),
    ?assertEqual({R1, []}, ?R:handle_packet(unicast, legacy(?ID, <<"other.local">>, Ans), 1, R1)).

multicast_answer_test() ->
    {R1, _} = ?R:resolve(<<"5F0E7A2C-8A61-4D2B-B3C4-9E8D7C6B5A41.LOCAL">>, 0, new()),
    %% Multicast responses carry ID 0, which is ignored (RFC 6762 §18.1);
    %% names compare case-insensitively.
    Resp = multicast([{?NAME, {10, 0, 0, 9}, 120, true}, {?NAME, {16#2001, 16#db8, 0, 0, 0, 0, 0, 9}, 120, true}]),
    {_, Acts} = ?R:handle_packet(multicast, Resp, 300, R1),
    ?assertEqual([{result, ?NAME, {ok, [{10, 0, 0, 9}, {16#2001, 16#db8, 0, 0, 0, 0, 0, 9}]}}], Acts).

additional_section_test() ->
    {R1, _} = ?R:resolve(?NAME, 0, new()),
    Resp = ?MSG:encode_response(0, [], [], [{?NAME, {10, 0, 0, 3}, 120, true}]),
    ?assertMatch({_, [{result, ?NAME, {ok, [{10, 0, 0, 3}]}}]}, ?R:handle_packet(multicast, Resp, 1, R1)).

unsolicited_ignored_test() ->
    R0 = new(),
    Resp = multicast([{?NAME, {10, 0, 0, 9}, 120, true}]),
    {R1, []} = ?R:handle_packet(multicast, Resp, 0, R0),
    %% Not cached either: a later query goes to the network.
    ?assertEqual(error, ?R:cached(?NAME, 1, R1)),
    {R2, Acts} = ?R:resolve(?NAME, 1, R1),
    ?assertEqual(2, length(sends(Acts))),
    %% An answer for another name does not complete the query.
    Other = multicast([{<<"other.local">>, {10, 0, 0, 8}, 120, true}]),
    ?assertMatch({_, []}, ?R:handle_packet(multicast, Other, 2, R2)).

invalid_responses_ignored_test() ->
    {R1, _} = ?R:resolve(?NAME, 0, new()),
    Good = multicast([{?NAME, {10, 0, 0, 9}, 120, true}]),
    <<Id:16, Flags:16, Rest/binary>> = Good,
    %% A query (QR clear), a non-zero opcode and an error rcode.
    [?assertEqual({R1, []}, ?R:handle_packet(multicast, <<Id:16, F:16, Rest/binary>>, 1, R1))
     || F <- [Flags band 16#7FFF, Flags bor (1 bsl 11), Flags bor 3]],
    %% Goodbye records (TTL 0) are not answers.
    Bye = multicast([{?NAME, {10, 0, 0, 9}, 0, true}]),
    ?assertEqual({R1, []}, ?R:handle_packet(multicast, Bye, 1, R1)),
    ?assertEqual({R1, []}, ?R:handle_packet(multicast, <<"garbage">>, 1, R1)),
    %% Truncated or random input never crashes.
    rand:seed(exsss, {4, 5, 6}),
    [{_, _} = ?R:handle_packet(multicast, binary:part(Good, 0, L), 1, R1) || L <- lists:seq(0, byte_size(Good))],
    [{_, _} = ?R:handle_packet(unicast, rand:bytes(rand:uniform(80)), 1, R1) || _ <- lists:seq(1, 2000)].

join_running_query_test() ->
    {R1, _} = ?R:resolve(?NAME, 0, new()),
    ?assertEqual({R1, []}, ?R:resolve(?NAME, 10, R1)).

bad_name_test() ->
    ?assertMatch({_, [{result, <<"a..local">>, {error, bad_name}}]}, ?R:resolve(<<"a..local">>, 0, new())).

max_queries_test() ->
    R0 = new(#{max_queries => 2}),
    {R1, _} = ?R:resolve(<<"a.local">>, 0, R0),
    {R2, _} = ?R:resolve(<<"b.local">>, 0, R1),
    ?assertMatch({_, [{result, <<"c.local">>, {error, too_many_queries}}]}, ?R:resolve(<<"c.local">>, 0, R2)).

cache_bounded_test() ->
    R0 = new(#{max_cache => 2}),
    Answer = fun(Name, TTL, Now, R) ->
        {R1, _} = ?R:resolve(Name, Now, R),
        {R2, [_]} = ?R:handle_packet(multicast, multicast([{Name, {10, 0, 0, 1}, TTL, true}]), Now, R1),
        R2
    end,
    R1 = Answer(<<"a.local">>, 100, 0, R0),
    R2 = Answer(<<"b.local">>, 50, 0, R1),
    R3 = Answer(<<"c.local">>, 100, 0, R2),
    %% The entry closest to expiry made room.
    ?assertEqual(error, ?R:cached(<<"b.local">>, 1, R3)),
    ?assertMatch({ok, _}, ?R:cached(<<"a.local">>, 1, R3)),
    ?assertMatch({ok, _}, ?R:cached(<<"c.local">>, 1, R3)).

ttl_capped_test() ->
    R0 = new(#{max_ttl => 5}),
    {R1, _} = ?R:resolve(?NAME, 0, R0),
    {R2, _} = ?R:handle_packet(multicast, multicast([{?NAME, {10, 0, 0, 1}, 4000000, true}]), 0, R1),
    ?assertMatch({ok, _}, ?R:cached(?NAME, 4999, R2)),
    ?assertEqual(error, ?R:cached(?NAME, 5000, R2)).
