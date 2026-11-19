%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Tests for the STUN client transaction table (RFC 8489 §6.2.1).
-module(webrtc_stun_tx_tests).
-include_lib("eunit/include/eunit.hrl").

-define(ID, <<1:96>>).

%% Drive the table with its own timer until it is empty or `Until'.
run(T, Until) ->
    run(T, Until, []).

run(T, Until, Acc) ->
    case webrtc_stun_tx:next_timeout(T) of
        infinity ->
            {T, lists:reverse(Acc)};
        Next when Next > Until ->
            {T, lists:reverse(Acc)};
        Next ->
            {T1, Acts} = webrtc_stun_tx:handle_timeout(Next, T),
            run(T1, Until, lists:reverse([{Next, A} || A <- Acts]) ++ Acc)
    end.

default_schedule_test() ->
    {T0, [{send, dest, <<"req">>}]} =
        webrtc_stun_tx:send(?ID, dest, <<"req">>, #{meta => m}, 0, webrtc_stun_tx:new()),
    {T1, Events} = run(T0, 100000),
    Sends = [At || {At, {send, dest, <<"req">>}} <- Events],
    ?assertEqual([500, 1500, 3500, 7500, 15500, 31500], Sends),
    ?assertEqual([{39500, {timeout, ?ID, dest, m}}], [E || {_, {timeout, _, _, _}} = E <- Events]),
    ?assertEqual(0, webrtc_stun_tx:size(T1)),
    ?assertEqual(infinity, webrtc_stun_tx:next_timeout(T1)).

custom_parameters_test() ->
    T = webrtc_stun_tx:new(#{rto => 100, rc => 3, rm => 4}),
    {T0, _} = webrtc_stun_tx:send(?ID, d, <<>>, #{}, 1000, T),
    {_, Events} = run(T0, 100000),
    ?assertEqual([{1100, {send, d, <<>>}}, {1300, {send, d, <<>>}}, {1700, {timeout, ?ID, d, undefined}}],
                 Events).

per_transaction_rto_test() ->
    {T0, _} = webrtc_stun_tx:send(?ID, d, <<>>, #{rto => 800, rc => 2, rm => 1}, 0, webrtc_stun_tx:new()),
    {_, Events} = run(T0, 100000),
    ?assertEqual([{800, {send, d, <<>>}}, {1600, {timeout, ?ID, d, undefined}}], Events).

single_request_test() ->
    {T0, _} = webrtc_stun_tx:send(?ID, d, <<>>, #{rc => 1, rm => 2}, 0, webrtc_stun_tx:new()),
    {_, Events} = run(T0, 100000),
    ?assertEqual([{1000, {timeout, ?ID, d, undefined}}], Events).

max_rto_cap_test() ->
    T = webrtc_stun_tx:new(#{max_rto => 1000}),
    {T0, _} = webrtc_stun_tx:send(?ID, d, <<>>, #{}, 0, T),
    {_, Events} = run(T0, 100000),
    ?assertEqual([500, 1500, 2500, 3500, 4500, 5500], [At || {At, {send, _, _}} <- Events]),
    ?assertEqual([13500], [At || {At, {timeout, _, _, _}} <- Events]).

response_test() ->
    {T0, _} = webrtc_stun_tx:send(?ID, d, <<>>, #{meta => m}, 0, webrtc_stun_tx:new()),
    ?assertEqual({ok, d, m}, webrtc_stun_tx:lookup(?ID, T0)),
    ?assertEqual(error, webrtc_stun_tx:response(<<2:96>>, 10, T0)),
    {ok, Info, T1} = webrtc_stun_tx:response(?ID, 120, T0),
    ?assertEqual(#{dest => d, meta => m, rtt => 120}, Info),
    ?assertEqual(error, webrtc_stun_tx:lookup(?ID, T1)),
    ?assertEqual(error, webrtc_stun_tx:response(?ID, 130, T1)).

karn_no_rtt_after_retransmit_test() ->
    {T0, _} = webrtc_stun_tx:send(?ID, d, <<>>, #{}, 0, webrtc_stun_tx:new()),
    {T1, [{send, d, <<>>}]} = webrtc_stun_tx:handle_timeout(500, T0),
    {ok, #{rtt := undefined}, _} = webrtc_stun_tx:response(?ID, 600, T1).

cancel_test() ->
    {T0, _} = webrtc_stun_tx:send(?ID, d, <<>>, #{}, 0, webrtc_stun_tx:new()),
    T1 = webrtc_stun_tx:cancel(?ID, T0),
    ?assertEqual(39500, webrtc_stun_tx:next_timeout(T1)),
    %% Still matched before the deadline.
    ?assertMatch({ok, _, _}, webrtc_stun_tx:response(?ID, 20000, T1)),
    %% No retransmission and no timeout event.
    {T2, Events} = run(T1, 100000),
    ?assertEqual([], Events),
    ?assertEqual(0, webrtc_stun_tx:size(T2)),
    ?assertEqual(webrtc_stun_tx:new(), webrtc_stun_tx:cancel(<<9:96>>, webrtc_stun_tx:new())).

remove_test() ->
    {T0, _} = webrtc_stun_tx:send(?ID, d, <<>>, #{}, 0, webrtc_stun_tx:new()),
    T1 = webrtc_stun_tx:remove(?ID, T0),
    ?assertEqual([], webrtc_stun_tx:ids(T1)),
    ?assertEqual(infinity, webrtc_stun_tx:next_timeout(T1)).

rto_cache_test() ->
    T = webrtc_stun_tx:new(#{min_rto => 1}),
    ?assertEqual(500, webrtc_stun_tx:rto(srv, 0, T)),
    {T0, _} = webrtc_stun_tx:send(?ID, d, <<>>, #{key => srv}, 0, T),
    {ok, _, T1} = webrtc_stun_tx:response(?ID, 100, T0),
    %% RFC 6298: SRTT = 100, RTTVAR = 50, RTO = 100 + 4 * 50.
    ?assertEqual(300, webrtc_stun_tx:rto(srv, 100, T1)),
    %% A new transaction to the same key starts with the cached RTO.
    {T2, _} = webrtc_stun_tx:send(<<2:96>>, d, <<>>, #{key => srv}, 200, T1),
    ?assertEqual(500, webrtc_stun_tx:next_timeout(T2)),
    %% Stale after 10 minutes without transactions.
    ?assertEqual(500, webrtc_stun_tx:rto(srv, 200 + 600001, T2)),
    ?assertEqual(500, webrtc_stun_tx:rto(other, 200, T2)).

rto_floor_test() ->
    T = webrtc_stun_tx:new(),
    {T0, _} = webrtc_stun_tx:send(?ID, d, <<>>, #{key => k}, 0, T),
    {ok, _, T1} = webrtc_stun_tx:response(?ID, 10, T0),
    ?assertEqual(500, webrtc_stun_tx:rto(k, 10, T1)).

many_transactions_test() ->
    T = lists:foldl(
        fun(N, Acc) -> element(1, webrtc_stun_tx:send(<<N:96>>, N, <<>>, #{rc => 1, rm => 1}, N, Acc)) end,
        webrtc_stun_tx:new(),
        lists:seq(1, 5)
    ),
    ?assertEqual(5, webrtc_stun_tx:size(T)),
    {T1, Acts} = webrtc_stun_tx:handle_timeout(503, T),
    ?assertEqual([{timeout, <<1:96>>, 1, undefined}, {timeout, <<2:96>>, 2, undefined},
                  {timeout, <<3:96>>, 3, undefined}], Acts),
    ?assertEqual(504, webrtc_stun_tx:next_timeout(T1)).
