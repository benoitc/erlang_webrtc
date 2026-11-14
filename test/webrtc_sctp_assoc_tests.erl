%% Deterministic tests of the SCTP association engine over the in-memory
%% network of webrtc_sctp_net.
-module(webrtc_sctp_assoc_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_sctp.hrl").

-define(A, webrtc_sctp_assoc).
-define(NET, webrtc_sctp_net).
-define(MINUTE, 60000).

%%====================================================================
%% Helpers
%%====================================================================

base_opts(Seed) ->
    #{random_seed => Seed, heartbeat_interval => infinity, cookie_secret => <<"secret">>}.

pair(OptsA, OptsB, NetOpts) ->
    A = ?A:new(maps:merge(base_opts(1), OptsA)),
    B = ?A:new(maps:merge(base_opts(2), OptsB)),
    ?NET:new(?A, {A, B}, maps:merge(#{seed => 7, mtu => 1200}, NetOpts)).

connect(Side, N) ->
    ?NET:call(Side, fun(E, Now) -> ?A:connect(Now, E) end, N).

%% Both sides send INIT, as WebRTC peers do.
established(OptsA, OptsB, NetOpts) ->
    N0 = connect(b, connect(a, pair(OptsA, OptsB, NetOpts))),
    {ok, N} = ?NET:run_until(fun both_connected/1, 10 * ?MINUTE, N0),
    N.

both_connected(N) -> connected(a, N) andalso connected(b, N).

connected(Side, N) ->
    lists:any(
        fun
            ({connected, _}) -> true;
            (_) -> false
        end,
        ?NET:events(Side, N)
    ).

send(Side, Sid, Data, Opts, N) ->
    send(Side, Sid, 53, Data, Opts, N).

send(Side, Sid, Ppid, Data, Opts, N) ->
    case ?NET:call(Side, fun(E, Now) -> ?A:send(Sid, Ppid, Data, Opts, Now, E) end, N) of
        {error, R} -> error({send_failed, R});
        N1 -> N1
    end.

closed(Side, N) ->
    [R || {closed, R} <- ?NET:events(Side, N)].

received(Side, N) -> ?NET:messages(Side, N).

wait_messages(Side, Count, N) ->
    {ok, N1} = ?NET:run_until(fun(X) -> length(received(Side, X)) >= Count end, 60 * ?MINUTE, N),
    N1.

payload(I, Size) ->
    Seed = crypto:hash(sha256, integer_to_binary(I)),
    binary:part(binary:copy(Seed, Size div 32 + 1), 0, Size).

stat(Side, K, N) ->
    maps:get(K, ?A:stats(?NET:engine(Side, N)), 0).

%%====================================================================
%% Handshake
%%====================================================================

handshake_test() ->
    N0 = connect(a, pair(#{}, #{}, #{})),
    {ok, N} = ?NET:run_until(fun both_connected/1, ?MINUTE, N0),
    ?assertEqual(established, ?A:state(?NET:engine(a, N))),
    ?assertEqual(established, ?A:state(?NET:engine(b, N))),
    [{connected, Info}] = ?NET:events(a, N),
    ?assertMatch(
        #{
            partial_reliability := true,
            stream_reconfig := true,
            message_interleaving := false,
            outbound_streams := 65535,
            inbound_streams := 65535
        },
        Info
    ),
    ?assertEqual(0, ?NET:stat(mtu_violations, N)).

simultaneous_init_test() ->
    N = established(#{}, #{}, #{}),
    N1 = ?NET:run(?MINUTE, N),
    ?assertMatch([{connected, _}], ?NET:events(a, N1)),
    ?assertMatch([{connected, _}], ?NET:events(b, N1)),
    %% Data flows both ways after the collision was resolved.
    N2 = send(a, 0, <<"from a">>, #{}, send(b, 1, <<"from b">>, #{}, N1)),
    N3 = wait_messages(a, 1, wait_messages(b, 1, N2)),
    ?assertEqual([{0, 53, <<"from a">>}], received(b, N3)),
    ?assertEqual([{1, 53, <<"from b">>}], received(a, N3)).

data_before_connect_test() ->
    N0 = send(a, 3, <<"early">>, #{}, pair(#{}, #{}, #{})),
    N1 = connect(a, N0),
    N2 = wait_messages(b, 1, N1),
    ?assertEqual([{3, 53, <<"early">>}], received(b, N2)).

%%====================================================================
%% Data transfer
%%====================================================================

large_message_test() ->
    Msg = payload(1, 256 * 1024),
    N0 = established(#{}, #{}, #{}),
    N1 = wait_messages(b, 1, send(a, 0, Msg, #{}, N0)),
    ?assertEqual([{0, 53, Msg}], received(b, N1)),
    ?assertEqual(0, ?NET:stat(mtu_violations, N1)).

large_message_small_mtu_test() ->
    Msg = payload(2, 100000),
    N0 = established(#{mtu => 576}, #{mtu => 576}, #{mtu => 576}),
    N1 = wait_messages(b, 1, send(a, 0, Msg, #{}, N0)),
    ?assertEqual([{0, 53, Msg}], received(b, N1)),
    ?assertEqual(0, ?NET:stat(mtu_violations, N1)).

ordered_delivery_with_reordering_test() ->
    N0 = established(#{}, #{}, #{reorder => 0.3, jitter => 20}),
    Msgs = [payload(I, 100 + I) || I <- lists:seq(1, 200)],
    N1 = lists:foldl(fun(M, Acc) -> send(a, 1, M, #{}, Acc) end, N0, Msgs),
    N2 = wait_messages(b, 200, N1),
    ?assertEqual([{1, 53, M} || M <- Msgs], received(b, N2)).

unordered_delivery_test() ->
    N0 = established(#{}, #{}, #{reorder => 0.3, jitter => 20, seed => 3}),
    Msgs = [payload(I, 100 + I) || I <- lists:seq(1, 200)],
    N1 = lists:foldl(fun(M, Acc) -> send(a, 1, M, #{ordered => false}, Acc) end, N0, Msgs),
    N2 = wait_messages(b, 200, N1),
    Got = [D || {1, 53, D} <- received(b, N2)],
    ?assertEqual(lists:sort(Msgs), lists:sort(Got)),
    %% The network reordered packets and unordered delivery shows it.
    ?assertNotEqual(Msgs, Got).

unordered_fragmented_test() ->
    N0 = established(#{}, #{}, #{reorder => 0.2, seed => 4}),
    Msgs = [payload(I, 5000 + I) || I <- lists:seq(1, 20)],
    N1 = lists:foldl(fun(M, Acc) -> send(a, 2, M, #{ordered => false}, Acc) end, N0, Msgs),
    N2 = wait_messages(b, 20, N1),
    ?assertEqual(lists:sort(Msgs), lists:sort([D || {2, 53, D} <- received(b, N2)])).

%% Random sized messages on several streams, both directions, lossy link.
lossy_transfer(Loss, Seed) ->
    Opts = #{max_retransmissions => 30},
    N0 = established(Opts, Opts, #{loss => Loss, seed => Seed, reorder => 0.05, dup => 0.02}),
    Sizes = [1 + (I * 7919) rem 6000 || I <- lists:seq(1, 120)],
    Msgs = [{I rem 4, payload(I, S)} || {I, S} <- lists:zip(lists:seq(1, 120), Sizes)],
    N1 = lists:foldl(fun({Sid, M}, Acc) -> send(a, Sid, M, #{}, Acc) end, N0, Msgs),
    N2 = lists:foldl(
        fun({Sid, M}, Acc) -> send(b, Sid, M, #{}, Acc) end, N1, lists:sublist(Msgs, 40)
    ),
    N3 = wait_messages(a, 40, wait_messages(b, 120, N2)),
    lists:foreach(
        fun(Sid) ->
            ?assert([M || {S, M} <- Msgs, S =:= Sid] =:= per_stream(Sid, b, N3)),
            ?assert([M || {S, M} <- lists:sublist(Msgs, 40), S =:= Sid] =:= per_stream(Sid, a, N3))
        end,
        lists:seq(0, 3)
    ),
    ?assertEqual([], closed(a, N3)),
    ?assertEqual(0, ?NET:stat(mtu_violations, N3)),
    N3.

per_stream(Sid, Side, N) ->
    [D || {S, _, D} <- received(Side, N), S =:= Sid].

loss_10_test_() ->
    {timeout, 120, fun() ->
        N = lossy_transfer(0.10, 11),
        ?assert(stat(a, retransmissions, N) > 0)
    end}.

loss_30_test_() ->
    {timeout, 300, fun() ->
        N = lossy_transfer(0.30, 12),
        ?assert(stat(a, retransmissions, N) > 0),
        ?assert(stat(a, t3_expirations, N) > 0)
    end}.

%% Drop one DATA packet: later SACKs report the gap and the sender
%% retransmits it without waiting for T3-rtx.
fast_retransmit_test() ->
    Count = counters:new(1, []),
    Filter = fun
        (a, Bin, _Now) ->
            {ok, #sctp_packet{chunks = Cs}} = webrtc_sctp_chunk:decode(Bin),
            case [T || #sctp_data{tsn = T} <- Cs] of
                [_ | _] ->
                    counters:add(Count, 1, 1),
                    case counters:get(Count, 1) of
                        4 -> drop;
                        _ -> keep
                    end;
                [] ->
                    keep
            end;
        (_, _, _) ->
            keep
    end,
    N0 = established(#{}, #{}, #{filter => Filter}),
    Msgs = [payload(I, 1000) || I <- lists:seq(1, 40)],
    N1 = lists:foldl(fun(M, Acc) -> send(a, 0, M, #{}, Acc) end, N0, Msgs),
    N2 = wait_messages(b, 40, N1),
    ?assertEqual([{0, 53, M} || M <- Msgs], received(b, N2)),
    ?assert(stat(a, fast_retransmits, N2) >= 1),
    ?assertEqual(0, stat(a, t3_expirations, N2)).

buffered_amount_test() ->
    N0 = established(#{}, #{}, #{}),
    N1 = ?NET:call(a, fun(E, _) -> {?A:set_buffered_amount_low_threshold(5, 1000, E), []} end, N0),
    {ok, E1, _} = ?A:send(5, 53, payload(1, 50000), #{}, ?NET:now(N1), ?NET:engine(a, N1)),
    ?assert(?A:buffered_amount(5, E1) > 1000),
    N2 = send(a, 5, payload(2, 50000), #{}, N1),
    N3 = wait_messages(b, 1, N2),
    ?assertEqual(0, ?A:buffered_amount(5, ?NET:engine(a, N3))),
    ?assert(lists:member({buffered_amount_low, 5}, ?NET:events(a, N3))).

send_buffer_limit_test() ->
    N0 = ?NET:set(loss, 1.0, established(#{send_buffer => 10000}, #{}, #{})),
    E = ?NET:engine(a, N0),
    {ok, E1, _} = ?A:send(0, 53, payload(1, 8000), #{}, 0, E),
    Room = 10000 - ?A:buffered_amount(0, E1),
    {ok, E2, _} = ?A:send(0, 53, payload(2, Room), #{}, 0, E1),
    ?assertEqual({error, buffer_full}, ?A:send(0, 53, payload(3, 10000), #{}, 0, E2)),
    ?assertEqual({error, empty_message}, ?A:send(0, 53, <<>>, #{}, 0, E2)),
    ?assertEqual({error, badarg}, ?A:send(0, 53, <<"x">>, #{max_retransmits => -1}, 0, E2)).

%%====================================================================
%% Partial reliability (RFC 3758)
%%====================================================================

pr_max_retransmits_test() ->
    N0 = established(#{}, #{}, #{loss => 0.3, seed => 21}),
    Msgs = [payload(I, 800) || I <- lists:seq(1, 100)],
    N1 = lists:foldl(
        fun(M, Acc) -> send(a, 1, M, #{ordered => false, max_retransmits => 0}, Acc) end,
        N0,
        Msgs
    ),
    N2 = ?NET:run(5 * ?MINUTE, N1),
    Got = [D || {1, _, D} <- received(b, N2)],
    ?assert(length(Got) < 100),
    ?assert(length(Got) > 30),
    ?assertEqual([], Got -- Msgs),
    ?assert(stat(a, forward_tsn_sent, N2) > 0),
    ?assertEqual(0, stat(a, retransmissions, N2)),
    %% The association keeps working: a reliable message still arrives.
    N3 = ?NET:set(loss, 0.0, N2),
    N4 = send(a, 2, <<"reliable">>, #{}, N3),
    {ok, N5a} = ?NET:run_until(fun(X) -> lists:keymember(2, 1, received(b, X)) end, ?MINUTE, N4),
    N5 = ?NET:run(1000, N5a),
    ?assertEqual([], closed(a, N5)),
    ?assertEqual(0, ?A:buffered_amount(1, ?NET:engine(a, N5))),
    ?assertEqual(0, stat(a, outstanding_chunks, N5)).

pr_ordered_max_retransmits_test() ->
    N0 = established(#{}, #{}, #{loss => 0.25, seed => 22}),
    Msgs = [payload(I, 3000) || I <- lists:seq(1, 60)],
    N1 = lists:foldl(fun(M, Acc) -> send(a, 1, M, #{max_retransmits => 1}, Acc) end, N0, Msgs),
    N2 = ?NET:run(10 * ?MINUTE, N1),
    Got = [D || {1, _, D} <- received(b, N2)],
    %% Ordered partial reliability: a subsequence, in order.
    ?assertEqual(Got, [M || M <- Msgs, lists:member(M, Got)]),
    ?assert(length(Got) < 60),
    ?assertEqual(0, stat(a, outstanding_chunks, N2)),
    %% Nothing stays stranded in the receive buffer.
    ?assertEqual(1048576, stat(b, a_rwnd, N2)).

pr_lifetime_test() ->
    %% Long one-way delay: messages expire while waiting in the queue
    %% behind the congestion window.
    N0 = established(#{}, #{}, #{delay => 200}),
    Msgs = [payload(I, 1100) || I <- lists:seq(1, 200)],
    N1 = lists:foldl(fun(M, Acc) -> send(a, 1, M, #{max_lifetime => 300}, Acc) end, N0, Msgs),
    N2 = ?NET:run(2 * ?MINUTE, N1),
    Got = [D || {1, _, D} <- received(b, N2)],
    ?assert(length(Got) < 200),
    ?assert(length(Got) > 0),
    ?assertEqual(Got, [M || M <- Msgs, lists:member(M, Got)]),
    ?assert(stat(a, expired_messages, N2) > 0),
    ?assertEqual(0, ?A:buffered_amount(1, ?NET:engine(a, N2))).

pr_lifetime_loss_test() ->
    N0 = established(#{}, #{}, #{loss => 0.3, seed => 5}),
    Msgs = [payload(I, 2500) || I <- lists:seq(1, 50)],
    N1 = lists:foldl(fun(M, Acc) -> send(a, 3, M, #{max_lifetime => 500}, Acc) end, N0, Msgs),
    N2 = ?NET:run(5 * ?MINUTE, N1),
    Got = [D || {3, _, D} <- received(b, N2)],
    ?assertEqual(Got, [M || M <- Msgs, lists:member(M, Got)]),
    ?assert(stat(a, abandoned_messages, N2) + stat(a, expired_messages, N2) > 0),
    ?assertEqual(0, stat(a, outstanding_chunks, N2)),
    ?assertEqual(1048576, stat(b, a_rwnd, N2)).

%%====================================================================
%% Stream reset (RFC 6525)
%%====================================================================

reset(Side, Sids, N) ->
    case ?NET:call(Side, fun(E, Now) -> ?A:reset_streams(Sids, Now, E) end, N) of
        {error, R} -> error({reset_failed, R});
        N1 -> N1
    end.

not_connected_events(Side, N) ->
    [E || E <- ?NET:events(Side, N), element(1, E) =/= connected].

stream_reset_test() ->
    N0 = established(#{}, #{}, #{}),
    N1 = send(a, 1, <<"one">>, #{}, send(a, 1, <<"zero">>, #{}, N0)),
    N2 = reset(a, [1], N1),
    %% Sent after the reset request: waits, then starts at SSN 0.
    N3 = send(a, 1, <<"after">>, #{}, N2),
    {ok, N4} = ?NET:run_until(fun(X) -> length(received(b, X)) =:= 3 end, ?MINUTE, N3),
    ?assertEqual(
        [
            {message, 1, 53, <<"zero">>},
            {message, 1, 53, <<"one">>},
            {stream_reset, [1]},
            {message, 1, 53, <<"after">>}
        ],
        not_connected_events(b, N4)
    ),
    ?assert(lists:member({outgoing_stream_reset, [1]}, ?NET:events(a, N4))).

stream_reset_both_directions_test() ->
    N0 = established(#{}, #{}, #{}),
    N1 = reset(a, [4], send(a, 4, <<"x">>, #{}, N0)),
    {ok, N2} = ?NET:run_until(
        fun(X) -> lists:member({stream_reset, [4]}, ?NET:events(b, X)) end, ?MINUTE, N1
    ),
    N3 = reset(b, [4], N2),
    {ok, N4} = ?NET:run_until(
        fun(X) -> lists:member({outgoing_stream_reset, [4]}, ?NET:events(b, X)) end, ?MINUTE, N3
    ),
    ?assert(lists:member({stream_reset, [4]}, ?NET:events(a, N4))),
    ?assert(lists:member({outgoing_stream_reset, [4]}, ?NET:events(a, N4))).

%% The RE-CONFIG overtakes the last DATA chunk: the receiver defers the
%% reset until the chunk arrives (RFC 6525 §5.2.2 E2).
stream_reset_deferred_test() ->
    Count = counters:new(1, []),
    Filter = fun
        (a, Bin, _Now) ->
            {ok, #sctp_packet{chunks = Cs}} = webrtc_sctp_chunk:decode(Bin),
            case [D || #sctp_data{data = D} <- Cs] of
                [<<"last">>] ->
                    counters:add(Count, 1, 1),
                    case counters:get(Count, 1) of
                        1 -> drop;
                        _ -> keep
                    end;
                _ ->
                    keep
            end;
        (_, _, _) ->
            keep
    end,
    N0 = established(#{}, #{}, #{filter => Filter}),
    N1 = reset(a, [2], send(a, 2, <<"last">>, #{}, N0)),
    {ok, N2} = ?NET:run_until(
        fun(X) -> lists:member({stream_reset, [2]}, ?NET:events(b, X)) end, ?MINUTE, N1
    ),
    ?assertEqual([{message, 2, 53, <<"last">>}, {stream_reset, [2]}], not_connected_events(b, N2)),
    {ok, N3} = ?NET:run_until(
        fun(X) -> lists:member({outgoing_stream_reset, [2]}, ?NET:events(a, X)) end, ?MINUTE, N2
    ),
    ?assertEqual([], closed(a, N3)).

stream_reset_lossy_test_() ->
    {timeout, 60, fun() ->
        N0 = established(#{}, #{}, #{loss => 0.3, seed => 31}),
        N1 = lists:foldl(
            fun(I, Acc) -> send(a, 7, payload(I, 2000), #{}, Acc) end, N0, lists:seq(1, 20)
        ),
        N2 = reset(a, [7], N1),
        N3 = send(a, 7, <<"new">>, #{}, N2),
        {ok, N4} = ?NET:run_until(fun(X) -> length(received(b, X)) =:= 21 end, 30 * ?MINUTE, N3),
        ?assertEqual(
            [{message, 7, 53, payload(I, 2000)} || I <- lists:seq(1, 20)] ++
                [{stream_reset, [7]}, {message, 7, 53, <<"new">>}],
            not_connected_events(b, N4)
        )
    end}.

reset_errors_test() ->
    N = established(#{}, #{}, #{}),
    ?assertEqual({error, invalid_stream}, ?A:reset_streams([70000], 0, ?NET:engine(a, N))),
    ?assertEqual({error, invalid_stream}, ?A:reset_streams([], 0, ?NET:engine(a, N))),
    ?assertEqual({error, not_connected}, ?A:reset_streams([1], 0, ?A:new(#{}))).

%%====================================================================
%% Message interleaving (RFC 8260)
%%====================================================================

interleaving_test() ->
    Opts = #{interleaving => true},
    N0 = established(Opts, Opts, #{}),
    [{connected, #{message_interleaving := true}}] = ?NET:events(a, N0),
    Large = payload(1, 200 * 1024),
    N1 = send(a, 2, <<"small">>, #{}, send(a, 1, Large, #{}, N0)),
    N2 = wait_messages(b, 2, N1),
    %% The small message is not stuck behind the large one.
    ?assertEqual([{2, 53, <<"small">>}, {1, 53, Large}], received(b, N2)).

no_interleaving_test() ->
    N0 = established(#{interleaving => true}, #{}, #{}),
    [{connected, #{message_interleaving := false}}] = ?NET:events(a, N0),
    Large = payload(1, 200 * 1024),
    N1 = send(a, 2, <<"small">>, #{}, send(a, 1, Large, #{}, N0)),
    N2 = wait_messages(b, 2, N1),
    ?assertEqual([{1, 53, Large}, {2, 53, <<"small">>}], received(b, N2)).

interleaving_lossy_test_() ->
    {timeout, 120, fun() ->
        Opts = #{interleaving => true, max_retransmissions => 30},
        N0 = established(Opts, Opts, #{loss => 0.2, seed => 41, reorder => 0.1}),
        Msgs = [{I rem 3, payload(I, 1 + (I * 3571) rem 20000)} || I <- lists:seq(1, 60)],
        N1 = lists:foldl(fun({S, M}, Acc) -> send(a, S, M, #{}, Acc) end, N0, Msgs),
        N2 = wait_messages(b, 60, N1),
        lists:foreach(
            fun(Sid) ->
                ?assertEqual(
                    [M || {S, M} <- Msgs, S =:= Sid],
                    [D || {S, _, D} <- received(b, N2), S =:= Sid]
                )
            end,
            [0, 1, 2]
        )
    end}.

interleaving_pr_test() ->
    Opts = #{interleaving => true},
    N0 = established(Opts, Opts, #{loss => 0.3, seed => 42}),
    Msgs = [payload(I, 3000) || I <- lists:seq(1, 40)],
    N1 = lists:foldl(
        fun(M, Acc) -> send(a, 1, M, #{ordered => false, max_retransmits => 0}, Acc) end, N0, Msgs
    ),
    N2 = lists:foldl(fun(M, Acc) -> send(a, 2, M, #{max_retransmits => 0}, Acc) end, N1, Msgs),
    N3 = ?NET:run(5 * ?MINUTE, N2),
    Got2 = [D || {2, _, D} <- received(b, N3)],
    ?assertEqual(Got2, [M || M <- Msgs, lists:member(M, Got2)]),
    ?assertEqual([], [D || {1, _, D} <- received(b, N3)] -- Msgs),
    ?assert(stat(a, forward_tsn_sent, N3) > 0),
    ?assertEqual(0, stat(a, outstanding_chunks, N3)),
    ?assertEqual(1048576, stat(b, a_rwnd, N3)).

%%====================================================================
%% Termination
%%====================================================================

shutdown_test() ->
    N0 = established(#{}, #{}, #{}),
    Msgs = [payload(I, 4000) || I <- lists:seq(1, 30)],
    N1 = lists:foldl(fun(M, Acc) -> send(a, 0, M, #{}, Acc) end, N0, Msgs),
    N2 = ?NET:call(a, fun(E, Now) -> ?A:shutdown(Now, E) end, N1),
    ?assertEqual({error, shutting_down}, ?A:send(0, 53, <<"late">>, #{}, 0, ?NET:engine(a, N2))),
    {ok, N3} = ?NET:run_until(
        fun(X) -> closed(a, X) =/= [] andalso closed(b, X) =/= [] end, ?MINUTE, N2
    ),
    ?assertEqual([{0, 53, M} || M <- Msgs], received(b, N3)),
    ?assertEqual([shutdown], closed(a, N3)),
    ?assertEqual([shutdown], closed(b, N3)),
    ?assertEqual(infinity, ?A:next_timeout(?NET:engine(a, N3))),
    ?assertEqual(infinity, ?A:next_timeout(?NET:engine(b, N3))).

shutdown_lossy_test() ->
    N0 = established(#{}, #{}, #{loss => 0.3, seed => 51}),
    N1 = lists:foldl(
        fun(I, Acc) -> send(b, 0, payload(I, 3000), #{}, Acc) end, N0, lists:seq(1, 10)
    ),
    N2 = ?NET:call(b, fun(E, Now) -> ?A:shutdown(Now, E) end, N1),
    {ok, N3} = ?NET:run_until(fun(X) -> closed(b, X) =/= [] end, 30 * ?MINUTE, N2),
    ?assertEqual([{0, 53, payload(I, 3000)} || I <- lists:seq(1, 10)], received(a, N3)),
    ?assertEqual([shutdown], closed(b, N3)).

abort_test() ->
    N0 = established(#{}, #{}, #{}),
    N1 = ?NET:call(a, fun(E, Now) -> ?A:abort(<<"bye">>, Now, E) end, N0),
    N2 = ?NET:run(?MINUTE, N1),
    ?assertEqual([aborted], closed(a, N2)),
    ?assertEqual([{peer_abort, [{user_abort, <<"bye">>}]}], closed(b, N2)),
    ?assertEqual({error, closed}, ?A:send(0, 53, <<"x">>, #{}, 0, ?NET:engine(a, N2))).

retransmission_limit_test() ->
    N0 = established(#{}, #{}, #{}),
    N1 = ?NET:set(loss, 1.0, N0),
    N2 = send(a, 0, <<"lost">>, #{}, N1),
    {ok, N3} = ?NET:run_until(fun(X) -> closed(a, X) =/= [] end, 30 * ?MINUTE, N2),
    ?assertEqual([max_retransmissions], closed(a, N3)),
    ?assertEqual(11, stat(a, t3_expirations, N3)).

heartbeat_failure_test() ->
    Opts = #{heartbeat_interval => 1000, max_retransmissions => 3},
    N0 = established(Opts, Opts, #{}),
    N1 = ?NET:run(10000, N0),
    ?assert(stat(a, heartbeats_sent, N1) > 0),
    ?assertNotEqual(undefined, stat(a, srtt, N1)),
    ?assertEqual([], closed(a, N1)),
    N2 = ?NET:set(loss, 1.0, N1),
    {ok, N3} = ?NET:run_until(fun(X) -> closed(a, X) =/= [] end, 10 * ?MINUTE, N2),
    ?assertEqual([max_retransmissions], closed(a, N3)).

handshake_timeout_test() ->
    N0 = connect(a, pair(#{}, #{}, #{loss => 1.0})),
    {ok, N1} = ?NET:run_until(fun(X) -> closed(a, X) =/= [] end, 30 * ?MINUTE, N0),
    ?assertEqual([handshake_timeout], closed(a, N1)),
    ?assertEqual(8, stat(a, init_retransmissions, N1)).

%%====================================================================
%% Restart and cookies (RFC 9260 §5.2)
%%====================================================================

peer_restart_test() ->
    N0 = established(#{}, #{}, #{}),
    N1 = wait_messages(b, 1, send(a, 0, <<"before">>, #{}, N0)),
    %% B loses its state and opens a new association.
    B2 = ?A:new(base_opts(99)),
    N2 = connect(b, ?NET:clear_events(b, ?NET:set_engine(b, B2, N1))),
    {ok, N3} = ?NET:run_until(fun(X) -> connected(b, X) end, ?MINUTE, N2),
    ?assertMatch([{restarted, _}], [E || {restarted, _} = E <- ?NET:events(a, N3)]),
    N4 = wait_messages(b, 1, send(a, 0, <<"after">>, #{}, N3)),
    ?assertEqual([{0, 53, <<"after">>}], received(b, N4)).

stale_cookie_test() ->
    %% Cookies live 100 ms but the round trip takes 400 ms.
    N0 = connect(a, pair(#{}, #{cookie_lifetime => 100}, #{delay => 200})),
    {ok, N1} = ?NET:run_until(fun both_connected/1, ?MINUTE, N0),
    ?assertEqual(1, stat(b, stale_cookies, N1)),
    ?assertEqual([], closed(a, N1)).

bad_cookie_test() ->
    N0 = established(#{}, #{}, #{}),
    B = ?NET:engine(b, N0),
    Forged = binary:copy(<<"forged">>, 20),
    Pkt = webrtc_sctp_chunk:encode(#sctp_packet{vtag = 1234, chunks = [{cookie_echo, Forged}]}),
    {B1, Acts} = ?A:handle_packet(Pkt, 1000, B),
    ?assertEqual([], Acts),
    ?assertEqual(established, ?A:state(B1)).

%%====================================================================
%% Flow control
%%====================================================================

%% Rewrite the a_rwnd of SACKs from b to 0 for a while: a must probe the
%% closed window and finish once it reopens.
zero_window_test_() ->
    {timeout, 60, fun() ->
        Filter = fun
            (b, Bin, Now) when Now < 20000 ->
                {ok, #sctp_packet{chunks = Cs} = P} = webrtc_sctp_chunk:decode(Bin),
                Cs1 = [zero_rwnd(C) || C <- Cs],
                {replace, webrtc_sctp_chunk:encode(P#sctp_packet{chunks = Cs1})};
            (_, _, _) ->
                keep
        end,
        N0 = established(#{}, #{}, #{filter => Filter}),
        Msgs = [payload(I, 1000) || I <- lists:seq(1, 30)],
        N1 = lists:foldl(fun(M, Acc) -> send(a, 0, M, #{}, Acc) end, N0, Msgs),
        N2 = ?NET:run(19000, N1),
        ?assert(stat(a, zero_window_probes, N2) > 0),
        ?assert(length(received(b, N2)) < 30),
        N3 = wait_messages(b, 30, N2),
        ?assertEqual([{0, 53, M} || M <- Msgs], received(b, N3)),
        ?assertEqual([], closed(a, N3))
    end}.

zero_rwnd(#sctp_sack{} = S) -> S#sctp_sack{a_rwnd = 0};
zero_rwnd(C) -> C.

receive_window_test() ->
    %% A small receive buffer: the sender never overruns it.
    N0 = established(
        #{}, #{receive_buffer => 8000, max_message_size => 8000}, #{reorder => 0.2}
    ),
    Msgs = [payload(I, 3000) || I <- lists:seq(1, 50)],
    N1 = lists:foldl(fun(M, Acc) -> send(a, 0, M, #{}, Acc) end, N0, Msgs),
    N2 = wait_messages(b, 50, N1),
    ?assertEqual([{0, 53, M} || M <- Msgs], received(b, N2)),
    ?assertEqual(0, stat(b, dropped_chunks, N2)).

too_large_message_test() ->
    N0 = established(#{}, #{max_message_size => 10000}, #{}),
    N1 = ?NET:run(1000, send(a, 0, payload(1, 20000), #{}, N0)),
    ?assertMatch([{protocol_violation, _}], closed(b, N1)),
    ?assertMatch([{peer_abort, _}], closed(a, N1)).

%%====================================================================
%% Many streams
%%====================================================================

many_streams_test_() ->
    {timeout, 60, fun() ->
        N0 = established(#{}, #{}, #{}),
        Sids = lists:seq(0, 1023),
        N1 = lists:foldl(fun(S, Acc) -> send(a, S, payload(S, 100), #{}, Acc) end, N0, Sids),
        N2 = wait_messages(b, 1024, N1),
        ?assertEqual(
            lists:sort([{S, 53, payload(S, 100)} || S <- Sids]), lists:sort(received(b, N2))
        ),
        N3 = reset(a, Sids, N2),
        Reset = fun(X) ->
            lists:usort(lists:append([L || {stream_reset, L} <- ?NET:events(b, X)]))
        end,
        {ok, N4} = ?NET:run_until(fun(X) -> Reset(X) =:= Sids end, ?MINUTE, N3),
        ?assertEqual(Sids, Reset(N4)),
        ?assertEqual(0, ?NET:stat(mtu_violations, N4))
    end}.

%%====================================================================
%% Zero checksum (RFC 9653) and packet validation
%%====================================================================

capture(Side, Tab) ->
    fun
        (S, Bin, _Now) when S =:= Side ->
            ets:insert(Tab, {erlang:unique_integer([monotonic]), Bin}),
            keep;
        (_, _, _) ->
            keep
    end.

zero_checksum_test() ->
    Tab = ets:new(cap, [ordered_set, public]),
    Opts = #{zero_checksum => true},
    N0 = established(Opts, Opts, #{filter => capture(a, Tab)}),
    [{connected, #{zero_checksum := true}}] = ?NET:events(a, N0),
    N1 = wait_messages(b, 1, send(a, 0, <<"zero">>, #{}, N0)),
    Sums = [
        {kind(hd(P#sctp_packet.chunks)), P#sctp_packet.checksum}
     || {_, B} <- ets:tab2list(Tab), {ok, P} <- [webrtc_sctp_chunk:decode(B)]
    ],
    ?assert(
        lists:all(
            fun
                ({sctp_init, C}) -> C =/= 0;
                (_) -> true
            end,
            Sums
        )
    ),
    ?assert(lists:member({sctp_data, 0}, Sums)),
    ?assertEqual([{0, 53, <<"zero">>}], received(b, N1)),
    ets:delete(Tab).

kind(C) when is_atom(C) -> C;
kind(C) -> element(1, C).

zero_checksum_one_side_test() ->
    Tab = ets:new(cap, [ordered_set, public]),
    N0 = established(#{zero_checksum => true}, #{}, #{filter => capture(a, Tab)}),
    [{connected, #{zero_checksum := false}}] = ?NET:events(a, N0),
    N1 = wait_messages(b, 1, send(a, 0, <<"crc">>, #{}, N0)),
    ?assert(
        lists:all(fun({_, B}) -> webrtc_sctp_chunk:checksum_ok(B, false) end, ets:tab2list(Tab))
    ),
    ?assertEqual(1, length(received(b, N1))),
    ets:delete(Tab).

%% Learn b's verification tag from a packet a sends.
peer_vtag(N) ->
    Tab = ets:new(cap, [ordered_set, public]),
    N1 = ?NET:set(filter, capture(a, Tab), N),
    N2 = wait_messages(b, 1, send(a, 9, <<"probe">>, #{}, N1)),
    [{_, Bin} | _] = ets:tab2list(Tab),
    ets:delete(Tab),
    {ok, #sctp_packet{vtag = V}} = webrtc_sctp_chunk:decode(Bin),
    {V, ?NET:set(filter, undefined, N2)}.

inject(Vtag, Chunks, N) ->
    B = ?NET:engine(b, N),
    Pkt = webrtc_sctp_chunk:encode(#sctp_packet{vtag = Vtag, chunks = Chunks}),
    {B1, Acts} = ?A:handle_packet(Pkt, ?NET:now(N), B),
    Out = [
        C
     || {send, Bin} <- Acts,
        {ok, #sctp_packet{chunks = Cs}} <- [webrtc_sctp_chunk:decode(Bin)],
        C <- Cs
    ],
    {B1, Out, Acts}.

unknown_chunk_test() ->
    {V, N} = peer_vtag(established(#{}, #{}, #{})),
    Hb = {heartbeat, <<"hb">>},
    %% 01: stop and report.
    {_, Out1, _} = inject(V, [{unknown_chunk, 16#41, 0, <<1, 2, 3>>}, Hb], N),
    ?assertMatch([{op_error, [{unrecognized_chunk, _}]}], Out1),
    %% 00: stop silently.
    {_, Out2, _} = inject(V, [{unknown_chunk, 16#21, 0, <<>>}, Hb], N),
    ?assertEqual([], Out2),
    %% 10: skip silently.
    {_, Out3, _} = inject(V, [{unknown_chunk, 16#81, 0, <<>>}, Hb], N),
    ?assertEqual([{heartbeat_ack, <<"hb">>}], Out3),
    %% 11: skip and report.
    {_, Out4, _} = inject(V, [{unknown_chunk, 16#C1, 0, <<9>>}, Hb], N),
    ?assertMatch([{op_error, [{unrecognized_chunk, _}]}, {heartbeat_ack, <<"hb">>}], Out4).

bad_vtag_test() ->
    {V, N} = peer_vtag(established(#{}, #{}, #{})),
    {_, Out, Acts} = inject(V bxor 1, [{heartbeat, <<"hb">>}], N),
    ?assertEqual([], Out),
    ?assertEqual([], Acts).

bad_checksum_test() ->
    {V, N} = peer_vtag(established(#{}, #{}, #{})),
    Pkt = webrtc_sctp_chunk:encode(
        #sctp_packet{vtag = V, chunks = [{heartbeat, <<"hb">>}]}, #{checksum => zero}
    ),
    {_, Acts} = ?A:handle_packet(Pkt, ?NET:now(N), ?NET:engine(b, N)),
    ?assertEqual([], Acts).

no_user_data_test() ->
    {V, N} = peer_vtag(established(#{}, #{}, #{})),
    {B1, Out, _} = inject(V, [#sctp_data{tsn = 5, data = <<>>}], N),
    ?assertMatch([{abort, false, [{no_user_data, 5}]}], Out),
    ?assertEqual(closed, ?A:state(B1)).

sack_unsent_tsn_test() ->
    Tab = ets:new(cap, [ordered_set, public]),
    N0 = established(#{}, #{}, #{filter => capture(b, Tab)}),
    N1 = wait_messages(a, 1, send(b, 0, <<"data">>, #{}, N0)),
    [Tsn] = [
        T
     || {_, Bin} <- ets:tab2list(Tab),
        {ok, #sctp_packet{chunks = Cs}} <- [webrtc_sctp_chunk:decode(Bin)],
        #sctp_data{tsn = T} <- Cs
    ],
    ets:delete(Tab),
    {V, N} = peer_vtag(N1),
    %% Acknowledging the TSN already sent is fine, the next one is not.
    {_, [], _} = inject(V, [#sctp_sack{cum_tsn = Tsn, a_rwnd = 100000}], N),
    {B1, Out, _} = inject(
        V, [#sctp_sack{cum_tsn = (Tsn + 1) band 16#FFFFFFFF, a_rwnd = 100000}], N
    ),
    ?assertMatch([{abort, false, [{protocol_violation, _}]}], Out),
    ?assertEqual(closed, ?A:state(B1)).

ootb_test() ->
    E = ?A:new(base_opts(5)),
    Data = webrtc_sctp_chunk:encode(
        #sctp_packet{vtag = 77, chunks = [#sctp_data{tsn = 1, data = <<"x">>}]}
    ),
    {_, [{send, Bin}]} = ?A:handle_packet(Data, 0, E),
    ?assertMatch(
        {ok, #sctp_packet{vtag = 77, chunks = [{abort, true, []}]}}, webrtc_sctp_chunk:decode(Bin)
    ),
    Ack = webrtc_sctp_chunk:encode(#sctp_packet{vtag = 78, chunks = [shutdown_ack]}),
    {_, [{send, Bin2}]} = ?A:handle_packet(Ack, 0, E),
    ?assertMatch(
        {ok, #sctp_packet{vtag = 78, chunks = [{shutdown_complete, true}]}},
        webrtc_sctp_chunk:decode(Bin2)
    ),
    Abort = webrtc_sctp_chunk:encode(#sctp_packet{vtag = 79, chunks = [{abort, false, []}]}),
    ?assertMatch({_, []}, ?A:handle_packet(Abort, 0, E)),
    ?assertMatch({_, []}, ?A:handle_packet(<<"garbage">>, 0, E)).

init_validation_test() ->
    E = ?A:new(base_opts(5)),
    Init = #sctp_init{tag = 1, a_rwnd = 100000, os = 1, mis = 1, tsn = 1},
    Bad = webrtc_sctp_chunk:encode(#sctp_packet{vtag = 0, chunks = [Init, cookie_ack]}),
    ?assertMatch({_, []}, ?A:handle_packet(Bad, 0, E)),
    Bad2 = webrtc_sctp_chunk:encode(#sctp_packet{vtag = 5, chunks = [Init]}),
    ?assertMatch({_, []}, ?A:handle_packet(Bad2, 0, E)),
    ZeroTag = webrtc_sctp_chunk:encode(#sctp_packet{vtag = 0, chunks = [Init#sctp_init{tag = 0}]}),
    ?assertMatch({_, []}, ?A:handle_packet(ZeroTag, 0, E)),
    NoStreams = webrtc_sctp_chunk:encode(#sctp_packet{vtag = 0, chunks = [Init#sctp_init{os = 0}]}),
    {_, [{send, Abort}]} = ?A:handle_packet(NoStreams, 0, E),
    ?assertMatch(
        {ok, #sctp_packet{vtag = 1, chunks = [{abort, false, [invalid_mandatory_param]}]}},
        webrtc_sctp_chunk:decode(Abort)
    ),
    %% Unknown parameter with "skip and report" comes back in INIT ACK.
    Unknown = {unknown_param, 16#C123, <<1, 2, 3, 4>>},
    Good = webrtc_sctp_chunk:encode(
        #sctp_packet{vtag = 0, chunks = [Init#sctp_init{params = [Unknown]}]}
    ),
    {E1, [{send, Bin}]} = ?A:handle_packet(Good, 0, E),
    {ok, #sctp_packet{vtag = 1, chunks = [#sctp_init{ack = true, params = Ps}]}} =
        webrtc_sctp_chunk:decode(Bin),
    ?assert(lists:keymember(state_cookie, 1, Ps)),
    ?assertEqual(
        [{unrecognized_param, webrtc_sctp_param:encode_param(Unknown)}],
        [P || {unrecognized_param, _} = P <- Ps]
    ),
    %% Stateless: no TCB was created.
    ?assertEqual(closed, ?A:state(E1)).

bad_options_test() ->
    ?assertError({badarg, mtu}, ?A:new(#{mtu => 10})),
    ?assertError({badarg, sack_delay}, ?A:new(#{sack_delay => 600})),
    ?assertError({badarg, heartbeat_interval}, ?A:new(#{heartbeat_interval => -1})).

%%====================================================================
%% SACK timing, invalid streams, chunk type mismatches
%%====================================================================

%% One DATA packet is acknowledged after SACK.Delay; a second packet
%% triggers an immediate SACK (RFC 9260 §6.2).
delayed_sack_test() ->
    Tab = ets:new(cap, [ordered_set, public]),
    Filter = fun
        (b, Bin, Now) ->
            {ok, #sctp_packet{chunks = Cs}} = webrtc_sctp_chunk:decode(Bin),
            [ets:insert(Tab, {Now, sack}) || #sctp_sack{} <- Cs],
            keep;
        (_, _, _) ->
            keep
    end,
    N0 = ?NET:set(filter, Filter, ?NET:run(1000, established(#{}, #{}, #{delay => 10}))),
    T0 = ?NET:now(N0),
    N1 = ?NET:run(1000, send(a, 0, <<"one">>, #{}, N0)),
    ?assertEqual([{T0 + 10 + 200, sack}], ets:tab2list(Tab)),
    ets:delete_all_objects(Tab),
    T2 = ?NET:now(N1),
    %% Two packets: the second one is acknowledged at once.
    N2 = send(a, 0, payload(1, 1100), #{}, send(a, 0, payload(2, 1100), #{}, N1)),
    _ = ?NET:run(1000, N2),
    ?assertEqual([{T2 + 10, sack}], ets:tab2list(Tab)),
    ets:delete(Tab).

invalid_stream_test() ->
    N0 = established(#{}, #{inbound_streams => 10}, #{}),
    ?assertEqual({error, invalid_stream}, ?A:send(10, 53, <<"x">>, #{}, 0, ?NET:engine(a, N0))),
    %% next_tsn/2 works on a copy of the network: the message peer_vtag/1
    %% sends takes that TSN, the injected chunk the one after it.
    Tsn = next_tsn(a, N0),
    {V, N} = peer_vtag(N0),
    {_, Out, _} = inject(V, [#sctp_data{tsn = Tsn, sid = 10, data = <<"bad">>}], N),
    %% The TSN is acknowledged and the stream reported (§6.5).
    ?assertMatch([#sctp_sack{cum_tsn = Tsn}, {op_error, [{invalid_stream, 10}]}], Out).

%% Next TSN `Side' would send, learnt by sending one message.
next_tsn(Side, N) ->
    Tab = ets:new(cap, [ordered_set, public]),
    N1 = ?NET:set(filter, capture(Side, Tab), N),
    Other =
        case Side of
            a -> b;
            b -> a
        end,
    Before = length(received(Other, N1)),
    _ = wait_messages(Other, Before + 1, send(Side, 0, <<"tsn">>, #{}, N1)),
    [T] = [
        T
     || {_, Bin} <- ets:tab2list(Tab),
        {ok, #sctp_packet{chunks = Cs}} <- [webrtc_sctp_chunk:decode(Bin)],
        #sctp_data{tsn = T} <- Cs
    ],
    ets:delete(Tab),
    (T + 1) band 16#FFFFFFFF.

idata_without_negotiation_test() ->
    {V, N} = peer_vtag(established(#{}, #{}, #{})),
    {B1, Out, _} = inject(V, [#sctp_data{idata = true, tsn = 1, data = <<"x">>}], N),
    ?assertMatch([{abort, false, [{protocol_violation, _}]}], Out),
    ?assertEqual(closed, ?A:state(B1)).

forward_tsn_with_idata_test() ->
    Opts = #{interleaving => true},
    {V, N} = peer_vtag(established(Opts, Opts, #{})),
    {B1, Out, _} = inject(V, [{forward_tsn, 1, []}], N),
    ?assertMatch([{abort, false, [{protocol_violation, _}]}], Out),
    ?assertEqual(closed, ?A:state(B1)).

stream_reset_interleaving_test() ->
    Opts = #{interleaving => true},
    N0 = established(Opts, Opts, #{}),
    N1 = reset(a, [3], send(a, 3, <<"m0">>, #{ordered => false}, send(a, 3, <<"o0">>, #{}, N0))),
    N2 = send(a, 3, <<"m1">>, #{ordered => false}, send(a, 3, <<"o1">>, #{}, N1)),
    {ok, N3} = ?NET:run_until(fun(X) -> length(received(b, X)) =:= 4 end, ?MINUTE, N2),
    ?assertEqual(
        [
            {message, 3, 53, <<"o0">>},
            {message, 3, 53, <<"m0">>},
            {stream_reset, [3]},
            {message, 3, 53, <<"o1">>},
            {message, 3, 53, <<"m1">>}
        ],
        not_connected_events(b, N3)
    ).

%%====================================================================
%% Incoming reconfiguration requests (RFC 6525 §5.2)
%%====================================================================

%% The first request sequence number of a is its initial TSN.
reconf_pair(OptsB) ->
    Tab = ets:new(cap, [ordered_set, public]),
    N0 = established(#{}, OptsB, #{filter => capture(a, Tab)}),
    [Itsn | _] = [
        T
     || {_, Bin} <- ets:tab2list(Tab),
        {ok, #sctp_packet{chunks = Cs}} <- [webrtc_sctp_chunk:decode(Bin)],
        #sctp_init{tsn = T} <- Cs
    ],
    ets:delete(Tab),
    {V, N} = peer_vtag(N0),
    {V, Itsn, N}.

reconf_out(Out) ->
    [P || {reconfig, Ps} <- Out, P <- Ps].

reconf_requests_test() ->
    {V, Seq, N} = reconf_pair(#{inbound_streams => 100}),
    %% SSN/TSN reset is denied, a retransmission gets the same answer.
    {B1, Out1, _} = inject(V, [{reconfig, [{tsn_reset, Seq}]}], N),
    ?assertEqual([{reconf_response, Seq, denied, undefined}], reconf_out(Out1)),
    {B2, Out2, _} = inject(V, [{reconfig, [{tsn_reset, Seq}]}], ?NET:set_engine(b, B1, N)),
    ?assertEqual([{reconf_response, Seq, denied, undefined}], reconf_out(Out2)),
    N2 = ?NET:set_engine(b, B2, N),
    %% Out of sequence.
    {_, Out3, _} = inject(V, [{reconfig, [{tsn_reset, Seq + 5}]}], N2),
    ?assertEqual(
        [{reconf_response, Seq + 5, error_bad_sequence_number, undefined}], reconf_out(Out3)
    ),
    %% Add Outgoing Streams grows b's incoming streams.
    {B4, Out4, _} = inject(V, [{reconfig, [{add_out_streams, Seq + 1, 10}]}], N2),
    ?assertEqual([{reconf_response, Seq + 1, success_performed, undefined}], reconf_out(Out4)),
    ?assertEqual(110, maps:get(inbound_streams, ?A:info(B4))),
    N4 = ?NET:set_engine(b, B4, N2),
    {B5, Out5, _} = inject(V, [{reconfig, [{add_in_streams, Seq + 2, 10}]}], N4),
    ?assertEqual([{reconf_response, Seq + 2, denied, undefined}], reconf_out(Out5)),
    %% Incoming SSN Reset: b answers with its own outgoing reset.
    N5 = ?NET:set_engine(b, B5, N4),
    {_, Out6, _} = inject(V, [{reconfig, [{in_reset, Seq + 3, [7]}]}], N5),
    Resp = Seq + 3,
    ?assertMatch([{out_reset, _, Resp, _, [7]}], reconf_out(Out6)).

reconf_out_reset_invalid_stream_test() ->
    {V, Seq, N} = reconf_pair(#{inbound_streams => 10}),
    {_, Out, _} = inject(V, [{reconfig, [{out_reset, Seq, 0, 0, [50]}]}], N),
    ?assertEqual([{reconf_response, Seq, denied, undefined}], reconf_out(Out)).

%% A request deferred on a TSN not received yet is answered "In
%% progress"; a second request meanwhile is refused (RFC 6525 §5.1.1).
reconf_deferred_requests_test() ->
    {V, Seq, N} = reconf_pair(#{}),
    Ahead = (next_tsn(a, N) + 100) band 16#FFFFFFFF,
    {B1, Out1, _} = inject(V, [{reconfig, [{out_reset, Seq, 0, Ahead, [1]}]}], N),
    ?assertEqual([{reconf_response, Seq, in_progress, undefined}], reconf_out(Out1)),
    N1 = ?NET:set_engine(b, B1, N),
    {_, Out2, _} = inject(V, [{reconfig, [{out_reset, Seq + 1, 0, Ahead, [2]}]}], N1),
    ?assertEqual(
        [{reconf_response, Seq + 1, error_request_in_progress, undefined}], reconf_out(Out2)
    ),
    {_, Out3, _} = inject(V, [{reconfig, [{out_reset, Seq, 0, Ahead, [1]}]}], N1),
    ?assertEqual([{reconf_response, Seq, in_progress, undefined}], reconf_out(Out3)).
