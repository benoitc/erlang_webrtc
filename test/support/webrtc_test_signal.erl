%% @doc Test helper: in-process signaling between Erlang peer
%% connections owned by the calling process.
-module(webrtc_test_signal).

-export([negotiate/2, connect/2, connect/3, wait/3, wait_connected/2, wait_pairs_connected/2, flush/0]).

%% @doc Offer from A, answer from B, without waiting for connectivity.
negotiate(A, B) ->
    {ok, Offer} = webrtc:create_offer(A, #{}),
    ok = webrtc:set_local_description(A, offer, Offer),
    ok = webrtc:set_remote_description(B, offer, Offer),
    {ok, Answer} = webrtc:create_answer(B, #{}),
    ok = webrtc:set_local_description(B, answer, Answer),
    ok = webrtc:set_remote_description(A, answer, Answer),
    {Offer, Answer}.

%% @doc Negotiate, trickle candidates both ways and wait until both
%% peers report `connected'.
connect(A, B) ->
    connect(A, B, 10000).

connect(A, B, Timeout) ->
    {Offer, Answer} = negotiate(A, B),
    ok = wait_connected([A, B], Timeout),
    {Offer, Answer}.

%% @doc Relay candidates between the peers of a single connection until
%% both are connected. Other events stay in the mailbox.
wait_connected([A, B], Timeout) ->
    wait_pairs_connected([{A, B}], Timeout).

%% @doc Same for several independent connections: candidates of a peer
%% only go to its partner.
wait_pairs_connected(Pairs, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    Peer = maps:from_list(lists:append([[{A, B}, {B, A}] || {A, B} <- Pairs])),
    relay(Peer, maps:keys(Peer), [], Deadline).

relay(Peer, Pcs, Done, Deadline) ->
    case lists:sort(Pcs) =:= lists:sort(Done) of
        true ->
            ok;
        false ->
            Left = max(0, Deadline - erlang:monotonic_time(millisecond)),
            receive
                {webrtc, P, {ice_candidate, C, Mid}} when is_map_key(P, Peer) ->
                    ok = webrtc:add_ice_candidate(maps:get(P, Peer), C, Mid),
                    relay(Peer, Pcs, Done, Deadline);
                {webrtc, P, {connection_state, connected}} when is_map_key(P, Peer) ->
                    relay(Peer, Pcs, [P | Done], Deadline);
                {webrtc, P, {connection_state, failed}} when is_map_key(P, Peer) ->
                    {error, {failed, P}}
            after Left ->
                {error, timeout}
            end
    end.

%% @doc Wait for an event of Pc matching Pred.
wait(Pc, Pred, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    wait_loop(Pc, Pred, Deadline, []).

wait_loop(Pc, Pred, Deadline, Skipped) ->
    Left = max(0, Deadline - erlang:monotonic_time(millisecond)),
    receive
        {webrtc, Pc, E} = Msg ->
            case Pred(E) of
                true ->
                    requeue(Skipped),
                    {ok, E};
                false ->
                    wait_loop(Pc, Pred, Deadline, [Msg | Skipped])
            end
    after Left ->
        requeue(Skipped),
        {error, timeout}
    end.

%% Put back skipped messages, in order, at the end of the mailbox.
requeue(Skipped) ->
    [self() ! M || M <- lists:reverse(Skipped)],
    ok.

flush() ->
    receive
        {webrtc, _, _} -> flush()
    after 0 -> ok
    end.
