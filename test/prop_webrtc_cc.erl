%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% PropEr properties for congestion control: the pacer never sends
%% more than its budget plus the burst allowance and never loses or
%% duplicates a packet; transport-wide feedback reports every packet
%% exactly as it arrived, through the real RTCP codec.
-module(prop_webrtc_cc).
-include_lib("proper/include/proper.hrl").
-include("webrtc_rtp_rtcp.hrl").

-export([prop_pacer_conservation/0, prop_pacer_accounting/0, prop_twcc_feedback_roundtrip/0]).

%%====================================================================
%% Pacer
%%====================================================================

op() ->
    frequency([
        {3, {enqueue, oneof([audio, rtx, video]), integer(1, 1500), integer(0, 5)}},
        {1, {tick, integer(0, 50)}}
    ]).

pacer_case() ->
    {integer(8000, 20000000), integer(1, 40), integer(1, 64), list(op())}.

%% Run the operations; returns the sends [{Time, Packet}], the packets
%% enqueued and the final pacer.
drive(Rate, Burst, Max, Ops) ->
    P0 = webrtc_pacer:new(#{rate => Rate, burst_ms => Burst, max_packets => Max}),
    {_, _, Sent, In, P} = lists:foldl(
        fun
            ({enqueue, C, Size, Dt}, {T, N, S, I, Px}) ->
                Pkt = {C, Size, N},
                {Out, P1} = webrtc_pacer:enqueue(Pkt, T + Dt, Px),
                {T + Dt, N + 1, S ++ [{T + Dt, X} || X <- Out], [Pkt | I], P1};
            ({tick, Dt}, {T, N, S, I, Px}) ->
                {Out, P1} = webrtc_pacer:handle_timeout(T + Dt, Px),
                {T + Dt, N, S ++ [{T + Dt, X} || X <- Out], I, P1}
        end,
        {0, 0, [], [], P0},
        Ops
    ),
    {Sent, lists:reverse(In), P}.

%% Over any interval [T1, T2] between two sends, the bytes sent are at
%% most rate x (T2 - T1) plus the burst cap plus one packet.
prop_pacer_conservation() ->
    ?FORALL(
        {Rate, Burst, Max, Ops},
        pacer_case(),
        begin
            {Sent, _, _} = drive(Rate, Burst, Max, Ops),
            Cap = max(Rate * Burst, 1500 * 8000),
            Times = lists:usort([T || {T, _} <- Sent]),
            lists:all(
                fun({T1, T2}) ->
                    Bits = lists:sum([Sz * 8000 || {T, {_, Sz, _}} <- Sent, T >= T1, T =< T2]),
                    Bits =< Rate * (T2 - T1) + Cap + 1500 * 8000
                end,
                [{A, B} || A <- Times, B <- Times, A =< B]
            )
        end
    ).

%% Every packet is sent at most once, sent + dropped + queued equals
%% what was enqueued, and each class keeps its order.
prop_pacer_accounting() ->
    ?FORALL(
        {Rate, Burst, Max, Ops},
        pacer_case(),
        begin
            {Sent, In, P} = drive(Rate, Burst, Max, Ops),
            Ids = [N || {_, {_, _, N}} <- Sent],
            #{dropped := D, queued := Q, sent := S} = webrtc_pacer:stats(P),
            Dropped = lists:sum(maps:values(D)),
            {Flushed, _} = webrtc_pacer:flush(P),
            InOrder = lists:all(
                fun(C) ->
                    Seq = [N || {_, {C1, _, N}} <- Sent, C1 =:= C] ++ [N || {C1, _, N} <- Flushed, C1 =:= C],
                    Seq =:= lists:sort(Seq)
                end,
                [audio, rtx, video]
            ),
            length(Ids) =:= length(lists:usort(Ids)) andalso
                S =:= length(Sent) andalso
                S + Dropped + Q =:= length(In) andalso
                Q =:= length(Flushed) andalso
                Q =< Max andalso
                InOrder
        end
    ).

%%====================================================================
%% Transport-wide feedback
%%====================================================================

%% Packets sent 0..N-1 (starting at a random sequence number so wrap
%% around is exercised), each lost or delivered with a delay; the
%% receiver gives feedback every 100 ms and once at the end.
twcc_case() ->
    {integer(0, 65535), list({integer(0, 5), oneof([lost, integer(10, 200)])})}.

prop_twcc_feedback_roundtrip() ->
    ?FORALL(
        {First, Plan},
        twcc_case(),
        begin
            Tx0 = webrtc_twcc_sender:new(#{initial_seq => First}),
            %% The size identifies the packet.
            {Sends, Tx, _} = lists:foldl(
                fun({{Gap, Fate}, I}, {Acc, T0, Now}) ->
                    Seq = webrtc_twcc_sender:next_seq(T0),
                    T1 = webrtc_twcc_sender:sent(I, Now + Gap, T0),
                    {[{Seq, Now + Gap, Fate, I} | Acc], T1, Now + Gap}
                end,
                {[], Tx0, 1000},
                lists:zip(Plan, lists:seq(1, length(Plan)))
            ),
            Arrivals = lists:keysort(2, [{Seq, At + D} || {Seq, At, D, _} <- Sends, D =/= lost]),
            Rx = feed(Arrivals, webrtc_twcc_receiver:new(#{sender_ssrc => 1}), []),
            {Results, _} = lists:foldl(
                fun(Fb, {Acc, T}) ->
                    {R, T1} = webrtc_twcc_sender:feedback(Fb, 0, T),
                    {Acc ++ R, T1}
                end,
                {[], Tx},
                Rx
            ),
            check_results(lists:reverse(Sends), Results)
        end
    ).

%% Deliver arrivals in time order, collecting feedback through the codec.
feed([], Rx, Acc) ->
    {Fb, _} = webrtc_twcc_receiver:flush(0, Rx),
    lists:reverse(Acc) ++ wire(Fb);
feed([{Seq, At} | Rest], Rx0, Acc) ->
    {Fb, Rx1} = webrtc_twcc_receiver:handle_timeout(At, Rx0),
    Rx2 = webrtc_twcc_receiver:packet(Seq, 42, At, Rx1),
    feed(Rest, Rx2, lists:reverse(wire(Fb)) ++ Acc).

wire(Fbs) ->
    [P || Fb <- Fbs, {ok, [P]} <- [webrtc_rtcp:decode(webrtc_rtcp:encode([Fb]))]].

%% Every delivered packet is reported received once, with its send time
%% and size, and with arrival times whose differences are exact. A
%% packet reported lost and never received was lost; lost packets
%% between the first and last delivered ones are reported lost.
check_results(Sends, Results) ->
    Received = [R || {_, A, _} = R <- Results, A =/= lost],
    Delivered = [{At * 1000, (At + D) * 1000, I} || {_, At, D, I} <- Sends, D =/= lost],
    Norm = fun
        ([]) -> [];
        (L) ->
            Min = lists:min([A || {_, A, _} <- L]),
            lists:sort([{S, A - Min, Z} || {S, A, Z} <- L])
    end,
    Same = Norm(Received) =:= Norm(Delivered),
    Lost = [I || {_, _, lost, I} <- Sends],
    ReceivedIds = [I || {_, _, I} <- Received],
    FinalLost = [I || {_, lost, I} <- Results, not lists:member(I, ReceivedIds)],
    Inner =
        case Delivered of
            [] -> [];
            _ ->
                Lo = lists:min([I || {_, _, I} <- Delivered]),
                Hi = lists:max([I || {_, _, I} <- Delivered]),
                [I || I <- Lost, I > Lo, I < Hi]
        end,
    Same andalso
        length(Received) =:= length(Delivered) andalso
        lists:all(fun(I) -> lists:member(I, FinalLost) end, Inner) andalso
        lists:all(fun(I) -> lists:member(I, Lost) end, FinalLost).
