%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Throughput of two SCTP associations wired back to back with no
%% loss and a 1 ms link. Measures the CPU cost of the engine, not a
%% network.
%%
%% Run from the project root after `rebar3 compile':
%%
%%   erlc -o /tmp -I include bench/webrtc_sctp_bench.erl
%%   erl -noshell -pa _build/default/lib/webrtc/ebin -pa /tmp \
%%       -eval 'webrtc_sctp_bench:run(), halt().'
-module(webrtc_sctp_bench).

-export([run/0, run/3]).

-define(S, webrtc_sctp_assoc).

-spec run() -> ok.
run() ->
    run(64 * 1024 * 1024, 16 * 1024, false),
    run(64 * 1024 * 1024, 16 * 1024, true),
    run(16 * 1024 * 1024, 1000, false).

%% @doc Send `Total' bytes in messages of `Size' bytes from a to b.
-spec run(pos_integer(), pos_integer(), boolean()) -> ok.
run(Total, Size, IData) ->
    Opts = #{heartbeat_interval => infinity, interleaving => IData, send_buffer => 64 * 1024 * 1024},
    A0 = ?S:new(Opts#{random_seed => 1}),
    B0 = ?S:new(Opts#{random_seed => 2}),
    {A1, ToB} = ?S:connect(0, A0),
    {A2, B1, T1} = pump(A1, B0, sends(ToB), [], 0, fun(_) -> false end),
    Msg = binary:copy(<<"x">>, Size),
    Count = Total div Size,
    Start = erlang:monotonic_time(microsecond),
    {A3, B2, _T2, Got} = feed(A2, B1, T1, Msg, Count, 0),
    Us = erlang:monotonic_time(microsecond) - Start,
    _ = {A3, B2},
    MBps = Got * Size / Us,
    io:format(
        "~p messages of ~p bytes, interleaving ~p: ~.1f MB/s (~p ms)~n",
        [Got, Size, IData, MBps, Us div 1000]
    ).

%% Keep the send queue topped up and the link drained.
feed(A, B, T, _Msg, 0, Got) ->
    {A, B, T, Got};
feed(A, B, T, Msg, Left, Got) ->
    {A1, Acts, Sent} = fill(A, T, Msg, min(Left, 256), 0, []),
    {A2, B1, T1, N} = drain(A1, B, sends(Acts), T),
    feed(A2, B1, T1, Msg, Left - Sent, Got + N).

fill(A, _T, _Msg, 0, Sent, Acts) ->
    {A, lists:append(lists:reverse(Acts)), Sent};
fill(A, T, Msg, K, Sent, Acts) ->
    case ?S:send(0, 53, Msg, #{}, T, A) of
        {ok, A1, Out} -> fill(A1, T, Msg, K - 1, Sent + 1, [Out | Acts]);
        {error, buffer_full} -> {A, lists:append(lists:reverse(Acts)), Sent}
    end.

drain(A, B, ToB, T) ->
    Self = self(),
    Count = fun(Acts) -> Self ! {got, length([x || {event, {message, _, _, _}} <- Acts])} end,
    {A1, B1, T1} = pump(A, B, ToB, [], T, Count),
    {A1, B1, T1, collect(0)}.

collect(N) ->
    receive
        {got, K} -> collect(N + K)
    after 0 -> N
    end.

%% Exchange packets until both sides are quiet, 1 ms per hop.
pump(A, B, [], [], T, Seen) ->
    case min(?S:next_timeout(A), ?S:next_timeout(B)) of
        infinity ->
            {A, B, T};
        Next when Next - T > 1000 ->
            {A, B, T};
        Next ->
            {A1, ActsA} = ?S:handle_timeout(Next, A),
            {B1, ActsB} = ?S:handle_timeout(Next, B),
            case {sends(ActsA), sends(ActsB)} of
                {[], []} -> {A1, B1, Next};
                {ToB, ToA} -> pump(A1, B1, ToB, ToA, Next, Seen)
            end
    end;
pump(A, B, ToB, ToA, T0, Seen) ->
    T = T0 + 1,
    {B1, OutB} = lists:foldl(
        fun(Bin, {E, Acc}) ->
            {E1, Acts} = ?S:handle_packet(Bin, T, E),
            _ = is_function(Seen) andalso Seen(Acts),
            {E1, Acc ++ sends(Acts)}
        end,
        {B, []},
        ToB
    ),
    {A1, OutA} = lists:foldl(
        fun(Bin, {E, Acc}) ->
            {E1, Acts} = ?S:handle_packet(Bin, T, E),
            {E1, Acc ++ sends(Acts)}
        end,
        {A, []},
        ToA
    ),
    pump(A1, B1, OutA, OutB, T, Seen).

sends(Acts) -> [Bin || {send, Bin} <- Acts].
