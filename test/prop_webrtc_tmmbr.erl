%% PropEr properties for the TMMBR bounding set (RFC 5104 §3.5.4.2) and
%% the rate limiter that follows it, checked against the definitions
%% rather than the algorithm: the bounding set gives the same lower
%% envelope as all the tuples, every member of it is needed, and the
%% limiter never releases more than its rate allows.
-module(prop_webrtc_tmmbr).
-include_lib("proper/include/proper.hrl").

-export([prop_bounding_set_envelope/0, prop_bounding_set_minimal/0, prop_rate_limit_bound/0]).

tuples() ->
    ?LET(L, non_empty(list({integer(0, 2000000), integer(0, 511)})),
         [{N, B, O} || {N, {B, O}} <- lists:zip(lists:seq(1, length(L)), L)]).

%% The envelope max(0, min(B - 8 O x)) at the rational x = P / Q,
%% scaled by Q: exact.
env(Tuples, {P, Q}) ->
    max(0, lists:min([B * Q - 8 * O * P || {_, B, O} <- Tuples])).

%% Both envelopes are piecewise linear with breakpoints among the
%% pairwise intersections and the zero crossings of the lines: equal at
%% those points, between consecutive ones and past the last, they are
%% equal on every packet rate >= 0.
points(Tuples) ->
    Breaks = lists:usort(
        [{0, 1}] ++
        [norm({B2 - B1, 8 * (O2 - O1)}) || {_, B1, O1} <- Tuples, {_, B2, O2} <- Tuples, O2 > O1, B2 >= B1] ++
        [norm({B, 8 * O}) || {_, B, O} <- Tuples, O > 0]
    ),
    Sorted = lists:sort(fun le/2, Breaks),
    Mids = [mid(X, Y) || {X, Y} <- lists:zip(lists:droplast(Sorted), tl(Sorted))],
    {Lp, Lq} = lists:last(Sorted),
    Sorted ++ Mids ++ [{Lp + Lq, Lq}].

norm({P, Q}) -> G = gcd(P, Q), {P div G, Q div G}.
gcd(A, 0) -> abs(A);
gcd(A, B) -> gcd(B, A rem B).
le({A, B}, {C, D}) -> A * D =< C * B.
mid({A, B}, {C, D}) -> norm({A * D + C * B, 2 * B * D}).

prop_bounding_set_envelope() ->
    ?FORALL(Ts, tuples(),
        begin
            Set = webrtc_tmmbr:bounding_set(Ts),
            lists:all(fun(X) -> env(Set, X) =:= env(Ts, X) end, points(Ts))
        end).

%% Dropping any member of the bounding set raises the envelope somewhere.
prop_bounding_set_minimal() ->
    ?FORALL(Ts, tuples(),
        begin
            Set = webrtc_tmmbr:bounding_set(Ts),
            Pts = points(Ts),
            lists:all(fun(T) ->
                          Rest = Set -- [T],
                          Rest =:= [] orelse lists:any(fun(X) -> env(Rest, X) =/= env(Set, X) end, Pts)
                      end, Set)
        end).

op() ->
    frequency([
        {4, {enqueue, integer(8, 12000), integer(0, 30)}},
        {1, {charge, integer(8, 12000), integer(0, 30)}},
        {1, {tick, integer(0, 200)}}
    ]).

%% Bits released up to any time T <= rate x T + cap + one item, with
%% charges taken from the budget as well.
prop_rate_limit_bound() ->
    ?FORALL({Rate, Burst, Ops}, {integer(8000, 5000000), integer(1, 100), list(op())},
        begin
            L0 = webrtc_rate_limit:new(#{rate => Rate, burst_ms => Burst, max_items => 1000}),
            {_, Out, _} = lists:foldl(
                fun({enqueue, Bits, Dt}, {T, Acc, L}) ->
                        {R, L1} = webrtc_rate_limit:enqueue(Bits, Bits, T + Dt, L),
                        {T + Dt, Acc ++ [{T + Dt, B} || B <- R], L1};
                   ({charge, Bits, Dt}, {T, Acc, L}) ->
                        %% Sent anyway; it only makes the queue wait longer.
                        {T + Dt, Acc, webrtc_rate_limit:charge(Bits, T + Dt, L)};
                   ({tick, Dt}, {T, Acc, L}) ->
                        {R, L1} = webrtc_rate_limit:handle_timeout(T + Dt, L),
                        {T + Dt, Acc ++ [{T + Dt, B} || B <- R], L1}
                end,
                {0, [], L0},
                Ops
            ),
            Cap = max(Rate * Burst, 12000 * 1000),
            {Ok, _} = lists:foldl(
                fun({T, B}, {Ok0, Sum}) ->
                    Sum1 = Sum + B,
                    {Ok0 andalso Sum1 * 1000 =< Rate * T + Cap + 12000 * 1000, Sum1}
                end,
                {true, 0},
                Out
            ),
            Ok
        end).
