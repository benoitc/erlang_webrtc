%% @doc In-memory network for deterministic tests of sans-IO engines.
%%
%% Wires two engines `a' and `b' (any module with handle_packet/3,
%% handle_timeout/2 and next_timeout/1 returning `{State, Actions}')
%% through a fake clock and a lossy link with seeded loss, duplication,
%% reordering, delay and an MTU check. `{send, Bin}' actions become
%% packets to the other side; `{event, E}' actions are recorded per side.
-module(webrtc_sctp_net).

-export([
    new/3,
    call/3,
    run/2,
    run_until/3,
    events/2,
    clear_events/2,
    engine/2,
    set_engine/3,
    now/1,
    set/3,
    stat/2,
    messages/2
]).

-record(net, {
    mod :: module(),
    now = 0 :: integer(),
    a :: term(),
    b :: term(),
    q = [] :: [{integer(), non_neg_integer(), a | b, binary()}],
    seq = 0 :: non_neg_integer(),
    rand :: rand:state(),
    loss = 0.0 :: float(),
    dup = 0.0 :: float(),
    reorder = 0.0 :: float(),
    delay = 10 :: non_neg_integer(),
    jitter = 0 :: non_neg_integer(),
    mtu = infinity :: pos_integer() | infinity,
    filter = undefined :: undefined | fun((a | b, binary(), integer()) -> keep | drop | {replace, binary()}),
    ev = #{a => [], b => []} :: #{a | b => [term()]},
    stats = #{} :: #{atom() => non_neg_integer()}
}).

-opaque net() :: #net{}.
-export_type([net/0]).

%% @doc `Opts': seed, loss, dup, reorder (probabilities), delay, jitter
%% (ms), mtu, filter.
-spec new(module(), {term(), term()}, map()) -> net().
new(Mod, {A, B}, Opts) ->
    N = #net{mod = Mod, a = A, b = B, rand = rand:seed_s(exsss, maps:get(seed, Opts, 1))},
    apply_opts(maps:to_list(Opts), N).

apply_opts([], N) -> N;
apply_opts([{K, V} | R], N) -> apply_opts(R, set(K, V, N)).

-spec set(atom(), term(), net()) -> net().
set(seed, _, N) -> N;
set(loss, V, N) -> N#net{loss = float(V)};
set(dup, V, N) -> N#net{dup = float(V)};
set(reorder, V, N) -> N#net{reorder = float(V)};
set(delay, V, N) -> N#net{delay = V};
set(jitter, V, N) -> N#net{jitter = V};
set(mtu, V, N) -> N#net{mtu = V};
set(filter, V, N) -> N#net{filter = V}.

-spec now(net()) -> integer().
now(#net{now = T}) -> T.

-spec engine(a | b, net()) -> term().
engine(a, #net{a = A}) -> A;
engine(b, #net{b = B}) -> B.

-spec set_engine(a | b, term(), net()) -> net().
set_engine(a, E, N) -> N#net{a = E};
set_engine(b, E, N) -> N#net{b = E}.

-spec events(a | b, net()) -> [term()].
events(Side, #net{ev = Ev}) -> lists:reverse(maps:get(Side, Ev)).

-spec clear_events(a | b, net()) -> net().
clear_events(Side, #net{ev = Ev} = N) -> N#net{ev = Ev#{Side := []}}.

%% @doc `{message, Sid, Ppid, Data}' events of one side, in order.
-spec messages(a | b, net()) -> [{non_neg_integer(), non_neg_integer(), binary()}].
messages(Side, N) ->
    [{Sid, P, D} || {message, Sid, P, D} <- events(Side, N)].

-spec stat(atom(), net()) -> non_neg_integer().
stat(K, #net{stats = S}) -> maps:get(K, S, 0).

%% @doc Run `Fun(Engine, Now)' on one side. The function returns
%% `{Engine, Actions}', `{ok, Engine, Actions}' or `{error, Reason}'.
-spec call(a | b, fun((term(), integer()) -> term()), net()) -> net() | {error, term()}.
call(Side, Fun, N) ->
    case Fun(engine(Side, N), N#net.now) of
        {error, _} = E -> E;
        {ok, E1, Acts} -> actions(Side, Acts, set_engine(Side, E1, N));
        {E1, Acts} when is_list(Acts) -> actions(Side, Acts, set_engine(Side, E1, N))
    end.

%% @doc Advance the clock by `Ms', processing everything due.
-spec run(non_neg_integer(), net()) -> net().
run(Ms, N) ->
    End = N#net.now + Ms,
    {_, N1} = until(fun(_) -> false end, End, N),
    N1#net{now = max(N1#net.now, End)}.

%% @doc Run until `Pred(Net)' holds or `MaxMs' of simulated time passed.
-spec run_until(fun((net()) -> boolean()), non_neg_integer(), net()) -> {ok | timeout, net()}.
run_until(Pred, MaxMs, N) ->
    until(Pred, N#net.now + MaxMs, N).

until(Pred, Deadline, N) ->
    case Pred(N) of
        true ->
            {ok, N};
        false ->
            case next_time(N) of
                infinity ->
                    {timeout, N};
                T when T > Deadline ->
                    {timeout, N};
                T ->
                    until(Pred, Deadline, step(N#net{now = max(T, N#net.now)}))
            end
    end.

next_time(#net{mod = M, a = A, b = B, q = Q}) ->
    QT =
        case Q of
            [] -> infinity;
            [{T, _, _, _} | _] -> T
        end,
    lists:min([QT, M:next_timeout(A), M:next_timeout(B)]).

step(#net{now = Now, q = [{T, _, To, Bin} | Rest]} = N) when T =< Now ->
    N1 = bump(delivered, N#net{q = Rest}),
    E = engine(To, N1),
    {E1, Acts} = (N1#net.mod):handle_packet(Bin, Now, E),
    step(actions(To, Acts, set_engine(To, E1, N1)));
step(#net{now = Now, mod = M} = N) ->
    N1 = timeout(a, M, Now, N),
    timeout(b, M, Now, N1).

timeout(Side, M, Now, N) ->
    E = engine(Side, N),
    case M:next_timeout(E) of
        T when is_integer(T), T =< Now ->
            {E1, Acts} = M:handle_timeout(Now, E),
            actions(Side, Acts, set_engine(Side, E1, N));
        _ ->
            N
    end.

actions(_Side, [], N) ->
    N;
actions(Side, [{event, E} | Rest], #net{ev = Ev} = N) ->
    actions(Side, Rest, N#net{ev = Ev#{Side := [E | maps:get(Side, Ev)]}});
actions(Side, [{send, Bin} | Rest], N) ->
    actions(Side, Rest, transmit(Side, Bin, N)).

transmit(From, Bin, #net{mtu = Mtu} = N0) ->
    N = bump(sent, N0),
    N1 =
        case Mtu =/= infinity andalso byte_size(Bin) > Mtu of
            true -> bump(mtu_violations, N);
            false -> N
        end,
    Filtered =
        case N1#net.filter of
            undefined -> keep;
            F -> F(From, Bin, N1#net.now)
        end,
    case Filtered of
        drop ->
            bump(filtered, N1);
        keep ->
            link(From, Bin, N1);
        {replace, Bin1} ->
            link(From, Bin1, N1)
    end.

link(From, Bin, N) ->
    {Lost, N1} = chance(N#net.loss, N),
    case Lost of
        true ->
            bump(lost, N1);
        false ->
            {Dup, N2} = chance(N1#net.dup, N1),
            N3 = enqueue(From, Bin, N2),
            case Dup of
                true -> bump(duplicated, enqueue(From, Bin, N3));
                false -> N3
            end
    end.

enqueue(From, Bin, #net{now = Now, delay = D, jitter = J} = N) ->
    {Jit, N1} = uniform(J, N),
    {Re, N2} = chance(N1#net.reorder, N1),
    {Extra, N3} =
        case Re of
            true -> uniform(2 * D + 20, N2);
            false -> {0, N2}
        end,
    To =
        case From of
            a -> b;
            b -> a
        end,
    At = Now + D + Jit + Extra,
    Seq = N3#net.seq,
    Q = lists:merge([{At, Seq, To, Bin}], N3#net.q),
    N3#net{q = Q, seq = Seq + 1}.

chance(P, N) when P =< 0.0 -> {false, N};
chance(P, #net{rand = R} = N) ->
    {X, R1} = rand:uniform_s(R),
    {X < P, N#net{rand = R1}}.

uniform(0, N) -> {0, N};
uniform(Max, #net{rand = R} = N) ->
    {X, R1} = rand:uniform_s(Max + 1, R),
    {X - 1, N#net{rand = R1}}.

bump(K, #net{stats = S} = N) ->
    N#net{stats = maps:update_with(K, fun(V) -> V + 1 end, 1, S)}.
