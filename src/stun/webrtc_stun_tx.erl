%% @doc Sans-IO STUN client transaction table for UDP (RFC 8489 §6.2.1).
%%
%% The table tracks outstanding requests by transaction ID, decides
%% when a request must be retransmitted and when a transaction has
%% failed. It never sends anything itself: every call returns the
%% actions the owner must execute.
%%
%% Retransmission follows RFC 8489 §6.2.1: the first retransmission is
%% sent RTO after the request, the interval doubles after each
%% retransmission, at most `Rc' requests are sent (default 7) and the
%% transaction fails `Rm' times the initial RTO after the last request
%% (default 16). With RTO = 500 ms requests leave at 0, 500, 1500, 3500,
%% 7500, 15500 and 31500 ms and the transaction fails at 39500 ms.
%%
%% The RTO of a transaction is, in order of preference: the `rto' option
%% of `send/6' (ICE computes a per-check RTO, RFC 8445 §14.3), the value
%% cached for the transaction `key' (normally the server IP address,
%% computed from RTT samples as in RFC 6298 with Karn's algorithm and
%% discarded after 10 minutes without transactions), then the table
%% default.
%%
%% Actions:
%% <ul>
%% <li>`{send, Dest, Bin}': transmit `Bin' to `Dest' (opaque term given
%%     to `send/6').</li>
%% <li>`{timeout, TxId, Dest, Meta}': the transaction failed.</li>
%% </ul>
%%
%% A transaction can be cancelled (RFC 8445 §7.2.5.3 and §8.1.2): it is
%% no longer retransmitted and its timeout is not reported, but a
%% response arriving before the original deadline is still matched.
-module(webrtc_stun_tx).

-export([
    new/0,
    new/1,
    send/6,
    lookup/2,
    response/3,
    cancel/2,
    remove/2,
    handle_timeout/2,
    next_timeout/1,
    rto/3,
    size/1,
    ids/1
]).

-export_type([table/0, action/0, txid/0, send_opts/0]).

-type txid() :: <<_:96>>.
-type action() ::
    {send, Dest :: term(), binary()}
    | {timeout, txid(), Dest :: term(), Meta :: term()}.
-type send_opts() :: #{
    rto => pos_integer(),
    rc => pos_integer(),
    rm => pos_integer(),
    key => term(),
    meta => term()
}.

-record(tx, {
    dest :: term(),
    bin :: binary(),
    meta :: term(),
    key :: term(),
    rto0 :: pos_integer(),
    interval :: pos_integer(),
    sent = 1 :: pos_integer(),
    rc :: pos_integer(),
    rm :: pos_integer(),
    start :: integer(),
    last :: integer(),
    next :: integer(),
    deadline :: integer(),
    cancelled = false :: boolean()
}).

-record(rtt, {srtt :: number(), rttvar :: number(), rto :: pos_integer(), used :: integer()}).

-record(table, {
    txs = #{} :: #{txid() => #tx{}},
    rto = 500 :: pos_integer(),
    min_rto = 500 :: pos_integer(),
    max_rto = infinity :: pos_integer() | infinity,
    rc = 7 :: pos_integer(),
    rm = 16 :: pos_integer(),
    cache = #{} :: #{term() => #rtt{}},
    cache_ttl = 600000 :: non_neg_integer()
}).

-opaque table() :: #table{}.

%% Clock granularity used in the RFC 6298 RTO formula.
-define(G, 1).

-spec new() -> table().
new() ->
    new(#{}).

%% @doc Create a table. Options: `rto' (initial RTO, ms, default 500),
%% `min_rto' (floor for computed RTOs, default 500), `max_rto' (cap on
%% the doubled interval, default `infinity'), `rc' (default 7), `rm'
%% (default 16), `cache_ttl' (RTO cache lifetime, default 600000).
-spec new(map()) -> table().
new(Opts) ->
    #table{
        rto = maps:get(rto, Opts, 500),
        min_rto = maps:get(min_rto, Opts, 500),
        max_rto = maps:get(max_rto, Opts, infinity),
        rc = maps:get(rc, Opts, 7),
        rm = maps:get(rm, Opts, 16),
        cache_ttl = maps:get(cache_ttl, Opts, 600000)
    }.

%% @doc Start a transaction and return the first transmission.
-spec send(txid(), term(), binary(), send_opts(), integer(), table()) ->
    {table(), [action()]}.
send(TxId, Dest, Bin, Opts, Now, #table{txs = Txs} = T) ->
    Key = maps:get(key, Opts, undefined),
    Rto = case maps:find(rto, Opts) of
        {ok, R} -> R;
        error -> rto(Key, Now, T)
    end,
    Rc = maps:get(rc, Opts, T#table.rc),
    Rm = maps:get(rm, Opts, T#table.rm),
    Tx = #tx{
        dest = Dest,
        bin = Bin,
        meta = maps:get(meta, Opts, undefined),
        key = Key,
        rto0 = Rto,
        interval = Rto,
        rc = Rc,
        rm = Rm,
        start = Now,
        last = Now,
        next = first_next(Now, Rto, Rc, Rm),
        deadline = Now + total_duration(Rto, Rc, Rm, T#table.max_rto)
    },
    {T#table{txs = Txs#{TxId => Tx}, cache = touch(Key, Now, T#table.cache)}, [{send, Dest, Bin}]}.

first_next(Now, Rto, 1, Rm) -> Now + Rm * Rto;
first_next(Now, Rto, _Rc, _Rm) -> Now + Rto.

total_duration(Rto, Rc, Rm, Max) ->
    Intervals = lists:foldl(
        fun(_, {Sum, I}) -> {Sum + I, cap(2 * I, Max)} end,
        {0, Rto},
        lists:seq(1, Rc - 1)
    ),
    element(1, Intervals) + Rm * Rto.

cap(V, infinity) -> V;
cap(V, Max) -> min(V, Max).

%% @doc Return the destination and metadata of an outstanding
%% transaction without consuming it.
-spec lookup(txid(), table()) -> {ok, Dest :: term(), Meta :: term()} | error.
lookup(TxId, #table{txs = Txs}) ->
    case maps:find(TxId, Txs) of
        {ok, #tx{dest = D, meta = M}} -> {ok, D, M};
        error -> error
    end.

%% @doc Complete a transaction on receipt of a (validated) response.
%% `rtt' is only reported when the request was never retransmitted
%% (Karn's algorithm); it then also updates the RTO cache for `key'.
-spec response(txid(), integer(), table()) ->
    {ok, #{dest := term(), meta := term(), rtt := non_neg_integer() | undefined}, table()}
    | error.
response(TxId, Now, #table{txs = Txs} = T) ->
    case maps:take(TxId, Txs) of
        {#tx{sent = Sent, start = Start, dest = D, meta = M, key = K}, Txs2} ->
            Rtt = case Sent of
                1 -> max(0, Now - Start);
                _ -> undefined
            end,
            T2 = T#table{txs = Txs2, cache = sample(K, Rtt, Now, T)},
            {ok, #{dest => D, meta => M, rtt => Rtt}, T2};
        error ->
            error
    end.

%% @doc Stop retransmitting `TxId'. A response is still matched until
%% the original transaction deadline; no timeout is reported.
-spec cancel(txid(), table()) -> table().
cancel(TxId, #table{txs = Txs} = T) ->
    case maps:find(TxId, Txs) of
        {ok, Tx} ->
            T#table{txs = Txs#{TxId => Tx#tx{cancelled = true, next = Tx#tx.deadline}}};
        error ->
            T
    end.

%% @doc Forget a transaction immediately.
-spec remove(txid(), table()) -> table().
remove(TxId, #table{txs = Txs} = T) ->
    T#table{txs = maps:remove(TxId, Txs)}.

-spec handle_timeout(integer(), table()) -> {table(), [action()]}.
handle_timeout(Now, #table{txs = Txs} = T) ->
    Due = lists:sort([{Next, Id} || Id := #tx{next = Next} <- Txs, Next =< Now]),
    {Txs2, Acts} = lists:foldl(
        fun({_, Id}, {Acc, A}) -> fire(Id, maps:get(Id, Acc), Now, Acc, A, T) end,
        {Txs, []},
        Due
    ),
    {T#table{txs = Txs2}, lists:reverse(Acts)}.

fire(Id, #tx{cancelled = true}, _Now, Txs, Acts, _T) ->
    {maps:remove(Id, Txs), Acts};
fire(Id, #tx{sent = Sent, rc = Rc, dest = D, meta = M}, _Now, Txs, Acts, _T) when Sent >= Rc ->
    {maps:remove(Id, Txs), [{timeout, Id, D, M} | Acts]};
fire(Id, #tx{} = Tx, Now, Txs, Acts, T) ->
    Sent = Tx#tx.sent + 1,
    Interval =
        case Sent of
            2 -> Tx#tx.interval;
            _ -> cap(2 * Tx#tx.interval, T#table.max_rto)
        end,
    NextInterval = cap(2 * Interval, T#table.max_rto),
    Next =
        case Sent >= Tx#tx.rc of
            true -> Now + Tx#tx.rm * Tx#tx.rto0;
            false -> Now + NextInterval
        end,
    Tx2 = Tx#tx{sent = Sent, interval = Interval, last = Now, next = Next},
    {Txs#{Id => Tx2}, [{send, Tx#tx.dest, Tx#tx.bin} | Acts]}.

-spec next_timeout(table()) -> integer() | infinity.
next_timeout(#table{txs = Txs}) ->
    maps:fold(fun(_, #tx{next = N}, Acc) -> min(N, Acc) end, infinity, Txs).

%% @doc RTO to use for a new transaction towards `Key': the cached value
%% when fresh, otherwise the table default.
-spec rto(term(), integer(), table()) -> pos_integer().
rto(undefined, _Now, #table{rto = R}) ->
    R;
rto(Key, Now, #table{rto = R, cache = C, cache_ttl = Ttl}) ->
    case maps:find(Key, C) of
        {ok, #rtt{rto = Cached, used = U}} when Now - U =< Ttl -> Cached;
        _ -> R
    end.

-spec size(table()) -> non_neg_integer().
size(#table{txs = Txs}) ->
    map_size(Txs).

-spec ids(table()) -> [txid()].
ids(#table{txs = Txs}) ->
    maps:keys(Txs).

%%--------------------------------------------------------------------
%% RTO estimation (RFC 6298)
%%--------------------------------------------------------------------

touch(undefined, _Now, C) ->
    C;
touch(Key, Now, C) ->
    case maps:find(Key, C) of
        {ok, E} -> C#{Key => E#rtt{used = Now}};
        error -> C
    end.

sample(undefined, _Rtt, _Now, #table{cache = C}) ->
    C;
sample(_Key, undefined, _Now, #table{cache = C}) ->
    C;
sample(Key, R, Now, #table{cache = C, min_rto = Min, max_rto = Max, cache_ttl = Ttl}) ->
    {Srtt, Var} =
        case maps:find(Key, C) of
            {ok, #rtt{srtt = S0, rttvar = V0, used = U}} when Now - U =< Ttl ->
                V1 = 0.75 * V0 + 0.25 * abs(S0 - R),
                {0.875 * S0 + 0.125 * R, V1};
            _ ->
                {R, R / 2}
        end,
    Rto = cap(max(Min, round(Srtt + max(?G, 4 * Var))), Max),
    C#{Key => #rtt{srtt = Srtt, rttvar = Var, rto = Rto, used = Now}}.
