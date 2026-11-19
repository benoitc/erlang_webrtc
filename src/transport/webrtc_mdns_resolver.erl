%% @doc Sans-IO one-shot multicast DNS resolver (RFC 6762 §5.1) for the
%% A and AAAA records of `.local' host names, with a small TTL cache.
%%
%% The owner (`webrtc_mdns') sends the queries, feeds the responses it
%% receives and arms one timer:
%%
%% ```
%% R0 = webrtc_mdns_resolver:new(#{}),
%% {R1, [{send, QueryA}, {send, QueryAAAA}]} = webrtc_mdns_resolver:resolve(<<"x.local">>, Now, R0),
%% {R2, [{result, <<"x.local">>, {ok, [IP]}}]} =
%%     webrtc_mdns_resolver:handle_packet(unicast, Response, Now, R1).
%% '''
%%
%% Queries go out from an ephemeral port (one-shot querier, §5.1), one
%% message for A and one for AAAA (Chromium's responder ignores
%% messages with more than one question). The first query sets the QU bit
%% (§5.4); retransmissions clear it, as §5.4 recommends, which also gets
%% an answer from responders that ignore QU questions (Chromium answers
%% QM questions only, by multicast). After the last attempt the query
%% fails with `{error, timeout}'.
%%
%% Responses are validated before use:
%% <ul>
%% <li>QR set, opcode 0 and rcode 0 (RFC 6762 §18.3, §18.11).</li>
%% <li>Unicast responses (`unicast') are legacy unicast replies to our
%%     ephemeral port (§6.7): the ID must be the query ID and the question
%%     must be repeated.</li>
%% <li>Multicast responses (`multicast') carry ID 0 which is ignored
%%     (§18.1).</li>
%% <li>Only class IN A or AAAA records whose name is a pending question
%%     are used, from the answer and additional sections (§6.2).
%%     Responses that answer nothing pending are unsolicited and ignored,
%%     and never fill the cache.</li>
%% </ul>
%%
%% The cache keeps at most `max_cache' names for their TTL, capped at
%% `max_ttl' seconds. Records with TTL 0 (goodbye, §10.1) are not used.
-module(webrtc_mdns_resolver).

-export([new/1, resolve/3, handle_packet/4, handle_timeout/2, next_timeout/1, pending/1, cached/3]).

-export_type([resolver/0, action/0, result/0]).

-type result() :: {ok, [inet:ip_address(), ...]} | {error, timeout | bad_name | too_many_queries}.
-type action() :: {send, binary()} | {result, binary(), result()}.

-record(q, {
    id :: 0..65535,
    attempt = 1 :: pos_integer(),
    deadline :: integer()
}).

-record(r, {
    %% Delays in milliseconds after each attempt; the query fails when
    %% the last one expires. Its length is the number of attempts.
    schedule :: [pos_integer(), ...],
    max_queries :: pos_integer(),
    max_cache :: pos_integer(),
    max_ttl :: pos_integer(),
    queries = #{} :: #{binary() => #q{}},
    %% Name => {Expiry, [IP]}.
    cache = #{} :: #{binary() => {integer(), [inet:ip_address()]}},
    ids :: fun(() -> 0..65535)
}).

-opaque resolver() :: #r{}.

%% @doc Options: `schedule' (default `[250, 1000, 2000]': attempts at
%% 0, 250 ms and 1250 ms, failure at 3250 ms; the first retransmission
%% is the first QM query, so it is kept short), `max_queries' (32),
%% `max_cache' (64), `max_ttl' (seconds, 3600) and `ids', a fun that
%% returns query IDs (random by default).
-spec new(map()) -> resolver().
new(Opts) ->
    Schedule = maps:get(schedule, Opts, [250, 1000, 2000]),
    true = Schedule =/= [] andalso lists:all(fun(D) -> is_integer(D) andalso D > 0 end, Schedule),
    #r{
        schedule = Schedule,
        max_queries = maps:get(max_queries, Opts, 32),
        max_cache = maps:get(max_cache, Opts, 64),
        max_ttl = maps:get(max_ttl, Opts, 3600),
        ids = maps:get(ids, Opts, fun random_id/0)
    }.

random_id() ->
    <<Id:16>> = crypto:strong_rand_bytes(2),
    Id.

%% @doc Start resolving `Name', or join a query already running. A
%% cached name gives its result at once.
-spec resolve(binary(), integer(), resolver()) -> {resolver(), [action()]}.
resolve(Name0, Now, R0) ->
    case webrtc_mdns_msg:normalize_name(Name0) of
        error ->
            {R0, [{result, Name0, {error, bad_name}}]};
        {ok, Name} ->
            R = expire(Now, R0),
            case maps:find(Name, R#r.cache) of
                {ok, {_, IPs}} ->
                    {R, [{result, Name, {ok, IPs}}]};
                error when is_map_key(Name, R#r.queries) ->
                    {R, []};
                error when map_size(R#r.queries) >= R#r.max_queries ->
                    {R, [{result, Name, {error, too_many_queries}}]};
                error ->
                    Q = #q{id = (R#r.ids)(), deadline = Now + hd(R#r.schedule)},
                    {R#r{queries = (R#r.queries)#{Name => Q}}, query(Name, Q, true)}
            end
    end.

%% One question per message: some responders (Chromium) ignore queries
%% with several questions.
query(Name, #q{id = Id}, QU) ->
    [{send, webrtc_mdns_msg:encode_query(Id, [{Name, T, QU}])} || T <- [a, aaaa]].

%% @doc A datagram received on the query socket (`unicast') or on the
%% multicast group (`multicast').
-spec handle_packet(unicast | multicast, binary(), integer(), resolver()) -> {resolver(), [action()]}.
handle_packet(How, Bin, Now, R) ->
    case webrtc_mdns_msg:decode(Bin) of
        {ok, #{qr := true, opcode := 0, rcode := 0} = M} ->
            answers(How, M, Now, R);
        _ ->
            {R, []}
    end.

answers(How, #{answers := An, additional := Ad} = M, Now, R) ->
    %% Goodbye records (TTL 0, RFC 6762 §10.1) withdraw an address.
    Records = [
        RR
     || #{type := T, class := 1, ttl := TTL} = RR <- An ++ Ad, T =:= a orelse T =:= aaaa, TTL > 0
    ],
    Names = lists:usort([N || #{name := N} <- Records, is_map_key(N, R#r.queries)]),
    Matching = [N || N <- Names, solicited(How, N, M, maps:get(N, R#r.queries))],
    lists:foldl(fun(N, Acc) -> complete(N, Records, Now, Acc) end, {R, []}, Matching).

%% Legacy unicast replies echo the ID and the question (RFC 6762 §6.7).
solicited(unicast, Name, #{id := Id, questions := Qs}, #q{id = Id}) ->
    lists:any(fun(#{name := N}) -> N =:= Name end, Qs);
solicited(unicast, _, _, _) ->
    false;
solicited(multicast, _, _, _) ->
    true.

complete(Name, Records, Now, {R, Acts}) ->
    RRs = [RR || #{name := N} = RR <- Records, N =:= Name],
    IPs = dedup([IP || #{data := IP} <- RRs]),
    TTL = min(R#r.max_ttl, lists:min([T || #{ttl := T} <- RRs])),
    R1 = R#r{queries = maps:remove(Name, R#r.queries)},
    {cache(Name, Now + TTL * 1000, IPs, R1), Acts ++ [{result, Name, {ok, IPs}}]}.

dedup(L) -> dedup(L, []).
dedup([], Acc) -> lists:reverse(Acc);
dedup([X | Xs], Acc) ->
    case lists:member(X, Acc) of
        true -> dedup(Xs, Acc);
        false -> dedup(Xs, [X | Acc])
    end.

%% When full, the entry closest to expiry makes room.
cache(Name, Expiry, IPs, #r{cache = C, max_cache = Max} = R) ->
    C1 =
        case map_size(C) >= Max andalso not is_map_key(Name, C) of
            true ->
                [{_, Oldest} | _] = lists:sort([{E, N} || N := {E, _} <- C]),
                maps:remove(Oldest, C);
            false ->
                C
        end,
    R#r{cache = C1#{Name => {Expiry, IPs}}}.

expire(Now, #r{cache = C} = R) ->
    R#r{cache = maps:filter(fun(_, {E, _}) -> E > Now end, C)}.

%% @doc Retransmit or fail the queries whose deadline passed.
-spec handle_timeout(integer(), resolver()) -> {resolver(), [action()]}.
handle_timeout(Now, R0) ->
    R = expire(Now, R0),
    maps:fold(
        fun
            (Name, #q{deadline = D} = Q, {Acc, Acts}) when D =< Now ->
                case lists:nthtail(Q#q.attempt, Acc#r.schedule) of
                    [Delay | _] ->
                        Q1 = Q#q{attempt = Q#q.attempt + 1, deadline = Now + Delay},
                        Qs = (Acc#r.queries)#{Name => Q1},
                        {Acc#r{queries = Qs}, Acts ++ query(Name, Q1, false)};
                    [] ->
                        Qs = maps:remove(Name, Acc#r.queries),
                        {Acc#r{queries = Qs}, Acts ++ [{result, Name, {error, timeout}}]}
                end;
            (_, _, Acc) ->
                Acc
        end,
        {R, []},
        R#r.queries
    ).

%% @doc Absolute time of the next retransmission or failure.
-spec next_timeout(resolver()) -> integer() | infinity.
next_timeout(#r{queries = Qs}) ->
    maps:fold(fun(_, #q{deadline = D}, Min) -> min(D, Min) end, infinity, Qs).

%% @doc Names being resolved.
-spec pending(resolver()) -> [binary()].
pending(#r{queries = Qs}) -> maps:keys(Qs).

%% @doc Cached addresses of a name, if still valid at `Now'.
-spec cached(binary(), integer(), resolver()) -> {ok, [inet:ip_address()]} | error.
cached(Name, Now, #r{cache = C}) ->
    case webrtc_mdns_msg:normalize_name(Name) of
        {ok, N} ->
            case maps:find(N, C) of
                {ok, {E, IPs}} when E > Now -> {ok, IPs};
                _ -> error
            end;
        error ->
            error
    end.
