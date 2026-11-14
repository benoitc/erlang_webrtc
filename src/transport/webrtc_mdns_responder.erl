%% @doc Sans-IO multicast DNS responder for the `<uuid>.local' names of
%% our own host candidates (draft-ietf-mmusic-mdns-ice-candidates §3.1).
%%
%% Each registered address gets a random version 4 UUID name
%% (draft §3.1). Being random, the names are not probed for
%% uniqueness and are not announced; they are only answered (RFC 6762
%% §6):
%% <ul>
%% <li>a query from a port other than the mDNS port is a legacy one-shot
%%     query: unicast reply to its source, ID and question repeated,
%%     TTL at most 10 seconds and no cache-flush bit (§6.7);</li>
%% <li>a QU question gets a unicast reply to its source (§5.4);</li>
%% <li>otherwise the reply is multicast to the group, at most once per
%%     second per name (§6);</li>
%% <li>a question whose answer the querier already lists with at least
%%     half its TTL left is not answered (known-answer suppression, §7.1).</li>
%% </ul>
%% Only A and AAAA (or ANY) questions for a name of the right family are
%% answered; there is no negative (NSEC) answer.
-module(webrtc_mdns_responder).

-export([new/1, register/2, names/1, handle_query/5, goodbye/1]).

-export_type([responder/0, dest/0]).

-define(TTL, 120).
-define(LEGACY_TTL, 10).
-define(RATE_MS, 1000).

-record(rs, {
    names = #{} :: #{binary() => inet:ip_address()},
    by_ip = #{} :: #{inet:ip_address() => binary()},
    last = #{} :: #{binary() => integer()},
    max :: pos_integer()
}).

-opaque responder() :: #rs{}.
-type dest() :: group | {inet:ip_address(), inet:port_number()}.

%% @doc Options: `max_names' (default 16).
-spec new(map()) -> responder().
new(Opts) ->
    #rs{max = maps:get(max_names, Opts, 16)}.

%% @doc The name of `IP', created on first use.
-spec register(inet:ip_address(), responder()) -> {ok, binary(), responder()} | {error, too_many_names}.
register(IP, #rs{by_ip = B} = R) when is_map_key(IP, B) ->
    {ok, maps:get(IP, B), R};
register(_IP, #rs{names = N, max = Max}) when map_size(N) >= Max ->
    {error, too_many_names};
register(IP, #rs{names = N, by_ip = B} = R) ->
    Name = uuid_name(),
    {ok, Name, R#rs{names = N#{Name => IP}, by_ip = B#{IP => Name}}}.

uuid_name() ->
    <<A:32, B:16, _:4, C:12, _:2, D:14, E:48>> = crypto:strong_rand_bytes(16),
    iolist_to_binary(
        io_lib:format("~8.16.0b-~4.16.0b-4~3.16.0b-~4.16.0b-~12.16.0b.local", [A, B, C, 16#8000 bor D, E])
    ).

%% @doc Registered names and their addresses.
-spec names(responder()) -> #{binary() => inet:ip_address()}.
names(#rs{names = N}) -> N.

%% @doc A query received from `Src' on the group socket (mDNS port
%% `MdnsPort'). Returns the replies to send.
-spec handle_query({inet:ip_address(), inet:port_number()}, inet:port_number(), binary(), integer(), responder()) ->
    {responder(), [{dest(), binary()}]}.
handle_query(_Src, _MdnsPort, _Bin, _Now, #rs{names = N} = R) when map_size(N) =:= 0 ->
    {R, []};
handle_query({_, SrcPort} = Src, MdnsPort, Bin, Now, R) ->
    case webrtc_mdns_msg:decode(Bin) of
        {ok, #{qr := false, opcode := 0, id := Id, questions := Qs, answers := Known}} ->
            Hits = [Q || Q <- Qs, answers(Q, Known, R) =/= []],
            reply(SrcPort =/= MdnsPort, Src, Id, Hits, Known, Now, R);
        _ ->
            {R, []}
    end.

answers(#{name := Name, type := T, class := C}, Known, #rs{names = N}) when C =:= 1; C =:= 255 ->
    case maps:find(Name, N) of
        {ok, IP} ->
            case type_matches(T, IP) andalso not known(Name, IP, Known) of
                true -> [{Name, IP}];
                false -> []
            end;
        error ->
            []
    end;
answers(_, _, _) ->
    [].

type_matches(any, _) -> true;
type_matches(a, IP) -> tuple_size(IP) =:= 4;
type_matches(aaaa, IP) -> tuple_size(IP) =:= 8;
type_matches(_, _) -> false.

known(Name, IP, Known) ->
    lists:any(fun(#{name := N, data := D, ttl := T}) -> N =:= Name andalso D =:= IP andalso T >= ?TTL div 2 end, Known).

reply(_Legacy, _Src, _Id, [], _Known, _Now, R) ->
    {R, []};
reply(true, Src, Id, Hits, Known, _Now, R) ->
    Qs = [{N, T} || #{name := N, type := T} <- Hits],
    As = lists:usort([{N, IP, ?LEGACY_TTL, false} || Q <- Hits, {N, IP} <- answers(Q, Known, R)]),
    {R, [{Src, webrtc_mdns_msg:encode_response(Id, Qs, As, [])}]};
reply(false, Src, _Id, Hits, Known, Now, R) ->
    {QU, QM} = lists:partition(fun(#{unicast := U}) -> U end, Hits),
    Unicast = [{Src, response(QU, Known, R)} || QU =/= []],
    Fresh = [
        Q
     || #{name := N} = Q <- QM, Now - maps:get(N, R#rs.last, Now - ?RATE_MS) >= ?RATE_MS
    ],
    R1 = R#rs{last = maps:merge(R#rs.last, maps:from_list([{N, Now} || #{name := N} <- Fresh]))},
    Multicast = [{group, response(Fresh, Known, R)} || Fresh =/= []],
    {R1, Unicast ++ Multicast}.

response(Qs, Known, R) ->
    As = lists:usort([{N, IP, ?TTL, true} || Q <- Qs, {N, IP} <- answers(Q, Known, R)]),
    webrtc_mdns_msg:encode_response(0, [], As, []).

%% @doc Goodbye packets withdrawing every name (TTL 0, RFC 6762 §10.1).
-spec goodbye(responder()) -> [binary()].
goodbye(#rs{names = N}) when map_size(N) =:= 0 ->
    [];
goodbye(#rs{names = N}) ->
    [webrtc_mdns_msg:encode_response(0, [], [{Name, IP, 0, true} || Name := IP <- N], [])].
