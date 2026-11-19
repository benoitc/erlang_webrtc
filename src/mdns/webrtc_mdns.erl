%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Name resolution for ICE candidates whose address is a host name,
%% and an optional mDNS responder for our own host candidates
%% (draft-ietf-mmusic-mdns-ice-candidates).
%%
%% One process per transport, started on demand. It never blocks its
%% caller: `resolve/2' returns a reference and the result arrives as
%% `{webrtc_mdns, Ref, {ok, [IP, ...]} | {error, Reason}}'.
%%
%% <ul>
%% <li>`.local' names use one-shot multicast DNS queries
%%     (`webrtc_mdns_resolver', RFC 6762 §5.1) sent from an ephemeral
%%     port to the group (224.0.0.251:5353). Legacy unicast replies come
%%     back on that port; multicast replies are received on a socket
%%     bound to the group port with `SO_REUSEPORT' (shared with the
%%     system responder) and joined to the group.</li>
%% <li>Other names are looked up with `inet:getaddrs(Name, Family, Timeout)' in a helper
%%     process, AAAA then A (RFC 8839 §5.1).</li>
%% <li>Responses must come from an address on a local subnet
%%     (RFC 6762 §11).</li>
%% <li>`register_name/2' gives an address a random `<uuid>.local' name
%%     (draft §3.1.1), announces it and answers queries for it on the
%%     group socket (`webrtc_mdns_responder').</li>
%% </ul>
%%
%% Queries go out over IPv4 (224.0.0.251) and IPv6 (ff02::fb) multicast,
%% the IPv6 ones once per interface (RFC 6762 §5, §20): a host that only
%% answers over IPv6 is found too, and our names are announced and
%% answered on both. A question for the family a name does not have is
%% answered with NSEC (§6.1).
%%
%% Options: `group' (`{IP, Port}' the queries go to), `listen'
%% (`{IP, Port}' of the multicast socket, `false' for none), `group6'
%% and `listen6' the same for IPv6 (`group6' defaults to
%% `{ff02::fb, 5353}', or `false', no IPv6, when `group' is given),
%% `schedule',
%% `max_queries', `max_cache' (see `webrtc_mdns_resolver'),
%% `fqdn_timeout' (ms, default 3000) and `check_source' (default true).
%% Tests point `group' and `listen' at loopback ports.
-module(webrtc_mdns).
-behaviour(gen_server).

-export([start/1, stop/1, stop_async/1, resolve/2, register_name/2]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-ifdef(TEST).
-export([from_link/2]).
-endif.

-define(GROUP, {{224, 0, 0, 251}, 5353}).
-define(GROUP6, {{16#ff02, 0, 0, 0, 0, 0, 0, 16#fb}, 5353}).
-define(ACTIVE_N, 32).
-define(MAX_WAITERS, 64).
-define(MAX_FQDN, 8).

-record(st, {
    owner :: pid(),
    qsock :: gen_udp:socket(),
    msock :: gen_udp:socket() | undefined,
    group :: {inet:ip4_address(), inet:port_number()},
    %% IPv6: query and group sockets, the group, and the interfaces a
    %% multicast goes out on (`[none]' for a unicast test group).
    qsock6 :: gen_udp:socket() | undefined,
    msock6 :: gen_udp:socket() | undefined,
    group6 :: {inet:ip6_address(), inet:port_number()} | undefined,
    ifs6 = [] :: [non_neg_integer() | none],
    resolver :: webrtc_mdns_resolver:resolver(),
    responder :: webrtc_mdns_responder:responder(),
    %% Name => [{Pid, Ref}] waiting for a multicast DNS answer.
    waiters = #{} :: #{binary() => [{pid(), reference()}]},
    %% Lookup helper => {Monitor, Pid, Ref} for DNS lookups.
    fqdn = #{} :: #{pid() => {reference(), pid(), reference()}},
    fqdn_timeout :: pos_integer(),
    nets :: [{inet:ip_address(), inet:ip_address()}] | any,
    timer :: undefined | reference()
}).

%%====================================================================
%% API
%%====================================================================

%% @doc Start a resolver for the calling process. It stops when the
%% caller exits.
-spec start(map()) -> {ok, pid()} | {error, term()}.
start(Opts) ->
    gen_server:start(?MODULE, Opts#{owner => self()}, []).

-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid, normal, 5000).

%% @doc Stop without waiting (goodbye packets are still sent).
-spec stop_async(pid()) -> ok.
stop_async(Pid) ->
    gen_server:cast(Pid, stop).

%% @doc Resolve a host name. The result is sent to the caller as
%% `{webrtc_mdns, Ref, Result}'.
-spec resolve(pid(), binary()) -> reference().
resolve(Pid, Name) ->
    Ref = make_ref(),
    gen_server:cast(Pid, {resolve, self(), Ref, Name}),
    Ref.

%% @doc Name an address with a random `<uuid>.local' name and answer
%% queries for it. The same address keeps its name.
-spec register_name(pid(), inet:ip_address()) -> {ok, binary()} | {error, term()}.
register_name(Pid, IP) ->
    gen_server:call(Pid, {register_name, IP}).

%%====================================================================
%% gen_server
%%====================================================================

init(#{owner := Owner} = Opts) ->
    _ = monitor(process, Owner),
    {GroupIP, _} = Group = maps:get(group, Opts, ?GROUP),
    QOpts = [binary, inet, {active, ?ACTIVE_N}, {multicast_ttl, 255}, {multicast_loop, true}],
    Group6 = maps:get(group6, Opts, case maps:is_key(group, Opts) of true -> false; false -> ?GROUP6 end),
    case gen_udp:open(0, QOpts) of
        {ok, QSock} ->
            {Q6, M6, G6, Ifs6} = open6(Group6, Opts),
            {ok, #st{
                owner = Owner,
                qsock = QSock,
                msock = open_listener(maps:get(listen, Opts, {{0, 0, 0, 0}, element(2, Group)}), GroupIP),
                group = Group,
                qsock6 = Q6,
                msock6 = M6,
                group6 = G6,
                ifs6 = Ifs6,
                resolver = webrtc_mdns_resolver:new(maps:with([schedule, max_queries, max_cache], Opts)),
                responder = webrtc_mdns_responder:new(#{}),
                fqdn_timeout = maps:get(fqdn_timeout, Opts, 3000),
                nets =
                    case maps:get(check_source, Opts, true) of
                        true -> local_nets();
                        false -> any
                    end
            }};
        {error, R} ->
            {stop, R}
    end.

%% The group socket is shared with the system's mDNS responder, hence
%% SO_REUSEADDR and, where it exists, SO_REUSEPORT.
open_listener(false, _Group) ->
    undefined;
open_listener({IP, Port}, Group) ->
    Base = [binary, inet, {ip, IP}, {active, ?ACTIVE_N}, {reuseaddr, true}, {multicast_loop, true},
        {multicast_ttl, 255}],
    case open_first(Port, [[{reuseport, true} | Base], Base]) of
        {ok, S} ->
            _ = is_multicast(Group) andalso join(S, Group),
            S;
        error ->
            undefined
    end.

%% IPv6 sockets, best effort: a host without IPv6 multicast keeps IPv4.
open6(false, _Opts) ->
    {undefined, undefined, undefined, []};
open6({GIP, GPort} = G, Opts) ->
    QOpts = [binary, inet6, {ipv6_v6only, true}, {active, ?ACTIVE_N}, {multicast_ttl, 255}, {multicast_loop, true}],
    case gen_udp:open(0, QOpts) of
        {ok, Q} ->
            Multicast = is_multicast(GIP),
            Ifs = case Multicast of true -> ifindexes6(); false -> [none] end,
            M = open_listener6(maps:get(listen6, Opts, {{0, 0, 0, 0, 0, 0, 0, 0}, GPort}), GIP, Multicast, Ifs),
            {Q, M, G, Ifs};
        {error, _} ->
            {undefined, undefined, undefined, []}
    end.

open_listener6(false, _G, _Multicast, _Ifs) ->
    undefined;
open_listener6({IP, Port}, G, Multicast, Ifs) ->
    Base = [binary, inet6, {ipv6_v6only, true}, {ip, IP}, {active, ?ACTIVE_N}, {reuseaddr, true},
        {multicast_loop, true}, {multicast_ttl, 255}],
    case open_first(Port, [[{reuseport, true} | Base], Base]) of
        {ok, S} ->
            _ = [inet:setopts(S, [{add_membership, {G, I}}]) || Multicast, I <- Ifs],
            S;
        error ->
            undefined
    end.

%% Indexes of the up, multicast capable interfaces with an IPv6 address.
ifindexes6() ->
    case net:getifaddrs(inet6) of
        {ok, Ifs} ->
            Names = lists:usort([N || #{name := N, flags := F} <- Ifs, lists:member(up, F), lists:member(multicast, F)]),
            [I || N <- Names, {ok, I} <- [net:if_name2index(N)]];
        {error, _} ->
            []
    end.

%% A multicast leaves on every interface (the scope of ff02::fb is the
%% link); a unicast group (tests) once.
send6(undefined, _B, _St) ->
    ok;
send6(S, B, #st{group6 = {IP, Port}, ifs6 = Ifs}) ->
    _ = [
        case If of
            none -> gen_udp:send(S, IP, Port, B);
            _ -> gen_udp:send(S, #{family => inet6, addr => IP, port => Port, scope_id => If}, B)
        end
     || If <- Ifs
    ],
    ok.

open_first(_Port, []) ->
    error;
open_first(Port, [O | Os]) ->
    case gen_udp:open(Port, O) of
        {ok, S} -> {ok, S};
        {error, _} -> open_first(Port, Os)
    end.

%% Join on every multicast capable IPv4 interface; failures (an
%% interface without multicast route) are not fatal.
join(S, Group) ->
    Ifs = [A || {A, _} <- ifaddrs(multicast), tuple_size(A) =:= 4],
    _ = [inet:setopts(S, [{add_membership, {Group, If}}]) || If <- Ifs],
    true.

is_multicast({A, _, _, _}) -> A >= 224 andalso A =< 239;
is_multicast({A, _, _, _, _, _, _, _}) -> A bsr 8 =:= 16#ff.

handle_call({register_name, IP}, _From, #st{msock = undefined, msock6 = undefined} = St) when is_tuple(IP) ->
    {reply, {error, no_listener}, St};
handle_call({register_name, IP}, _From, St) when is_tuple(IP) ->
    case webrtc_mdns_responder:register(IP, St#st.responder) of
        {ok, Name, R1} ->
            _ = is_map_key(Name, webrtc_mdns_responder:names(St#st.responder)) orelse
                send_group(webrtc_mdns_responder:announcement(Name, R1), St),
            {reply, {ok, Name}, St#st{responder = R1}};
        {error, _} = E -> {reply, E, St}
    end;
handle_call(_, _From, St) ->
    {reply, {error, badarg}, St}.

handle_cast({resolve, Pid, Ref, Name}, St) ->
    case kind(Name) of
        local -> {noreply, arm(mdns_resolve(Pid, Ref, Name, St))};
        fqdn -> {noreply, fqdn_resolve(Pid, Ref, Name, St)};
        bad -> Pid ! {webrtc_mdns, Ref, {error, bad_name}}, {noreply, St}
    end;
handle_cast(stop, St) ->
    {stop, normal, St};
handle_cast(_, St) ->
    {noreply, St}.

handle_info({udp, S, IP, Port, Bin}, #st{qsock = Q, qsock6 = Q6} = St) when S =:= Q; S =:= Q6 ->
    {noreply, arm(packet(unicast, {IP, Port}, Bin, St))};
handle_info({udp, S, IP, Port, Bin}, #st{msock = M, msock6 = M6} = St) when S =:= M; S =:= M6 ->
    case Bin of
        <<_:16, 0:1, _/bits>> -> {noreply, query_in({IP, Port}, Bin, St)};
        _ -> {noreply, arm(packet(multicast, {IP, Port}, Bin, St))}
    end;
handle_info({udp_passive, S}, St) ->
    _ = inet:setopts(S, [{active, ?ACTIVE_N}]),
    {noreply, St};
handle_info({timeout, T, tick}, #st{timer = T} = St) ->
    {R1, Acts} = webrtc_mdns_resolver:handle_timeout(now_ms(), St#st.resolver),
    {noreply, arm(actions(Acts, St#st{resolver = R1, timer = undefined}))};
handle_info({'DOWN', _, process, Owner, _}, #st{owner = Owner} = St) ->
    {stop, normal, St};
handle_info({lookup, Helper, Result}, #st{fqdn = F} = St) when is_map_key(Helper, F) ->
    {{Mon, Pid, Ref}, F1} = maps:take(Helper, F),
    demonitor(Mon, [flush]),
    Pid ! {webrtc_mdns, Ref, Result},
    {noreply, St#st{fqdn = F1}};
handle_info({'DOWN', _, process, Helper, _}, #st{fqdn = F} = St) when is_map_key(Helper, F) ->
    {{_, Pid, Ref}, F1} = maps:take(Helper, F),
    Pid ! {webrtc_mdns, Ref, {error, lookup_failed}},
    {noreply, St#st{fqdn = F1}};
handle_info(_, St) ->
    {noreply, St}.

terminate(_Reason, St) ->
    %% Goodbye packets for our names (RFC 6762 §10.1).
    _ = [send_group(B, St) || B <- webrtc_mdns_responder:goodbye(St#st.responder)],
    _ = [gen_udp:close(S) || S <- [St#st.qsock, St#st.msock, St#st.qsock6, St#st.msock6], S =/= undefined],
    ok.

%%====================================================================
%% Resolution
%%====================================================================

kind(Name) ->
    case webrtc_mdns_msg:normalize_name(Name) of
        {ok, N} when byte_size(N) > 6 ->
            case binary:part(N, byte_size(N), -6) of
                <<".local">> -> local;
                _ -> fqdn
            end;
        {ok, _} -> fqdn;
        error -> bad
    end.

mdns_resolve(Pid, Ref, Name, St) ->
    Waiting = lists:sum([length(W) || _ := W <- St#st.waiters]),
    case Waiting >= ?MAX_WAITERS of
        true ->
            Pid ! {webrtc_mdns, Ref, {error, too_many_queries}},
            St;
        false ->
            {R1, Acts} = webrtc_mdns_resolver:resolve(Name, now_ms(), St#st.resolver),
            {ok, Key} = webrtc_mdns_msg:normalize_name(Name),
            W = maps:get(Key, St#st.waiters, []),
            actions(Acts, St#st{resolver = R1, waiters = (St#st.waiters)#{Key => W ++ [{Pid, Ref}]}})
    end.

fqdn_resolve(Pid, Ref, _Name, #st{fqdn = F} = St) when map_size(F) >= ?MAX_FQDN ->
    Pid ! {webrtc_mdns, Ref, {error, too_many_queries}},
    St;
fqdn_resolve(Pid, Ref, Name, #st{fqdn = F, fqdn_timeout = T} = St) ->
    Self = self(),
    {Helper, Mon} = spawn_monitor(fun() -> Self ! {lookup, self(), lookup(binary_to_list(Name), T)} end),
    St#st{fqdn = F#{Helper => {Mon, Pid, Ref}}}.

%% RFC 8839 §5.1: AAAA first, then A.
lookup(Host, Timeout) ->
    V6 = getaddrs(Host, inet6, Timeout),
    V4 = getaddrs(Host, inet, Timeout),
    case V6 ++ V4 of
        [] -> {error, nxdomain};
        IPs -> {ok, IPs}
    end.

getaddrs(Host, Family, Timeout) ->
    case inet:getaddrs(Host, Family, Timeout) of
        {ok, IPs} -> IPs;
        {error, _} -> []
    end.

packet(How, Src, Bin, St) ->
    case from_link(Src, St#st.nets) of
        true ->
            {R1, Acts} = webrtc_mdns_resolver:handle_packet(How, Bin, now_ms(), St#st.resolver),
            actions(Acts, St#st{resolver = R1});
        false ->
            St
    end.

query_in(Src, Bin, St) ->
    case from_link(Src, St#st.nets) of
        true ->
            {R1, Out} = webrtc_mdns_responder:handle_query(Src, element(2, St#st.group), Bin, now_ms(),
                St#st.responder),
            _ = [send_reply(Dest, B, St) || {Dest, B} <- Out],
            St#st{responder = R1};
        false ->
            St
    end.

send_reply(group, B, St) ->
    send_group(B, St);
send_reply({{_, _, _, _} = IP, Port}, B, #st{msock = S}) when S =/= undefined ->
    gen_udp:send(S, IP, Port, B);
send_reply({{16#fe80, _, _, _, _, _, _, _} = IP, Port}, B, #st{msock6 = S, ifs6 = Ifs}) when S =/= undefined ->
    %% The interface a link-local source came from is not known: try
    %% each, only the right one reaches it.
    _ = [gen_udp:send(S, #{family => inet6, addr => IP, port => Port, scope_id => If}, B) || If <- Ifs, If =/= none],
    ok;
send_reply({IP, Port}, B, #st{msock6 = S}) when S =/= undefined, tuple_size(IP) =:= 8 ->
    gen_udp:send(S, IP, Port, B);
send_reply(_, _, _) ->
    ok.

%% Announcements and multicast answers go to both groups.
send_group(B, #st{msock = S, group = {IP, Port}} = St) ->
    _ = S =/= undefined andalso gen_udp:send(S, IP, Port, B),
    send6(St#st.msock6, B, St).

actions(Acts, St) ->
    lists:foldl(fun action/2, St, Acts).

action({send, Bin}, #st{qsock = S, group = {IP, Port}} = St) ->
    _ = gen_udp:send(S, IP, Port, Bin),
    ok = send6(St#st.qsock6, Bin, St),
    St;
action({result, Name, Result}, #st{waiters = W} = St) ->
    {Waiting, W1} =
        case maps:take(Name, W) of
            error -> {[], W};
            Found -> Found
        end,
    _ = [Pid ! {webrtc_mdns, Ref, Result} || {Pid, Ref} <- Waiting],
    St#st{waiters = W1}.

%% RFC 6762 §11: only accept packets from a local link.
from_link(_, any) ->
    true;
from_link({{A, _, _, _, _, _, _, _}, _}, _Nets) when A band 16#ffc0 =:= 16#fe80 ->
    %% IPv6 link-local.
    true;
from_link({{_, _, _, _, _, _, _, _} = IP, _}, Nets) ->
    lists:any(
        fun({Net, Mask}) when tuple_size(Net) =:= 8 ->
                lists:all(fun({X, Y, M}) -> X band M =:= Y band M end,
                          lists:zip3(tuple_to_list(IP), tuple_to_list(Net), tuple_to_list(Mask)));
           (_) ->
                false
        end,
        Nets
    );
from_link({{A, B, C, D}, _}, Nets) ->
    lists:any(
        fun({{A1, B1, C1, D1}, {M1, M2, M3, M4}}) ->
                (A band M1 =:= A1 band M1) andalso (B band M2 =:= B1 band M2) andalso
                    (C band M3 =:= C1 band M3) andalso (D band M4 =:= D1 band M4);
           (_) ->
                false
        end,
        Nets
    );
from_link(_, _) ->
    false.

local_nets() ->
    [{A, M} || {A, M} <- ifaddrs(any)].

%% IPv4 address and netmask of up interfaces (with the multicast flag
%% when asked).
ifaddrs(Need) ->
    case inet:getifaddrs() of
        {ok, Ifs} ->
            [
                AM
             || {_, Props} <- Ifs,
                Flags <- [proplists:get_value(flags, Props, [])],
                lists:member(up, Flags),
                Need =:= any orelse lists:member(multicast, Flags),
                AM <- addr_masks(Props)
            ];
        {error, _} ->
            []
    end.

%% getifaddrs lists `addr' followed by its `netmask'.
addr_masks([{addr, {_, _, _, _} = A}, {netmask, {_, _, _, _} = M} | Rest]) -> [{A, M} | addr_masks(Rest)];
addr_masks([{addr, {_, _, _, _} = A} | Rest]) -> [{A, {255, 255, 255, 255}} | addr_masks(Rest)];
addr_masks([{addr, {_, _, _, _, _, _, _, _} = A}, {netmask, {_, _, _, _, _, _, _, _} = M} | Rest]) ->
    [{A, M} | addr_masks(Rest)];
addr_masks([{addr, {_, _, _, _, _, _, _, _} = A} | Rest]) ->
    [{A, list_to_tuple(lists:duplicate(8, 16#ffff))} | addr_masks(Rest)];
addr_masks([_ | Rest]) -> addr_masks(Rest);
addr_masks([]) -> [].

arm(#st{timer = T0} = St) ->
    _ = T0 =/= undefined andalso erlang:cancel_timer(T0),
    case webrtc_mdns_resolver:next_timeout(St#st.resolver) of
        infinity -> St#st{timer = undefined};
        At -> St#st{timer = erlang:start_timer(max(At, now_ms()), self(), tick, [{abs, true}])}
    end.

now_ms() -> erlang:monotonic_time(millisecond).
