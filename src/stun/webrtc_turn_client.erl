%% @doc Sans-IO TURN client for UDP (RFC 8656), one allocation per
%% client state.
%%
%% The client talks to a single TURN server over the owner's UDP
%% socket. It never touches the socket: it returns `{send, Bin}'
%% actions (the destination is always the server) and `{event, Event}'
%% actions.
%%
%% ```
%% C0 = webrtc_turn_client:new(#{server => {IP, 3478},
%%                              username => <<"u">>, password => <<"p">>}),
%% {C1, Acts} = webrtc_turn_client:allocate(Now, C0),
%% %% for every datagram from the server:
%% {C2, Acts2} = webrtc_turn_client:handle_packet(Bin, Now, C1),
%% %% at next_timeout/1:
%% {C3, Acts3} = webrtc_turn_client:handle_timeout(Now, C2),
%% %% relay data to a peer (a permission is created on demand):
%% {C4, Acts4} = webrtc_turn_client:send(PeerAddr, Data, Now, C3),
%% %% release the allocation:
%% {C5, Acts5} = webrtc_turn_client:close(Now, C4).
%% '''
%%
%% Behavior:
%% <ul>
%% <li>Allocate is sent first without credentials (RFC 8489 §9.2.3.1).
%%     A 401 with REALM and NONCE is retried with the long-term
%%     credential (USERNAME, REALM, NONCE, MESSAGE-INTEGRITY). When the
%%     401 carries PASSWORD-ALGORITHMS the first supported algorithm is
%%     used, PASSWORD-ALGORITHMS and PASSWORD-ALGORITHM are echoed and
%%     all later requests use MESSAGE-INTEGRITY-SHA256 (§9.2.5). A 438
%%     is retried with the new nonce.</li>
%% <li>REQUESTED-TRANSPORT is always UDP. REQUESTED-ADDRESS-FAMILY is sent
%%     when the `family' option is given.</li>
%% <li>The allocation is refreshed one minute before it expires (or at
%%     half its lifetime when shorter than two minutes).</li>
%% <li>Permissions are refreshed every 240 s (lifetime 300 s), channel
%%     bindings every 540 s (lifetime 600 s).</li>
%% <li>`send/4' uses ChannelData when a channel is bound to the peer,
%%     otherwise a Send indication. Data for a peer without an installed
%%     permission is queued (bounded) until CreatePermission
%%     succeeds.</li>
%% <li>Responses to authenticated requests must carry valid integrity,
%%     otherwise they are discarded and retransmissions continue.</li>
%% </ul>
%%
%% Events:
%% <ul>
%% <li>`{allocated, #{relayed := Addr, mapped := Addr | undefined,
%%     lifetime := Seconds}}'</li>
%% <li>`{allocate_failed, Reason}' with `timeout', `{error, Code}' or
%%     `{unsupported, What}'</li>
%% <li>`{allocation_lost, Reason}' (437, refresh failure, expiry)</li>
%% <li>`{permission, IP, ok | {error, Reason}}'</li>
%% <li>`{channel, Peer, {ok, Number} | {error, Reason}}'</li>
%% <li>`{data, Peer, Data}': data relayed from `Peer'</li>
%% <li>`closed': the allocation was deleted</li>
%% </ul>
-module(webrtc_turn_client).

-include("webrtc_stun.hrl").

-export([
    new/1,
    allocate/2,
    handle_packet/3,
    handle_timeout/2,
    next_timeout/1,
    send/4,
    create_permission/3,
    bind_channel/3,
    close/2,
    state/1,
    relayed_address/1,
    mapped_address/1,
    server/1,
    has_permission/2,
    channel/2
]).

-export_type([client/0, action/0, event/0, state_name/0]).

-type address() :: webrtc_stun:address().
-type state_name() :: idle | allocating | allocated | failed | closing | closed.
-type event() ::
    {allocated, #{relayed := address(), mapped := address() | undefined, lifetime := non_neg_integer()}}
    | {allocate_failed, term()}
    | {allocation_lost, term()}
    | {permission, inet:ip_address(), ok | {error, term()}}
    | {channel, address(), {ok, 16#4000..16#4FFF} | {error, term()}}
    | {data, address(), binary()}
    | closed.
-type action() :: {send, binary()} | {event, event()}.

-define(PERM_LIFETIME, 300000).
-define(PERM_REFRESH, 240000).
-define(CHAN_LIFETIME, 600000).
-define(CHAN_REFRESH, 540000).
-define(MAX_STALE, 3).

%% A failed ChannelBind may still be installed on the server for its
%% lifetime (10 min); its number and peer then wait 5 more (§12).
-define(CHANNEL_QUARANTINE, (15 * 60000)).

-record(perm, {
    state = pending :: pending | installed,
    expires = 0 :: integer(),
    refresh_at = infinity :: integer() | infinity,
    queue = [] :: [{address(), binary()}]
}).

-record(chan, {
    num :: 16#4000..16#4FFF,
    state = pending :: pending | bound,
    refresh_at = infinity :: integer() | infinity
}).

-record(turn, {
    server :: address(),
    username :: binary(),
    password :: binary(),
    software :: binary() | undefined,
    family :: ipv4 | ipv6 | undefined,
    lifetime_req :: non_neg_integer() | undefined,
    realm :: binary() | undefined,
    nonce :: binary() | undefined,
    pw_algs :: [{atom() | integer(), binary()}] | undefined,
    pw_alg :: {atom(), binary()} | undefined,
    integrity :: webrtc_stun:integrity(),
    state = idle :: state_name(),
    relayed :: address() | undefined,
    mapped :: address() | undefined,
    expires = 0 :: integer(),
    refresh_at = infinity :: integer() | infinity,
    tx :: webrtc_stun_tx:table(),
    stale = 0 :: non_neg_integer(),
    perms = #{} :: #{inet:ip_address() => #perm{}},
    chans = #{} :: #{address() => #chan{}},
    by_num = #{} :: #{16#4000..16#4FFF => address()},
    next_chan = 16#4000 :: 16#4000..16#4FFF,
    %% Numbers of failed bindings, and their peer, until they may go to
    %% another binding.
    reserved = #{} :: #{16#4000..16#4FFF => {address(), integer()}},
    queue_limit = 64 :: non_neg_integer()
}).

-opaque client() :: #turn{}.

%% @doc Options: `server' (required), `username', `password',
%% `software' (default `<<"erlang-webrtc">>', `undefined' to omit),
%% `family' (`ipv4' | `ipv6', REQUESTED-ADDRESS-FAMILY), `lifetime'
%% (requested seconds), `rto', `rc', `rm' (transactions), `queue_limit'.
-spec new(map()) -> client().
new(#{server := Server} = Opts) ->
    #turn{
        server = Server,
        username = maps:get(username, Opts, <<>>),
        password = maps:get(password, Opts, <<>>),
        software = maps:get(software, Opts, <<"erlang-webrtc">>),
        family = maps:get(family, Opts, undefined),
        lifetime_req = maps:get(lifetime, Opts, undefined),
        queue_limit = maps:get(queue_limit, Opts, 64),
        tx = webrtc_stun_tx:new(maps:with([rto, rc, rm, max_rto], Opts))
    }.

-spec state(client()) -> state_name().
state(#turn{state = S}) -> S.

-spec relayed_address(client()) -> address() | undefined.
relayed_address(#turn{relayed = R}) -> R.

-spec mapped_address(client()) -> address() | undefined.
mapped_address(#turn{mapped = M}) -> M.

-spec server(client()) -> address().
server(#turn{server = S}) -> S.

-spec has_permission(inet:ip_address(), client()) -> boolean().
has_permission(IP, #turn{perms = P}) ->
    case maps:find(IP, P) of
        {ok, #perm{state = installed}} -> true;
        _ -> false
    end.

-spec channel(address(), client()) -> {ok, 16#4000..16#4FFF} | error.
channel(Peer, #turn{chans = C}) ->
    case maps:find(Peer, C) of
        {ok, #chan{state = bound, num = N}} -> {ok, N};
        _ -> error
    end.

%%====================================================================
%% Allocation
%%====================================================================

-spec allocate(integer(), client()) -> {client(), [action()]}.
allocate(Now, #turn{state = idle} = C) ->
    request(allocate, allocate_attrs(C), Now, C#turn{state = allocating});
allocate(_Now, C) ->
    {C, []}.

allocate_attrs(#turn{family = F, lifetime_req = L, software = Sw}) ->
    [{requested_transport, udp}] ++
        [{requested_address_family, F} || F =/= undefined] ++
        [{lifetime, L} || L =/= undefined] ++
        [{software, Sw} || Sw =/= undefined].

%% @doc Delete the allocation (Refresh with LIFETIME 0, RFC 8656 §8).
-spec close(integer(), client()) -> {client(), [action()]}.
close(Now, #turn{state = allocated} = C) ->
    C1 = C#turn{state = closing, refresh_at = infinity, perms = #{}, chans = #{}, by_num = #{}},
    request(refresh, [{lifetime, 0}], Now, C1);
close(_Now, #turn{state = closed} = C) ->
    {C, []};
close(_Now, C) ->
    {C#turn{state = closed, perms = #{}, chans = #{}, by_num = #{}}, [{event, closed}]}.

%%====================================================================
%% Permissions, channels, data
%%====================================================================

%% @doc Install (or keep refreshing) a permission for `IP'.
-spec create_permission(inet:ip_address(), integer(), client()) -> {client(), [action()]}.
create_permission(IP, Now, #turn{perms = P} = C) ->
    case maps:find(IP, P) of
        {ok, _} ->
            {C, []};
        error ->
            C1 = C#turn{perms = P#{IP => #perm{}}},
            case C#turn.state of
                allocated -> send_permission(IP, Now, C1);
                _ -> {C1, []}
            end
    end.

send_permission(IP, Now, C) ->
    request({permission, IP}, [{xor_peer_address, {IP, 0}}], Now, C).

%% @doc Bind a channel to `Peer' (RFC 8656 §12.1). Data keeps flowing
%% through Send indications until the binding is confirmed.
-spec bind_channel(address(), integer(), client()) -> {client(), [action()]}.
bind_channel(Peer, Now, #turn{state = allocated, chans = Ch} = C0) ->
    C = expire_reserved(Now, C0),
    case maps:is_key(Peer, Ch) of
        true ->
            {C, []};
        false ->
            case free_channel(Peer, C) of
                {ok, N} ->
                    C1 = C#turn{
                        chans = Ch#{Peer => #chan{num = N}},
                        by_num = (C#turn.by_num)#{N => Peer},
                        reserved = maps:remove(N, C#turn.reserved),
                        next_chan = next_num(N)
                    },
                    send_bind(Peer, N, Now, C1);
                error ->
                    {C, [{event, {channel, Peer, {error, no_channel}}}]}
            end
    end;
bind_channel(_Peer, _Now, C) ->
    {C, []}.

send_bind(Peer, N, Now, C) ->
    request({channel, Peer, N}, [{channel_number, N}, {xor_peer_address, Peer}], Now, C).

%% A peer whose binding failed recently gets its number back (binding
%% the same pair again refreshes it); other peers skip reserved numbers.
free_channel(Peer, #turn{by_num = B, reserved = R, next_chan = Start}) ->
    case [N || N := {P, _} <- R, P =:= Peer] of
        [N | _] -> {ok, N};
        [] -> free_channel(Start, B, R, 16#1000)
    end.

free_channel(_N, _B, _R, 0) ->
    error;
free_channel(N, B, R, Left) ->
    case maps:is_key(N, B) orelse maps:is_key(N, R) of
        false -> {ok, N};
        true -> free_channel(next_num(N), B, R, Left - 1)
    end.

expire_reserved(Now, #turn{reserved = R} = C) ->
    C#turn{reserved = maps:filter(fun(_, {_, Until}) -> Until > Now end, R)}.

next_num(16#4FFF) -> 16#4000;
next_num(N) -> N + 1.

%% @doc Relay `Data' to `Peer'. Dropped (as UDP would) when there is no
%% allocation.
-spec send(address(), binary(), integer(), client()) -> {client(), [action()]}.
send({IP, _} = Peer, Data, Now, #turn{state = allocated, perms = P} = C) ->
    case maps:find(IP, P) of
        {ok, #perm{state = installed}} ->
            {C, [{send, wrap(Peer, Data, C)}]};
        {ok, #perm{state = pending, queue = Q} = Perm} ->
            case length(Q) < C#turn.queue_limit of
                true -> {C#turn{perms = P#{IP => Perm#perm{queue = Q ++ [{Peer, Data}]}}}, []};
                false -> {C, []}
            end;
        error ->
            {C1, Acts} = create_permission(IP, Now, C),
            #perm{} = Perm = maps:get(IP, C1#turn.perms),
            Perms = (C1#turn.perms)#{IP => Perm#perm{queue = [{Peer, Data}]}},
            {C1#turn{perms = Perms}, Acts}
    end;
send(_Peer, _Data, _Now, C) ->
    {C, []}.

wrap(Peer, Data, #turn{chans = Ch}) ->
    case maps:find(Peer, Ch) of
        {ok, #chan{state = bound, num = N}} ->
            webrtc_turn_channel:encode(N, Data);
        _ ->
            webrtc_stun:encode(
                webrtc_stun:indication(send, [{xor_peer_address, Peer}, {data, Data}]),
                #{fingerprint => true}
            )
    end.

%%====================================================================
%% Requests and responses
%%====================================================================

request(Kind, Attrs, Now, #turn{server = S} = C) ->
    Msg = webrtc_stun:request(method(Kind), Attrs ++ webrtc_turn_auth:attrs(
        C#turn.username, C#turn.realm, C#turn.nonce, C#turn.pw_algs, C#turn.pw_alg)),
    Opts = #{integrity => C#turn.integrity, fingerprint => true},
    Bin = webrtc_stun:encode(Msg, maps:filter(fun(_, V) -> V =/= undefined end, Opts)),
    {Tx, Acts} = webrtc_stun_tx:send(
        Msg#stun.txid, S, Bin, #{key => element(1, S), meta => {Kind, Attrs}}, Now, C#turn.tx
    ),
    {C#turn{tx = Tx}, [{send, B} || {send, _, B} <- Acts]}.

method(allocate) -> allocate;
method(refresh) -> refresh;
method({permission, _}) -> create_permission;
method({channel, _, _}) -> channel_bind.

-spec handle_packet(binary(), integer(), client()) -> {client(), [action()]}.
handle_packet(<<B, _/binary>> = Bin, _Now, C) when B >= 64, B =< 79 ->
    case webrtc_turn_channel:decode(Bin) of
        {ok, N, Data} ->
            case maps:find(N, C#turn.by_num) of
                {ok, {IP, _} = Peer} ->
                    case maps:is_key(IP, C#turn.perms) of
                        true -> {C, [{event, {data, Peer, Data}}]};
                        false -> {C, []}
                    end;
                error ->
                    {C, []}
            end;
        {error, _} ->
            {C, []}
    end;
handle_packet(Bin, Now, C) ->
    case webrtc_stun:decode(Bin) of
        {ok, #stun{class = indication, method = data} = M} ->
            data_indication(M, C);
        {ok, #stun{class = Class, txid = TxId} = M} when Class =:= success; Class =:= error ->
            case webrtc_stun_tx:lookup(TxId, C#turn.tx) of
                {ok, _, {Kind, Attrs}} -> response(Kind, Attrs, M, Bin, Now, C);
                error -> {C, []}
            end;
        _ ->
            {C, []}
    end.

data_indication(M, C) ->
    case {webrtc_stun:get(xor_peer_address, M), webrtc_stun:get(data, M)} of
        {{ok, {IP, _} = Peer}, {ok, Data}} ->
            case maps:is_key(IP, C#turn.perms) of
                true -> {C, [{event, {data, Peer, Data}}]};
                false -> {C, []}
            end;
        _ ->
            {C, []}
    end.

response(Kind, Attrs, #stun{txid = TxId} = M, Bin, Now, C) ->
    case webrtc_turn_auth:authentic(M, Bin, C#turn.integrity) of
        false ->
            {C, []};
        true ->
            {ok, _, Tx} = webrtc_stun_tx:response(TxId, Now, C#turn.tx),
            C1 = C#turn{tx = Tx},
            case M#stun.class of
                success -> success(Kind, M, Now, C1#turn{stale = 0});
                error -> error_response(Kind, Attrs, code(M), M, Now, C1)
            end
    end.

code(M) ->
    case webrtc_stun:get(error_code, M) of
        {ok, {Code, _}} -> Code;
        error -> 0
    end.

success(allocate, M, Now, C) ->
    case {webrtc_stun:get(xor_relayed_address, M), webrtc_stun:get(lifetime, M)} of
        {{ok, Relayed}, {ok, Life}} ->
            Mapped = webrtc_stun:get(xor_mapped_address, M, undefined),
            C1 = schedule_refresh(Life, Now, C#turn{state = allocated, relayed = Relayed, mapped = Mapped}),
            Event = {event, {allocated, #{relayed => Relayed, mapped => Mapped, lifetime => Life}}},
            %% Permissions requested while allocating.
            lists:foldl(
                fun(IP, {CA, AA}) ->
                    {CB, AB} = send_permission(IP, Now, CA),
                    {CB, AA ++ AB}
                end,
                {C1, [Event]},
                maps:keys(C1#turn.perms)
            );
        _ ->
            fail_allocate({error, malformed_response}, C)
    end;
success(refresh, _M, _Now, #turn{state = closing} = C) ->
    {closed_state(C), [{event, closed}]};
success(refresh, M, Now, C) ->
    case webrtc_stun:get(lifetime, M) of
        {ok, 0} -> {closed_state(C), [{event, closed}]};
        {ok, Life} -> {schedule_refresh(Life, Now, C), []};
        error -> {C, []}
    end;
success({permission, IP}, _M, Now, #turn{perms = P} = C) ->
    case maps:find(IP, P) of
        {ok, Perm} ->
            Perm1 = Perm#perm{
                state = installed,
                expires = Now + ?PERM_LIFETIME,
                refresh_at = Now + ?PERM_REFRESH,
                queue = []
            },
            C1 = C#turn{perms = P#{IP => Perm1}},
            Flush = [{send, wrap(Peer, D, C1)} || {Peer, D} <- Perm#perm.queue],
            {C1, [{event, {permission, IP, ok}} | Flush]};
        error ->
            {C, []}
    end;
success({channel, {IP, _} = Peer, N}, _M, Now, #turn{chans = Ch, perms = P} = C) ->
    case maps:find(Peer, Ch) of
        {ok, #chan{num = N} = Chan} ->
            Perm = maps:get(IP, P, #perm{}),
            Perm1 = Perm#perm{
                state = installed, expires = Now + ?PERM_LIFETIME, refresh_at = Now + ?PERM_REFRESH
            },
            C1 = C#turn{
                chans = Ch#{Peer => Chan#chan{state = bound, refresh_at = Now + ?CHAN_REFRESH}},
                perms = P#{IP => Perm1#perm{queue = []}}
            },
            Flush = [{send, wrap(Pe, D, C1)} || {Pe, D} <- Perm#perm.queue],
            {C1, [{event, {channel, Peer, {ok, N}}} | Flush]};
        _ ->
            {C, []}
    end.

schedule_refresh(Life, Now, C) ->
    Ms = Life * 1000,
    Lead = case Life > 120 of
        true -> Ms - 60000;
        false -> Ms div 2
    end,
    C#turn{expires = Now + Ms, refresh_at = Now + Lead}.

closed_state(C) ->
    (lost_state(C))#turn{state = closed}.

lost_state(C) ->
    C#turn{state = failed, refresh_at = infinity, perms = #{}, chans = #{}, by_num = #{}}.

error_response(Kind, Attrs, 401, M, Now, C) when Kind =:= allocate ->
    %% Retry only when the credentials change (RFC 8489 §9.2.5).
    case C#turn.realm of
        undefined -> challenge(Kind, Attrs, M, Now, C);
        _ -> fail(Kind, {error, 401}, Now, C)
    end;
error_response(Kind, Attrs, 438, M, Now, #turn{stale = S} = C) when S < ?MAX_STALE ->
    case webrtc_stun:get(nonce, M) of
        {ok, Nonce} ->
            Realm = webrtc_stun:get(realm, M, C#turn.realm),
            C1 = C#turn{nonce = Nonce, realm = Realm, stale = S + 1},
            case C1#turn.integrity of
                undefined -> fail(Kind, {error, 438}, Now, C);
                _ -> request(Kind, Attrs, Now, set_key(C1))
            end;
        error ->
            fail(Kind, {error, 438}, Now, C)
    end;
error_response(refresh, _Attrs, 437, _M, _Now, #turn{state = closing} = C) ->
    %% Deleting an allocation that no longer exists succeeded (§8.3).
    {closed_state(C), [{event, closed}]};
error_response(Kind, _Attrs, 437, _M, _Now, C) when Kind =/= allocate ->
    {lost_state(C), [{event, {allocation_lost, {error, 437}}}]};
error_response({channel, _, _}, _Attrs, 400, _M, Now, C) ->
    %% The bindings of client and server are out of sync (§12.3): the
    %% allocation cannot be trusted any more, delete it.
    {C1, Acts} = close(Now, C),
    {C1, [{event, {allocation_lost, channel_out_of_sync}} | Acts]};
error_response(allocate, _Attrs, 300, M, Now, C) ->
    %% RFC 8656 §7.4: try the alternate server, with the same credentials.
    case webrtc_stun:get(alternate_server, M) of
        {ok, Alt} -> fail(allocate, {try_alternate, Alt}, Now, C);
        error -> fail(allocate, {error, 300}, Now, C)
    end;
error_response(Kind, _Attrs, Code, _M, Now, C) ->
    fail(Kind, {error, Code}, Now, C).

challenge(Kind, Attrs, M, Now, C) ->
    Realm = webrtc_stun:get(realm, M, undefined),
    Nonce = webrtc_stun:get(nonce, M, undefined),
    Algs = webrtc_stun:get(password_algorithms, M, undefined),
    case {Realm, Nonce} of
        {R, N} when is_binary(R), is_binary(N) ->
            case webrtc_turn_auth:pick_algorithm(N, Algs) of
                {ok, Alg} ->
                    C1 = C#turn{realm = R, nonce = N, pw_algs = Algs, pw_alg = Alg},
                    request(Kind, Attrs, Now, set_key(C1));
                {error, Why} ->
                    fail(Kind, Why, Now, C)
            end;
        _ ->
            fail(Kind, {error, 401}, Now, C)
    end.

set_key(#turn{username = U, realm = R, password = P, pw_alg = Alg} = C) ->
    C#turn{integrity = webrtc_turn_auth:integrity(U, R, P, Alg)}.

fail(allocate, Reason, _Now, C) ->
    fail_allocate(Reason, C);
fail(refresh, _Reason, _Now, #turn{state = closing} = C) ->
    {closed_state(C), [{event, closed}]};
fail(refresh, Reason, _Now, C) ->
    {lost_state(C), [{event, {allocation_lost, Reason}}]};
fail({permission, IP}, Reason, _Now, #turn{perms = P} = C) ->
    {C#turn{perms = maps:remove(IP, P)}, [{event, {permission, IP, Reason}}]};
fail({channel, Peer, N}, Reason, Now, #turn{chans = Ch, by_num = B} = C) ->
    %% The server may hold the binding anyway (a lost response): neither
    %% the number nor the peer goes to another binding before it would
    %% have expired, plus five minutes (§12).
    Reserved = (C#turn.reserved)#{N => {Peer, Now + ?CHANNEL_QUARANTINE}},
    {C#turn{chans = maps:remove(Peer, Ch), by_num = maps:remove(N, B), reserved = Reserved},
        [{event, {channel, Peer, Reason}}]}.

fail_allocate(Reason, C) ->
    {C#turn{state = failed}, [{event, {allocate_failed, Reason}}]}.

%%====================================================================
%% Timers
%%====================================================================

-spec handle_timeout(integer(), client()) -> {client(), [action()]}.
handle_timeout(Now, C) ->
    {Tx, TxActs} = webrtc_stun_tx:handle_timeout(Now, C#turn.tx),
    {C1, A1} = lists:foldl(
        fun
            ({send, _, B}, {CA, AA}) ->
                {CA, AA ++ [{send, B}]};
            ({timeout, _, _, {Kind, _}}, {CA, AA}) ->
                {CB, AB} = fail(Kind, timeout, Now, CA),
                {CB, AA ++ AB}
        end,
        {C#turn{tx = Tx}, []},
        TxActs
    ),
    {C2, A2} = refresh_timers(Now, C1),
    {C2, A1 ++ A2}.

refresh_timers(Now, #turn{state = allocated, expires = Exp} = C) when Now >= Exp ->
    {lost_state(C), [{event, {allocation_lost, expired}}]};
refresh_timers(Now, #turn{state = allocated} = C) ->
    {C1, A1} =
        case C#turn.refresh_at of
            R when R =< Now ->
                request(refresh, refresh_attrs(C), Now, C#turn{refresh_at = infinity});
            _ ->
                {C, []}
        end,
    {C2, A2} = refresh_perms(Now, C1),
    {C3, A3} = refresh_chans(Now, C2),
    {C3, A1 ++ A2 ++ A3};
refresh_timers(_Now, C) ->
    {C, []}.

refresh_attrs(#turn{lifetime_req = L, software = Sw}) ->
    [{lifetime, L} || L =/= undefined] ++ [{software, Sw} || Sw =/= undefined].

refresh_perms(Now, #turn{perms = P} = C) ->
    maps:fold(
        fun
            (IP, #perm{state = installed, refresh_at = R} = Perm, {CA, AA}) when R =< Now ->
                CA1 = CA#turn{perms = (CA#turn.perms)#{IP => Perm#perm{refresh_at = infinity}}},
                {CB, AB} = send_permission(IP, Now, CA1),
                {CB, AA ++ AB};
            (_, _, Acc) ->
                Acc
        end,
        {C, []},
        P
    ).

refresh_chans(Now, #turn{chans = Ch} = C) ->
    maps:fold(
        fun
            (Peer, #chan{state = bound, refresh_at = R, num = N} = Chan, {CA, AA}) when R =< Now ->
                CA1 = CA#turn{chans = (CA#turn.chans)#{Peer => Chan#chan{refresh_at = infinity}}},
                {CB, AB} = send_bind(Peer, N, Now, CA1),
                {CB, AA ++ AB};
            (_, _, Acc) ->
                Acc
        end,
        {C, []},
        Ch
    ).

-spec next_timeout(client()) -> integer() | infinity.
next_timeout(#turn{state = allocated} = C) ->
    Perms = [R || _ := #perm{refresh_at = R} <- C#turn.perms],
    Chans = [R || _ := #chan{refresh_at = R} <- C#turn.chans],
    lists:min([webrtc_stun_tx:next_timeout(C#turn.tx), C#turn.refresh_at, C#turn.expires | Perms ++ Chans]);
next_timeout(C) ->
    webrtc_stun_tx:next_timeout(C#turn.tx).
