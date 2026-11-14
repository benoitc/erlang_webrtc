%% @doc Sans-IO ICE agent (RFC 8445), full or lite, with trickle ICE
%% (RFC 8838), the RFC 8863 failure rule, consent freshness (RFC 7675)
%% and relayed candidates through TURN (RFC 8656).
%%
%% The agent handles one data stream. With BUNDLE and rtcp-mux (the
%% WebRTC case) that is a single component, 1; other components can be
%% configured with the `components' option and given to host
%% candidates.
%%
%% == Driving the agent ==
%%
%% The owner (a transport process) holds the agent state, the UDP
%% sockets and a single timer:
%%
%% ```
%% A0 = webrtc_ice_agent:new(#{role => controlling,
%%                            stun_servers => [{{192,0,2,1}, 3478}]}),
%% {U, P} = webrtc_ice_agent:local_credentials(A0),   % signal them
%% {A1, Acts1} = webrtc_ice_agent:gather([{Sock, {IP, Port}}], Now, A0),
%% {A2, Acts2} = webrtc_ice_agent:set_remote_credentials(RU, RP, Now, A1),
%% {A3, Acts3} = webrtc_ice_agent:add_remote_candidate(<<"candidate:...">>, Now, A2),
%% {A4, Acts4} = webrtc_ice_agent:end_of_candidates(Now, A3),
%% %% every datagram whose first byte is 0..3 (STUN) or 64..79 (TURN
%% %% ChannelData):
%% {A5, Acts5} = webrtc_ice_agent:handle_packet(Sock, {SrcIP, SrcPort}, Bin, Now, A4),
%% %% when the timer fires:
%% {A6, Acts6} = webrtc_ice_agent:handle_timeout(Now, A5),
%% Deadline = webrtc_ice_agent:next_timeout(A6),
%% %% application data (DTLS, SRTP) on the selected pair:
%% {ok, A7, Acts7} = webrtc_ice_agent:send(Data, Now, A6).
%% '''
%%
%% After every call the owner executes the actions in order and re-arms
%% its timer from `next_timeout/1' (an absolute time in the unit of
%% `Now', monotonic milliseconds, or `infinity').
%%
%% Datagrams that are neither STUN nor ChannelData (DTLS, SRTP) are not
%% given to the agent. The owner must drop them unless
%% `is_valid_remote(Socket, Source, Agent)' is true (RFC 8445 §12.2,
%% RFC 8826 §4.2).
%%
%% == Actions ==
%%
%% <ul>
%% <li>`{send, Socket, {IP, Port}, Bin}': send a datagram on the
%%     owner's socket.</li>
%% <li>`{event, Event}'.</li>
%% </ul>
%%
%% == Events ==
%%
%% <ul>
%% <li>`{local_candidate, #ice_cand{}}': a new local candidate to trickle
%%     (`webrtc_ice_candidate:to_sdp/1' gives the attribute value).</li>
%% <li>`{local_candidate_removed, #ice_cand{}}'.</li>
%% <li>`{gathering_state, new | gathering | complete}'.</li>
%% <li>`{connection_state, new | checking | connected | completed |
%%     failed | disconnected | closed}'.</li>
%% <li>`{selected_pair, Local, Remote}'.</li>
%% <li>`{consent_lost, Local, Remote}': consent expired or was revoked;
%%     the agent no longer sends data on that pair.</li>
%% <li>`{role_change, controlling | controlled}'.</li>
%% <li>`{data, {relay, Socket, Server}, Peer, Data}': a non-STUN datagram
%%     relayed by a TURN server; the owner demultiplexes it like a
%%     datagram received from `Peer'.</li>
%% <li>`{turn_error, Server, Reason}'.</li>
%% </ul>
%%
%% Paths (`via()') name where a packet entered or leaves: the owner's
%% socket for host candidates, `{relay, Socket, Server}' for relayed
%% candidates.
-module(webrtc_ice_agent).

-include("webrtc_ice_int.hrl").

-export([
    new/1,
    gather/3,
    add_host/4,
    remove_host/3,
    set_remote_credentials/4,
    add_remote_candidate/3,
    end_of_candidates/2,
    handle_packet/5,
    handle_timeout/2,
    next_timeout/1,
    send/3,
    send/4,
    is_valid_remote/3,
    restart/2,
    restart/3,
    close/2
]).
-export([
    local_credentials/1,
    remote_credentials/1,
    local_candidates/1,
    remote_candidates/1,
    connection_state/1,
    gathering_state/1,
    role/1,
    selected_pair/1,
    selected_pair/2,
    stats/1
]).

-export_type([agent/0, action/0, event/0, via/0, opts/0]).

-opaque agent() :: #ice{}.
-type via() :: term() | {relay, term(), webrtc_ice_candidate:address()}.
-type action() :: {send, term(), webrtc_ice_candidate:address(), binary()} | {event, event()}.
-type event() :: {atom(), term()} | {atom(), term(), term()} | {data, via(), term(), binary()}.
-type opts() :: #{atom() => term()}.

-define(OPTS, [
    {ta, #ice.ta}, {rc, #ice.rc}, {rm, #ice.rm}, {min_rto, #ice.min_rto},
    {max_check_rto, #ice.max_check_rto}, {max_rto, #ice.max_rto}, {max_pairs, #ice.max_pairs},
    {max_remote, #ice.max_remote},
    {pac_timeout, #ice.pac_timeout}, {eoc_timeout, #ice.eoc_timeout},
    {nomination, #ice.nomination}, {nomination_timeout, #ice.nomination_timeout},
    {consent, #ice.consent}, {consent_interval, #ice.consent_interval},
    {consent_expiry, #ice.consent_expiry}, {disconnect_timeout, #ice.disconnect_timeout},
    {keepalive_interval, #ice.keepalive_interval}, {stun_keepalive, #ice.stun_keepalive},
    {stun_servers, #ice.stun_servers}, {turn_servers, #ice.turn_servers},
    {components, #ice.components}
]).

%%====================================================================
%% Construction and configuration
%%====================================================================

%% @doc Create an agent. Options (all optional):
%% `role' (`controlling' default), `lite', `remote_lite', `ufrag',
%% `pwd', `tiebreaker', `seed' (term for `rand:seed_s/2', for
%% reproducible tie-breakers and jitter), `stun_servers' ([Addr]),
%% `turn_servers' ([#{address, username, password}]), `components',
%% `ta' (50 ms), `rc' (7), `rm' (16), `min_rto' (500), `max_check_rto'
%% (2500), `max_rto', `max_pairs' (100), `max_remote' (remote
%% candidates kept, signaled or peer-reflexive, 100), `pac_timeout' (39500),
%% `eoc_timeout' (39500), `nomination' (`best' | `first'),
%% `nomination_timeout' (1000), `consent' (true), `consent_interval'
%% (5000), `consent_expiry' (30000), `disconnect_timeout' (10000),
%% `keepalive_interval' (15000), `stun_keepalive' (15000).
-spec new(opts()) -> agent().
new(Opts) ->
    Rand =
        case maps:find(seed, Opts) of
            {ok, Seed} -> rand:seed_s(exsss, Seed);
            error ->
                <<A:32, B:32, C:32>> = crypto:strong_rand_bytes(12),
                rand:seed_s(exsss, {A, B, C})
        end,
    {T, Rand1} = rand:uniform_s(1 bsl 64, Rand),
    Lite = maps:get(lite, Opts, false),
    RemoteLite = maps:get(remote_lite, Opts, false),
    Role =
        if
            Lite -> controlled;
            RemoteLite -> controlling;
            true -> maps:get(role, Opts, controlling)
        end,
    Ufrag = maps:get(ufrag, Opts, webrtc_ice_candidate:random_ufrag()),
    Pwd = maps:get(pwd, Opts, webrtc_ice_candidate:random_pwd()),
    check_credentials(Ufrag, Pwd),
    S0 = #ice{
        lite = Lite,
        remote_lite = RemoteLite,
        role = Role,
        tiebreaker = maps:get(tiebreaker, Opts, T - 1),
        rand = Rand1,
        ufrag = Ufrag,
        pwd = Pwd,
        tx = webrtc_stun_tx:new()
    },
    S1 = lists:foldl(
        fun({K, Pos}, Acc) ->
            case maps:find(K, Opts) of
                {ok, V} -> setelement(Pos, Acc, V);
                error -> Acc
            end
        end,
        S0,
        ?OPTS
    ),
    case length(S1#ice.stun_servers) + length(S1#ice.turn_servers) =< 8 of
        true -> ok;
        false -> error({badarg, too_many_servers})
    end,
    S1#ice{tx = webrtc_stun_tx:new(#{rto => S1#ice.min_rto, min_rto => S1#ice.min_rto,
                                    rc => S1#ice.rc, rm => S1#ice.rm, max_rto => S1#ice.max_rto})}.

check_credentials(U, P) ->
    case webrtc_ice_candidate:valid_ufrag(U) andalso webrtc_ice_candidate:valid_pwd(P) of
        true -> ok;
        false -> error({badarg, bad_credentials})
    end.

%% @doc Add the host candidates (`{Socket, {IP, Port}}' or
%% `{Socket, {IP, Port}, Component}', one socket per host candidate) and
%% start gathering server-reflexive and relayed candidates.
-spec gather([tuple()], integer(), agent()) -> {agent(), [action()]}.
gather(Hosts, Now, S) ->
    {S1, Acts} = webrtc_ice_gather:add_hosts(Hosts, Now, S),
    finish(Now, S1, Acts).

%% @doc Add one host candidate later (new interface).
-spec add_host(term(), webrtc_ice_candidate:address(), integer(), agent()) -> {agent(), [action()]}.
add_host(Sock, Addr, Now, S) ->
    gather([{Sock, Addr}], Now, S).

%% @doc A socket went away (network change): remove its candidates.
-spec remove_host(term(), integer(), agent()) -> {agent(), [action()]}.
remove_host(Sock, Now, S) ->
    {S1, Acts} = webrtc_ice_gather:remove_socket(Sock, Now, S),
    finish(Now, S1, Acts).

%% @doc Remote ufrag and password (RFC 8839 §5.4). Starts the checks
%% and the RFC 8863 PAC timer. Changing them requires `restart/2,3'.
-spec set_remote_credentials(binary(), binary(), integer(), agent()) -> {agent(), [action()]}.
set_remote_credentials(U, P, Now, #ice{remote_ufrag = undefined} = S) ->
    check_credentials(U, P),
    S1 = webrtc_ice_checklist:initial_states(S#ice{remote_ufrag = U, remote_pwd = P, started_at = Now}),
    {S2, Acts} = webrtc_ice_responder:replay_early(Now, S1),
    finish(Now, S2, Acts);
set_remote_credentials(U, P, Now, #ice{remote_ufrag = U, remote_pwd = P} = S) ->
    finish(Now, S, []);
set_remote_credentials(_U, _P, _Now, _S) ->
    error(restart_required).

%% @doc Add a remote candidate (record or `a=candidate' value). Ignored
%% after end-of-candidates (RFC 8838 §14), for an unknown component,
%% or when its `ufrag' extension names another session.
-spec add_remote_candidate(#ice_cand{} | binary(), integer(), agent()) ->
    {agent(), [action()]} | {error, term()}.
add_remote_candidate(Bin, Now, S) when is_binary(Bin) ->
    case webrtc_ice_candidate:from_sdp(Bin) of
        {ok, C} -> add_remote_candidate(C, Now, S);
        {error, _} = E -> E
    end;
add_remote_candidate(#ice_cand{}, Now, #ice{remote_eoc = true} = S) ->
    finish(Now, S, []);
add_remote_candidate(#ice_cand{component = Comp} = C0, Now, S) ->
    C = C0#ice_cand{base = undefined, socket = undefined, server = undefined},
    Ufrag = proplists:get_value(<<"ufrag">>, C#ice_cand.extensions),
    Skip = not lists:member(Comp, S#ice.components) orelse
        map_size(S#ice.remote) >= S#ice.max_remote orelse
        (Ufrag =/= undefined andalso S#ice.remote_ufrag =/= undefined andalso Ufrag =/= S#ice.remote_ufrag),
    case Skip of
        true ->
            finish(Now, S, []);
        false ->
            case webrtc_ice_checklist:find_remote(Comp, webrtc_ice_candidate:transport_address(C), S) of
                {ok, Id} ->
                    finish(Now, upgrade_prflx(Id, C, S), []);
                error ->
                    {Id, S1} = webrtc_ice_checklist:add_remote(C, S),
                    S2 = webrtc_ice_checklist:pair_new_remote(Id, S1),
                    {S3, Acts} = webrtc_ice_relay:permit(C, Now, S2),
                    finish(Now, S3, Acts)
            end
    end.

%% A signaled candidate already learned as peer-reflexive takes its
%% signaled type, priority and foundation (RFC 8445 §7.3.1.3, RFC 8838
%% §11).
upgrade_prflx(Id, C, S) ->
    case webrtc_ice_checklist:remote(Id, S) of
        #ice_cand{type = prflx} ->
            S1 = S#ice{remote = (S#ice.remote)#{Id => C}},
            webrtc_ice_checklist:recompute_priorities(S1);
        _ ->
            S
    end.

-spec end_of_candidates(integer(), agent()) -> {agent(), [action()]}.
end_of_candidates(Now, S) ->
    finish(Now, S#ice{remote_eoc = true}, []).

%%====================================================================
%% Packets
%%====================================================================

%% @doc A datagram received on `Sock' from `From'.
-spec handle_packet(term(), webrtc_ice_candidate:address(), binary(), integer(), agent()) ->
    {agent(), [action()]}.
handle_packet(_Sock, _From, _Bin, _Now, #ice{state = closed} = S) ->
    {S, []};
handle_packet(Sock, From, <<B, _/binary>> = Bin, Now, S) when B >= 64, B =< 79 ->
    case webrtc_ice_relay:turn_key(Sock, From, S) of
        {ok, Key} -> turn_in(Key, Bin, Now, S);
        error -> {?INC(dropped, S), []}
    end;
handle_packet(Sock, From, Bin, Now, S) ->
    {S1, Acts} = stun_in(Sock, From, Bin, Now, S),
    finish(Now, S1, Acts).

turn_in(Key, Bin, Now, S) ->
    {S1, Acts, Deliver} = webrtc_ice_relay:turn_packet(Key, Bin, Now, S),
    {S2, Acts2} = deliver(Deliver, Now, S1),
    finish(Now, S2, Acts ++ Acts2).

deliver(Deliver, Now, S) ->
    lists:foldl(
        fun({Via, Peer, Data}, {SA, AA}) ->
            case webrtc_stun:is_stun(Data) of
                true ->
                    {SB, AB} = stun_in(Via, Peer, Data, Now, SA),
                    {SB, AA ++ AB};
                false ->
                    {SA, AA ++ [{event, {data, Via, Peer, Data}}]}
            end
        end,
        {S, []},
        Deliver
    ).

stun_in(Via, From, Bin, Now, S) ->
    case webrtc_stun:decode(Bin) of
        {ok, #stun{method = binding, class = request} = M} ->
            webrtc_ice_responder:handle_request(Via, From, M, Bin, Now, S);
        {ok, #stun{method = binding, class = C, txid = TxId} = M} when C =:= success; C =:= error ->
            response_in(TxId, Via, From, M, Bin, Now, S);
        {ok, #stun{method = binding, class = indication}} ->
            {?INC(indications_received, S), []};
        {ok, #stun{}} ->
            case relayed(Via) of
                true ->
                    {?INC(dropped, S), []};
                false ->
                    case webrtc_ice_relay:turn_key(Via, From, S) of
                        {ok, Key} ->
                            {S1, Acts, Deliver} = webrtc_ice_relay:turn_packet(Key, Bin, Now, S),
                            {S2, Acts2} = deliver(Deliver, Now, S1),
                            {S2, Acts ++ Acts2};
                        error ->
                            {?INC(dropped, S), []}
                    end
            end;
        {error, _} ->
            {?INC(dropped, S), []}
    end.

relayed({relay, _, _}) -> true;
relayed(_) -> false.

response_in(TxId, Via, From, M, Bin, Now, S) ->
    case webrtc_ice_consent:match(TxId, S) of
        none ->
            case webrtc_stun_tx:lookup(TxId, S#ice.tx) of
                {ok, _Dest, {check, _, _} = Meta} ->
                    webrtc_ice_conncheck:handle_response(TxId, Meta, Via, From, M, Bin, Now, S);
                {ok, {Via, From}, {srflx, _, _, _} = Job} ->
                    {ok, _, Tx} = webrtc_stun_tx:response(TxId, Now, S#ice.tx),
                    webrtc_ice_gather:srflx_response(Job, Via, From, M, Now, S#ice{tx = Tx});
                _ ->
                    {?INC(dropped, S), []}
            end;
        Target ->
            webrtc_ice_consent:response(Target, Via, From, M, Bin, Now, S)
    end.

%%====================================================================
%% Timers
%%====================================================================

-spec handle_timeout(integer(), agent()) -> {agent(), [action()]}.
handle_timeout(_Now, #ice{state = closed} = S) ->
    {S, []};
handle_timeout(Now, S) ->
    {Tx, TxActs} = webrtc_stun_tx:handle_timeout(Now, S#ice.tx),
    {S1, A1} = lists:foldl(fun(A, Acc) -> tx_action(A, Now, Acc) end, {S#ice{tx = Tx}, []}, TxActs),
    {S2, A2, Deliver} = webrtc_ice_relay:turn_timeout(Now, S1),
    {S3, A3} = deliver(Deliver, Now, S2),
    {S4, A4} = pace(Now, S3),
    {S5, A5} = webrtc_ice_consent:tick(Now, S4),
    {S6, A6} = webrtc_ice_gather:stun_refresh(Now, S5),
    finish(Now, S6, A1 ++ A2 ++ A3 ++ A4 ++ A5 ++ A6).

tx_action({send, {Via, To}, Bin}, Now, {S, Acts}) ->
    {S1, A} = webrtc_ice_gather:route(Via, To, Bin, Now, S),
    {S1, Acts ++ A};
tx_action({timeout, TxId, _Dest, {check, _, _} = Meta}, Now, {S, Acts}) ->
    {S1, A} = webrtc_ice_conncheck:check_timeout(TxId, Meta, Now, S),
    {S1, Acts ++ A};
tx_action({timeout, _TxId, _Dest, {srflx, _, _, _} = Job}, Now, {S, Acts}) ->
    {S1, A} = webrtc_ice_gather:srflx_timeout(Job, Now, S),
    {S1, Acts ++ A}.

%% One new transaction per Ta (RFC 8445 §6.1.4.2, §14.2): triggered
%% checks first, then gathering, then ordinary checks.
pace(Now, #ice{ta_at = At} = S) when At =< Now ->
    Triggered = S#ice.triggered =/= [] andalso webrtc_ice_checklist:has_check(S),
    Job = webrtc_ice_gather:has_job(S),
    case Triggered orelse not Job of
        true ->
            case webrtc_ice_checklist:next_check(S) of
                {Id, _Kind, S1} -> webrtc_ice_conncheck:send_check(Id, Now, S1#ice{last_paced = Now});
                none when Job -> webrtc_ice_gather:run_job(Now, S#ice{last_paced = Now});
                none -> {S, []}
            end;
        false ->
            webrtc_ice_gather:run_job(Now, S#ice{last_paced = Now})
    end;
pace(_Now, S) ->
    {S, []}.

-spec next_timeout(agent()) -> integer() | infinity.
next_timeout(#ice{state = closed}) ->
    infinity;
next_timeout(S) ->
    lists:min([
        webrtc_stun_tx:next_timeout(S#ice.tx),
        webrtc_ice_gather:next_timeout(S),
        webrtc_ice_consent:next_timeout(S),
        S#ice.ta_at,
        S#ice.recheck_at
    ]).

%%====================================================================
%% State evaluation, run after every input
%%====================================================================

finish(Now, S0, Acts0) ->
    {S1, Acts1} = nominate(Now, S0),
    S2 = evaluate(Now, S1),
    New = webrtc_ice_session:derive(Now, S2),
    StateEv =
        case New =:= S2#ice.state of
            true -> [];
            false -> [{event, {connection_state, New}}]
        end,
    S3 = S2#ice{state = New},
    Work = webrtc_ice_checklist:has_check(S3) orelse webrtc_ice_gather:has_job(S3),
    TaAt =
        case {Work, S3#ice.last_paced} of
            {false, _} -> infinity;
            {true, undefined} -> Now;
            {true, L} -> max(Now, L + S3#ice.ta)
        end,
    {S3#ice{ta_at = TaAt, recheck_at = webrtc_ice_session:recheck_at(Now, S3)}, Acts0 ++ Acts1 ++ StateEv}.

nominate(Now, S) ->
    webrtc_ice_session:nominate(Now, S).

evaluate(Now, S) ->
    webrtc_ice_session:evaluate(Now, S).

%%====================================================================
%% Data
%%====================================================================

-spec send(binary(), integer(), agent()) -> {ok, agent(), [action()]} | {error, term()}.
send(Data, Now, S) ->
    send(1, Data, Now, S).

%% @doc Send application data on the selected pair of `Comp' (or the
%% best valid pair before nomination, RFC 8445 §12.1, or the pair kept
%% across an ICE restart). Fails when no pair has consent.
-spec send(1..256, binary(), integer(), agent()) -> {ok, agent(), [action()]} | {error, term()}.
send(_Comp, _Data, _Now, #ice{state = closed}) ->
    {error, closed};
send(Comp, Data, Now, S) ->
    webrtc_ice_session:send_data(Comp, Data, Now, S).

%% @doc True when packets from `From' on `Via' belong to a validated
%% pair (or a pair the peer authenticated with a check) that still has
%% consent. Non-ICE traffic from other sources must be dropped.
-spec is_valid_remote(via(), webrtc_ice_candidate:address(), agent()) -> boolean().
is_valid_remote(Via, From, S) ->
    webrtc_ice_session:is_valid_remote(Via, From, S).

%% @doc ICE restart (RFC 8445 §9) with new random credentials.
-spec restart(integer(), agent()) -> {agent(), [action()]}.
restart(Now, S) ->
    restart(#{}, Now, S).

%% @doc ICE restart. `Opts' may give `ufrag' and `pwd'. The selected
%% pairs stay usable (with consent checks on the old credentials) until
%% the new session selects its own. Local candidates are kept; signal
%% them again with `local_candidates/1'.
-spec restart(map(), integer(), agent()) -> {agent(), [action()]}.
restart(Opts, Now, S) ->
    U = maps:get(ufrag, Opts, webrtc_ice_candidate:random_ufrag()),
    P = maps:get(pwd, Opts, webrtc_ice_candidate:random_pwd()),
    check_credentials(U, P),
    finish(Now, webrtc_ice_session:restart(U, P, Now, S), []).

%% @doc Close the agent: TURN allocations are deleted, nothing is sent
%% afterwards.
-spec close(integer(), agent()) -> {agent(), [action()]}.
close(_Now, #ice{state = closed} = S) ->
    {S, []};
close(Now, S) ->
    {S1, Acts} = webrtc_ice_relay:close(Now, S),
    {S1#ice{state = closed, ta_at = infinity, recheck_at = infinity},
        Acts ++ [{event, {connection_state, closed}}]}.

%%====================================================================
%% Accessors
%%====================================================================

-spec local_credentials(agent()) -> {binary(), binary()}.
local_credentials(#ice{ufrag = U, pwd = P}) -> {U, P}.

-spec remote_credentials(agent()) -> {binary(), binary()} | undefined.
remote_credentials(#ice{remote_ufrag = undefined}) -> undefined;
remote_credentials(#ice{remote_ufrag = U, remote_pwd = P}) -> {U, P}.

%% @doc Local candidates to signal (peer-reflexive ones excluded).
-spec local_candidates(agent()) -> [#ice_cand{}].
local_candidates(#ice{local = L}) ->
    [C || _ := #ice_cand{type = T} = C <- maps:iterator(L, ordered), T =/= prflx].

-spec remote_candidates(agent()) -> [#ice_cand{}].
remote_candidates(#ice{remote = R}) ->
    [C || _ := C <- maps:iterator(R, ordered)].

-spec connection_state(agent()) -> atom().
connection_state(#ice{state = St}) -> St.

-spec gathering_state(agent()) -> new | gathering | complete.
gathering_state(#ice{gather_state = G}) -> G.

-spec role(agent()) -> controlling | controlled.
role(#ice{role = R}) -> R.

-spec selected_pair(agent()) -> {#ice_cand{}, #ice_cand{}} | undefined.
selected_pair(S) -> selected_pair(1, S).

-spec selected_pair(1..256, agent()) -> {#ice_cand{}, #ice_cand{}} | undefined.
selected_pair(Comp, S) ->
    case maps:find(Comp, S#ice.selected) of
        {ok, Id} ->
            #pair{local = L, remote = R} = webrtc_ice_checklist:pair(Id, S),
            {webrtc_ice_checklist:local(L, S), webrtc_ice_checklist:remote(R, S)};
        error ->
            undefined
    end.

%% @doc Counters and the candidate pairs with their state, validity,
%% nomination, RTT and request/response counts.
-spec stats(agent()) -> map().
stats(S) ->
    webrtc_ice_session:stats(S).
