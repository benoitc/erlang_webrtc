%% @private
%% @doc Local candidates of the ICE agent: host candidates supplied by
%% the owner, server-reflexive candidates from STUN servers (RFC 8445
%% §5.1.1.2), relayed candidates from TURN allocations (RFC 8656), and
%% the routing of outgoing packets through a host socket or a TURN
%% allocation.
%%
%% Integration choice: the agent owns one `webrtc_turn_client' state per
%% (host socket, TURN server), keyed `{Socket, ServerAddr}'. A relayed
%% candidate is reached through the path `{relay, Socket, ServerAddr}':
%% checks and data sent from it are wrapped by the TURN client and sent
%% to the server over the host socket; data relayed by the server is
%% unwrapped and handed back to the agent with that path.
-module(webrtc_ice_gather).

-include("webrtc_ice_int.hrl").

-export([
    add_hosts/3,
    remove_socket/3,
    remove_locals/3,
    run_job/2,
    has_job/1,
    route/5,
    via/2,
    base_by_via/2,
    srflx_response/6,
    srflx_timeout/3,
    turn_key/3,
    turn_packet/4,
    turn_timeout/2,
    permit/3,
    bind_channel/3,
    stun_refresh/2,
    close/2,
    next_timeout/1,
    maybe_complete/1
]).

-type via() :: term() | {relay, term(), webrtc_ice_candidate:address()}.

%%--------------------------------------------------------------------
%% Host candidates
%%--------------------------------------------------------------------

%% @doc Add host candidates. Each spec is `{Socket, {IP, Port}}' or
%% `{Socket, {IP, Port}, Component}'. Local preferences follow RFC 8421
%% for the batch; later additions get lower, still unique, values.
-spec add_hosts([tuple()], integer(), #ice{}) -> {#ice{}, [term()]}.
add_hosts(Specs0, Now, S0) ->
    Specs = [norm(Sp) || Sp <- Specs0],
    Prefs = webrtc_ice_candidate:local_preferences([IP || {_, {IP, _}, _} <- Specs]),
    Ordered = order_specs(Prefs, Specs),
    {S1, Acts} = lists:foldl(
        fun({Spec, Rank}, {SA, AA}) ->
            {SB, AB} = add_host(Spec, S0#ice.host_rank + Rank, Now, SA),
            {SB, AA ++ AB}
        end,
        {S0, []},
        lists:zip(Ordered, lists:seq(0, length(Ordered) - 1))
    ),
    S2 = S1#ice{host_rank = S0#ice.host_rank + length(Ordered)},
    start_gathering(S2, Acts).

norm({Sock, {IP, Port}}) -> {Sock, {IP, Port}, 1};
norm({Sock, {IP, Port}, Comp}) -> {Sock, {IP, Port}, Comp}.

order_specs([], _Specs) ->
    [];
order_specs([{IP, _} | Rest], Specs) ->
    {value, Spec} = lists:search(fun({_, {I, _}, _}) -> I =:= IP end, Specs),
    [Spec | order_specs(Rest, lists:delete(Spec, Specs))].

add_host({Sock, {IP, Port}, Comp}, Rank, _Now, S) ->
    Cand = #ice_cand{
        foundation = webrtc_ice_candidate:foundation(host, IP, undefined, udp),
        component = Comp,
        priority = webrtc_ice_candidate:priority(host, webrtc_ice_candidate:local_preference(Rank, 0), Comp),
        address = IP,
        port = Port,
        type = host,
        base = {IP, Port},
        socket = Sock
    },
    {Id, S1} = add_local(Cand, S#ice.next_id, S),
    Jobs = jobs(Id, Cand, S1),
    S2 = S1#ice{gather_queue = S1#ice.gather_queue ++ Jobs},
    {webrtc_ice_checklist:pair_new_local(Id, S2), [{event, {local_candidate, Cand}}]}.

add_local(Cand, Id, #ice{local = L} = S) ->
    {Id, S#ice{next_id = Id + 1, local = L#{Id => Cand}}}.

jobs(_Id, _Cand, #ice{lite = true}) ->
    [];
jobs(Id, #ice_cand{address = IP}, #ice{stun_servers = Stun, turn_servers = Turn}) ->
    Fam = webrtc_ice_candidate:family(IP),
    NStun = length(Stun),
    [{srflx, Id, Srv, I} || {I, {SIP, _} = Srv} <- enum(Stun), webrtc_ice_candidate:family(SIP) =:= Fam] ++
        [{relay, Id, Cfg, NStun + I}
         || {I, #{address := {TIP, _}} = Cfg} <- enum(Turn), webrtc_ice_candidate:family(TIP) =:= Fam].

enum(L) -> lists:zip(lists:seq(0, length(L) - 1), L).

start_gathering(#ice{gather_queue = [], gather_pending = []} = S, Acts) ->
    case S#ice.gather_state of
        complete -> {S, Acts};
        _ -> {S#ice{gather_state = complete}, Acts ++ gstate(S, gathering) ++ [{event, {gathering_state, complete}}]}
    end;
start_gathering(S, Acts) ->
    {S#ice{gather_state = gathering}, Acts ++ gstate(S, gathering)}.

gstate(#ice{gather_state = gathering}, gathering) -> [];
gstate(_, St) -> [{event, {gathering_state, St}}].

%% @doc Emit `{gathering_state, complete}' once every job is done.
-spec maybe_complete(#ice{}) -> {#ice{}, [term()]}.
maybe_complete(#ice{gather_state = gathering, gather_queue = [], gather_pending = []} = S) ->
    {S#ice{gather_state = complete}, [{event, {gathering_state, complete}}]};
maybe_complete(S) ->
    {S, []}.

%%--------------------------------------------------------------------
%% Removal (network change)
%%--------------------------------------------------------------------

%% @doc The owner's socket went away: remove its host candidate and
%% every candidate derived from it.
-spec remove_socket(term(), integer(), #ice{}) -> {#ice{}, [term()]}.
remove_socket(Sock, Now, S) ->
    Ids = [Id || Id := #ice_cand{socket = So} <- S#ice.local, So =:= Sock],
    Turn = maps:filter(fun({So, _}, _) -> So =/= Sock end, S#ice.turn),
    Pending = [J || J <- S#ice.gather_pending, not lists:member(element(2, J), Ids)],
    Queue = [J || J <- S#ice.gather_queue, not lists:member(element(2, J), Ids)],
    Refresh = maps:filter(fun({H, _}, _) -> not lists:member(H, Ids) end, S#ice.stun_refresh),
    S1 = S#ice{turn = Turn, gather_pending = Pending, gather_queue = Queue, stun_refresh = Refresh},
    {S2, Acts} = remove_locals(Ids, Now, S1),
    {S3, Acts2} = maybe_complete(S2),
    {S3, Acts ++ Acts2}.

%% @doc Remove local candidates (and candidates based on them), their
%% pairs and transactions. Selected pairs that disappear are dropped.
-spec remove_locals([pos_integer()], integer(), #ice{}) -> {#ice{}, [term()]}.
remove_locals([], _Now, S) ->
    {S, []};
remove_locals(Ids0, _Now, S) ->
    Ids = lists:usort(Ids0 ++ [Id || Id := B <- S#ice.base_of, lists:member(B, Ids0)]),
    Removed = [C || Id <- Ids, #ice_cand{} = C <- [maps:get(Id, S#ice.local, undefined)]],
    {Gone, S1} = webrtc_ice_checklist:remove_pairs(fun(#pair{local = L}) -> lists:member(L, Ids) end, S),
    Tx = lists:foldl(
        fun(#pair{txid = T}, Acc) when is_binary(T) -> webrtc_stun_tx:remove(T, Acc);
           (_, Acc) -> Acc
        end,
        S1#ice.tx,
        Gone
    ),
    GoneIds = [P#pair.id || P <- Gone],
    Selected = maps:filter(fun(_, PId) -> not lists:member(PId, GoneIds) end, S1#ice.selected),
    Prev =
        case S1#ice.prev of
            #prev{pairs = PP} = Pv ->
                Pv#prev{pairs = maps:filter(fun(_, {#pair{local = L}, _}) -> not lists:member(L, Ids) end, PP)};
            undefined ->
                undefined
        end,
    Nominating =
        case lists:member(S1#ice.nominating, GoneIds) of
            true -> undefined;
            false -> S1#ice.nominating
        end,
    S2 = S1#ice{
        local = maps:without(Ids, S1#ice.local),
        base_of = maps:without(Ids, S1#ice.base_of),
        tx = Tx,
        selected = Selected,
        prev = Prev,
        nominating = Nominating
    },
    {S2, [{event, {local_candidate_removed, C}} || C <- Removed]}.

%%--------------------------------------------------------------------
%% Gathering jobs, paced by Ta
%%--------------------------------------------------------------------

-spec has_job(#ice{}) -> boolean().
has_job(#ice{gather_queue = Q}) -> Q =/= [].

-spec run_job(integer(), #ice{}) -> {#ice{}, [term()]}.
run_job(Now, #ice{gather_queue = [Job | Rest]} = S) ->
    start_job(Job, Now, S#ice{gather_queue = Rest, gather_pending = [Job | S#ice.gather_pending]}).

start_job({srflx, HostId, Server, _Idx} = Job, Now, S) ->
    case webrtc_ice_checklist:local(HostId, S) of
        #ice_cand{socket = Sock} ->
            send_binding(Job, Sock, Server, Now, S);
        undefined ->
            job_done(Job, S)
    end;
start_job({relay, HostId, #{address := Server} = Cfg, _Idx} = Job, Now, S) ->
    case webrtc_ice_checklist:local(HostId, S) of
        #ice_cand{socket = Sock} ->
            Opts = maps:merge(#{server => Server, rto => gather_rto(S)}, maps:without([address], Cfg)),
            C0 = webrtc_turn_client:new(Opts),
            {C1, TActs} = webrtc_turn_client:allocate(Now, C0),
            Entry = #{client => C1, host => HostId, job => Job, relay => undefined, srflx => undefined},
            Key = {Sock, Server},
            {S1, Acts, _} = turn_actions(Key, TActs, Now, S#ice{turn = (S#ice.turn)#{Key => Entry}}),
            {S1, Acts};
        undefined ->
            job_done(Job, S)
    end.

%% RFC 8445 §14.3: RTO = MAX(500ms, Ta * Num-Of-Cands).
gather_rto(#ice{ta = Ta, gather_queue = Q, gather_pending = P, min_rto = Min}) ->
    max(Min, Ta * (length(Q) + length(P))).

send_binding(Job, Sock, {SIP, _} = Server, Now, S) ->
    Msg = webrtc_stun:request(binding, []),
    Bin = webrtc_stun:encode(Msg, #{fingerprint => true}),
    {Tx, TxActs} = webrtc_stun_tx:send(
        Msg#stun.txid, {Sock, Server}, Bin,
        #{key => SIP, meta => Job, rto => webrtc_stun_tx:rto(SIP, Now, S#ice.tx)},
        Now, S#ice.tx
    ),
    {S#ice{tx = Tx}, [{send, So, To, B} || {send, {So, To}, B} <- TxActs]}.

job_done(Job, S) ->
    maybe_complete(S#ice{gather_pending = lists:delete(Job, S#ice.gather_pending)}).

%% @doc Binding response from a STUN server (`Job' is the transaction
%% metadata).
-spec srflx_response(tuple(), term(), webrtc_ice_candidate:address(), #stun{}, integer(), #ice{}) ->
    {#ice{}, [term()]}.
srflx_response({srflx, HostId, Server, Idx} = Job, Sock, From, #stun{class = Class} = M, Now, S) ->
    Host = webrtc_ice_checklist:local(HostId, S),
    Mapped =
        case webrtc_stun:get(xor_mapped_address, M) of
            {ok, A} -> {ok, A};
            error -> webrtc_stun:get(mapped_address, M)
        end,
    S1 = case lists:member(Job, S#ice.gather_pending) of
        true -> S#ice{gather_pending = lists:delete(Job, S#ice.gather_pending)};
        false -> S
    end,
    {S2, Acts} =
        case {Host, Class, Mapped} of
            {#ice_cand{socket = Sock}, success, {ok, {MIP, MPort}}} when From =:= Server ->
                Refresh = (S1#ice.stun_refresh)#{{HostId, Job} => Now + S1#ice.stun_keepalive},
                add_srflx(HostId, Host, Server, Idx, {MIP, MPort}, S1#ice{stun_refresh = Refresh});
            _ ->
                {S1, []}
        end,
    {S3, Acts2} = maybe_complete(S2),
    {S3, Acts ++ Acts2}.

add_srflx(HostId, #ice_cand{} = Host, {SIP, _}, Idx, {MIP, MPort}, S) ->
    HostLP = (Host#ice_cand.priority bsr 8) band 16#FFFF,
    Comp = Host#ice_cand.component,
    Cand = #ice_cand{
        foundation = webrtc_ice_candidate:foundation(srflx, Host#ice_cand.address, SIP, udp),
        component = Comp,
        priority = webrtc_ice_candidate:priority(srflx, max(0, HostLP - Idx), Comp),
        address = MIP,
        port = MPort,
        type = srflx,
        related_address = Host#ice_cand.address,
        related_port = Host#ice_cand.port,
        base = Host#ice_cand.base,
        socket = Host#ice_cand.socket,
        server = undefined
    },
    add_derived(Cand, HostId, S).

%% Trickle ICE: a redundant candidate is ignored regardless of its
%% priority (RFC 8838 §9).
add_derived(Cand, BaseId, S) ->
    case webrtc_ice_candidate:is_redundant(Cand, maps:values(S#ice.local)) of
        true ->
            {S, []};
        false ->
            {Id, S1} = add_local(Cand, S#ice.next_id, S),
            S2 = S1#ice{base_of = (S1#ice.base_of)#{Id => BaseId}},
            {webrtc_ice_checklist:pair_new_local(Id, S2), [{event, {local_candidate, Cand}}]}
    end.

-spec srflx_timeout(tuple(), integer(), #ice{}) -> {#ice{}, [term()]}.
srflx_timeout(Job, _Now, S) ->
    job_done(Job, S).

%% @doc Keep server-reflexive bindings alive until ICE completes
%% (RFC 8445 §5.1.1.4).
-spec stun_refresh(integer(), #ice{}) -> {#ice{}, [term()]}.
stun_refresh(_Now, #ice{cl_state = St} = S) when St =/= running ->
    {S#ice{stun_refresh = #{}}, []};
stun_refresh(Now, #ice{stun_refresh = R} = S) ->
    maps:fold(
        fun
            ({HostId, {srflx, _, Server, _} = Job} = K, At, {SA, AA}) when At =< Now ->
                case webrtc_ice_checklist:local(HostId, SA) of
                    #ice_cand{socket = Sock} ->
                        SA1 = SA#ice{stun_refresh = maps:remove(K, SA#ice.stun_refresh)},
                        {SB, AB} = send_binding(Job, Sock, Server, Now, SA1),
                        {SB, AA ++ AB};
                    undefined ->
                        {SA#ice{stun_refresh = maps:remove(K, SA#ice.stun_refresh)}, AA}
                end;
            (_, _, Acc) ->
                Acc
        end,
        {S, []},
        R
    ).

%%--------------------------------------------------------------------
%% Routing
%%--------------------------------------------------------------------

%% @doc Path of a local base candidate: its socket, or
%% `{relay, Socket, Server}' for a relayed candidate.
-spec via(#ice_cand{}, #ice{}) -> via().
via(#ice_cand{type = relay, socket = Sock, server = Server}, _S) -> {relay, Sock, Server};
via(#ice_cand{socket = Sock}, _S) -> Sock.

%% @doc Local base candidate receiving on `Via'.
-spec base_by_via(via(), #ice{}) -> {ok, pos_integer()} | error.
base_by_via({relay, Sock, Server}, #ice{local = L}) ->
    first([Id || Id := #ice_cand{type = relay, socket = So, server = Sv} <- L, So =:= Sock, Sv =:= Server]);
base_by_via(Sock, #ice{local = L}) ->
    first([Id || Id := #ice_cand{type = host, socket = So} <- L, So =:= Sock]).

first([X | _]) -> {ok, X};
first([]) -> error.

%% @doc Send `Bin' to `To' from the path `Via'.
-spec route(via(), webrtc_ice_candidate:address(), binary(), integer(), #ice{}) -> {#ice{}, [term()]}.
route({relay, Sock, Server}, To, Bin, Now, S) ->
    Key = {Sock, Server},
    case maps:find(Key, S#ice.turn) of
        {ok, #{client := C} = E} ->
            {C1, TActs} = webrtc_turn_client:send(To, Bin, Now, C),
            {S1, Acts, _} = turn_actions(Key, TActs, Now, S#ice{turn = (S#ice.turn)#{Key => E#{client => C1}}}),
            {S1, Acts};
        error ->
            {S, []}
    end;
route(Sock, To, Bin, _Now, S) ->
    {S, [{send, Sock, To, Bin}]}.

%%--------------------------------------------------------------------
%% TURN clients
%%--------------------------------------------------------------------

-spec turn_key(term(), webrtc_ice_candidate:address(), #ice{}) -> {ok, term()} | error.
turn_key(Sock, From, #ice{turn = T}) ->
    case maps:is_key({Sock, From}, T) of
        true -> {ok, {Sock, From}};
        false -> error
    end.

%% @doc Datagram from a TURN server. Returns the relayed datagrams
%% `{Via, Peer, Data}' for the agent to process.
-spec turn_packet(term(), binary(), integer(), #ice{}) -> {#ice{}, [term()], [tuple()]}.
turn_packet(Key, Bin, Now, S) ->
    #{client := C} = E = maps:get(Key, S#ice.turn),
    {C1, TActs} = webrtc_turn_client:handle_packet(Bin, Now, C),
    turn_actions(Key, TActs, Now, S#ice{turn = (S#ice.turn)#{Key => E#{client => C1}}}).

-spec turn_timeout(integer(), #ice{}) -> {#ice{}, [term()], [tuple()]}.
turn_timeout(Now, S) ->
    maps:fold(
        fun(Key, #{client := C}, {SA, AA, DA}) ->
            case webrtc_turn_client:next_timeout(C) =< Now of
                true ->
                    case maps:find(Key, SA#ice.turn) of
                        {ok, #{client := C0} = E} ->
                            {C1, TActs} = webrtc_turn_client:handle_timeout(Now, C0),
                            SA1 = SA#ice{turn = (SA#ice.turn)#{Key => E#{client => C1}}},
                            {SB, AB, DB} = turn_actions(Key, TActs, Now, SA1),
                            {SB, AA ++ AB, DA ++ DB};
                        error ->
                            {SA, AA, DA}
                    end;
                false ->
                    {SA, AA, DA}
            end
        end,
        {S, [], []},
        S#ice.turn
    ).

turn_actions({Sock, Server} = Key, TActs, Now, S) ->
    lists:foldl(
        fun
            ({send, B}, {SA, AA, DA}) ->
                {SA, AA ++ [{send, Sock, Server, B}], DA};
            ({event, Ev}, {SA, AA, DA}) ->
                {SB, AB, DB} = turn_event(Key, Ev, Now, SA),
                {SB, AA ++ AB, DA ++ DB}
        end,
        {S, [], []},
        TActs
    ).

turn_event({Sock, Server} = Key, {allocated, #{relayed := {RIP, RPort}, mapped := Mapped}}, Now, S) ->
    case maps:find(Key, S#ice.turn) of
        {ok, #{host := HostId, job := {relay, _, _, Idx} = Job} = E} ->
            Host = webrtc_ice_checklist:local(HostId, S),
            HostLP = (Host#ice_cand.priority bsr 8) band 16#FFFF,
            Comp = Host#ice_cand.component,
            {SIP, _} = Server,
            {RelA, RelP} = case Mapped of
                {MA, MP} -> {MA, MP};
                undefined -> {undefined, undefined}
            end,
            Relay = #ice_cand{
                foundation = webrtc_ice_candidate:foundation(relay, RIP, SIP, udp),
                component = Comp,
                priority = webrtc_ice_candidate:priority(relay, max(0, HostLP - Idx), Comp),
                address = RIP,
                port = RPort,
                type = relay,
                related_address = RelA,
                related_port = RelP,
                base = {RIP, RPort},
                socket = Sock,
                server = Server
            },
            S1 = S#ice{gather_pending = lists:delete(Job, S#ice.gather_pending)},
            %% A relayed candidate identical to a host candidate is discarded.
            HostAddrs = [{A, P} || _ := #ice_cand{type = host, address = A, port = P} <- S1#ice.local],
            {S2, A1} =
                case lists:member({RIP, RPort}, HostAddrs) of
                    true ->
                        {S1, []};
                    false ->
                        {RId, SR} = add_local(Relay, S1#ice.next_id, S1),
                        SR1 = SR#ice{turn = (SR#ice.turn)#{Key => E#{relay => RId}}},
                        {webrtc_ice_checklist:pair_new_local(RId, SR1), [{event, {local_candidate, Relay}}]}
                end,
            {S3, A2} =
                case Mapped of
                    undefined -> {S2, []};
                    _ -> add_srflx(HostId, Host, Server, Idx, Mapped, S2)
                end,
            {S4, A3} = permit_all(Key, Now, S3),
            {S5, A4} = maybe_complete(S4),
            {S5, A1 ++ A2 ++ A3 ++ A4, []};
        error ->
            {S, [], []}
    end;
turn_event(Key, {allocate_failed, Reason}, _Now, S) ->
    case maps:take(Key, S#ice.turn) of
        {#{job := {relay, HostId, #{address := Server}, Idx} = Job}, Turn} ->
            S1 = S#ice{turn = Turn, gather_pending = lists:delete(Job, S#ice.gather_pending)},
            %% A server out of resources can still give a server-reflexive
            %% candidate (RFC 8445 §5.1.1.2).
            Queue =
                case Reason of
                    {error, C} when C =:= 486; C =:= 508 -> [{srflx, HostId, Server, Idx}];
                    _ -> []
                end,
            {S2, A} = maybe_complete(S1#ice{gather_queue = S1#ice.gather_queue ++ Queue}),
            {S2, A ++ [{event, {turn_error, Server, Reason}}], []};
        error ->
            {S, [], []}
    end;
turn_event(Key, {allocation_lost, _} = Lost, Now, S) ->
    drop_relay(Key, [{event, {turn_error, element(2, Key), Lost}}], Now, S);
turn_event(Key, closed, Now, S) ->
    drop_relay(Key, [], Now, S);
turn_event({Sock, Server}, {data, Peer, Data}, _Now, S) ->
    {S, [], [{{relay, Sock, Server}, Peer, Data}]};
turn_event(_Key, _Other, _Now, S) ->
    {S, [], []}.

drop_relay(Key, Extra, Now, S) ->
    case maps:take(Key, S#ice.turn) of
        {#{relay := RId}, Turn} ->
            {S1, A} = remove_locals([R || R <- [RId], R =/= undefined], Now, S#ice{turn = Turn}),
            {S1, A ++ Extra, []};
        error ->
            {S, [], []}
    end.

%% @doc Create TURN permissions towards a new remote candidate, so the
%% peer's checks reach our relayed candidates (RFC 8445 §7.2.1).
-spec permit(#ice_cand{}, integer(), #ice{}) -> {#ice{}, [term()]}.
permit(#ice_cand{address = IP}, Now, S) ->
    lists:foldl(
        fun(Key, {SA, AA}) ->
            {SB, AB} = permit_one(Key, IP, Now, SA),
            {SB, AA ++ AB}
        end,
        {S, []},
        maps:keys(S#ice.turn)
    ).

permit_one(Key, IP, Now, S) ->
    #{client := C} = E = maps:get(Key, S#ice.turn),
    case webrtc_turn_client:relayed_address(C) of
        {RIP, _} ->
            case webrtc_ice_candidate:family(RIP) =:= webrtc_ice_candidate:family(IP) of
                true ->
                    {C1, TActs} = webrtc_turn_client:create_permission(IP, Now, C),
                    {S1, Acts, _} = turn_actions(Key, TActs, Now, S#ice{turn = (S#ice.turn)#{Key => E#{client => C1}}}),
                    {S1, Acts};
                false ->
                    {S, []}
            end;
        undefined ->
            {S, []}
    end.

permit_all(Key, Now, S) ->
    IPs = lists:usort([IP || _ := #ice_cand{address = IP} <- S#ice.remote]),
    lists:foldl(
        fun(IP, {SA, AA}) ->
            case maps:is_key(Key, SA#ice.turn) of
                true ->
                    {SB, AB} = permit_one(Key, IP, Now, SA),
                    {SB, AA ++ AB};
                false ->
                    {SA, AA}
            end
        end,
        {S, []},
        IPs
    ).

%% @doc Bind a TURN channel for the selected pair when its local
%% candidate is relayed.
-spec bind_channel(#pair{}, integer(), #ice{}) -> {#ice{}, [term()]}.
bind_channel(#pair{} = P, Now, S) ->
    case {webrtc_ice_checklist:pair_local(P, S), webrtc_ice_checklist:remote(P#pair.remote, S)} of
        {#ice_cand{type = relay, socket = Sock, server = Server}, #ice_cand{address = A, port = Po}} ->
            Key = {Sock, Server},
            case maps:find(Key, S#ice.turn) of
                {ok, #{client := C} = E} ->
                    {C1, TActs} = webrtc_turn_client:bind_channel({A, Po}, Now, C),
                    {S1, Acts, _} = turn_actions(Key, TActs, Now, S#ice{turn = (S#ice.turn)#{Key => E#{client => C1}}}),
                    {S1, Acts};
                error ->
                    {S, []}
            end;
        _ ->
            {S, []}
    end.

%% @doc Delete every allocation.
-spec close(integer(), #ice{}) -> {#ice{}, [term()]}.
close(Now, S) ->
    maps:fold(
        fun({Sock, Server}, #{client := C}, {SA, AA}) ->
            {_, TActs} = webrtc_turn_client:close(Now, C),
            {SA, AA ++ [{send, Sock, Server, B} || {send, B} <- TActs]}
        end,
        {S#ice{turn = #{}}, []},
        S#ice.turn
    ).

-spec next_timeout(#ice{}) -> integer() | infinity.
next_timeout(S) ->
    Turn = [webrtc_turn_client:next_timeout(C) || _ := #{client := C} <- S#ice.turn],
    Refresh =
        case S#ice.cl_state of
            running -> maps:values(S#ice.stun_refresh);
            _ -> []
        end,
    lists:min([infinity | Turn ++ Refresh]).
