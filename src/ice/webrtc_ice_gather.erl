%% @private
%% @doc Local candidates of the ICE agent: host candidates supplied by
%% the owner, server-reflexive candidates from STUN servers (RFC 8445
%% §5.1.1.2), gathering jobs paced by Ta, removal on network change, and
%% the routing of outgoing packets through a host socket or a TURN
%% allocation (relayed candidates live in webrtc_ice_relay).
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
    stun_refresh/2,
    next_timeout/1,
    maybe_complete/1,
    add_local/3,
    add_srflx/6
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
            webrtc_ice_relay:allocate({Sock, Server}, HostId, Job, Opts, Now, S);
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
    webrtc_ice_relay:send({Sock, Server}, To, Bin, Now, S);
route(Sock, To, Bin, _Now, S) ->
    {S, [{send, Sock, To, Bin}]}.

-spec next_timeout(#ice{}) -> integer() | infinity.
next_timeout(S) ->
    Turn = [webrtc_turn_client:next_timeout(C) || _ := #{client := C} <- S#ice.turn],
    Refresh =
        case S#ice.cl_state of
            running -> maps:values(S#ice.stun_refresh);
            _ -> []
        end,
    lists:min([infinity | Turn ++ Refresh]).
