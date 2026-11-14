%% @private
%% @doc Outgoing connectivity checks of the ICE agent (RFC 8445 §7.2):
%% sending Binding requests and processing their responses (role
%% conflicts, failures, peer-reflexive local candidates, valid pairs,
%% nomination and selection). Incoming checks are answered by
%% webrtc_ice_responder.
-module(webrtc_ice_conncheck).

-include("webrtc_ice_int.hrl").

-export([
    send_check/3,
    binding_request/4,
    handle_response/8,
    check_timeout/4,
    nominated/3,
    switch_role/2,
    has_fingerprint/1
]).

-type pair_id() :: {pos_integer(), pos_integer()}.

%%====================================================================
%% Outgoing checks
%%====================================================================

%% @doc Build a check: USERNAME "remote:local", PRIORITY, the role
%% attribute and optionally USE-CANDIDATE (RFC 8445 §7.1, §7.2.2).
-spec binding_request({binary(), binary()}, pos_integer(), boolean(), #ice{}) -> #stun{}.
binding_request({LocalUfrag, RemoteUfrag}, Prio, UseCand, #ice{role = Role, tiebreaker = T}) ->
    RoleAttr =
        case Role of
            controlling -> {ice_controlling, T};
            controlled -> {ice_controlled, T}
        end,
    webrtc_stun:request(binding, [
        {username, <<RemoteUfrag/binary, ":", LocalUfrag/binary>>},
        {priority, Prio},
        RoleAttr
        | [{use_candidate, true} || UseCand]
    ]).

%% PRIORITY of a check: the local candidate priority recomputed with the
%% peer-reflexive type preference (RFC 8445 §7.1.1).
prflx_priority(#ice_cand{priority = P, component = C}) ->
    webrtc_ice_candidate:priority(prflx, (P bsr 8) band 16#FFFF, C).

-spec send_check(pair_id(), integer(), #ice{}) -> {#ice{}, [term()]}.
send_check(Id, Now, S) ->
    #pair{} = P = webrtc_ice_checklist:pair(Id, S),
    L = webrtc_ice_checklist:pair_local(P, S),
    R = webrtc_ice_checklist:remote(P#pair.remote, S),
    Via = webrtc_ice_gather:via(L, S),
    Prio = prflx_priority(L),
    UseCand = S#ice.role =:= controlling andalso P#pair.use_candidate,
    Msg = binding_request({S#ice.ufrag, S#ice.remote_ufrag}, Prio, UseCand, S),
    Bin = webrtc_stun:encode(Msg, #{integrity => {sha1, S#ice.remote_pwd}, fingerprint => true}),
    Tx0 =
        case P#pair.txid of
            undefined -> S#ice.tx;
            Old -> webrtc_stun_tx:cancel(Old, S#ice.tx)
        end,
    Info = #{
        use_cand => UseCand,
        prio => Prio,
        controlling => S#ice.role =:= controlling,
        pwd => S#ice.remote_pwd,
        nominate => P#pair.nominate_on_success
    },
    To = webrtc_ice_candidate:transport_address(R),
    {Tx, TxActs} = webrtc_stun_tx:send(
        Msg#stun.txid, {Via, To}, Bin,
        #{rto => check_rto(S), rc => S#ice.rc, rm => S#ice.rm, meta => {check, Id, Info}},
        Now, Tx0
    ),
    P1 = P#pair{
        state = in_progress,
        txid = Msg#stun.txid,
        requests_sent = P#pair.requests_sent + 1,
        last_sent = Now
    },
    S1 = webrtc_ice_checklist:put_pair(P1, S#ice{tx = Tx}),
    route_all(TxActs, Now, ?INC(checks_sent, S1)).

%% RFC 8445 §14.3: RTO = MAX(500ms, Ta * N * (Num-Waiting +
%% Num-In-Progress)), capped by the `max_check_rto' option.
check_rto(#ice{ta = Ta, min_rto = Min, max_check_rto = Max} = S) ->
    {N, Active} = webrtc_ice_checklist:rto_counts(S),
    V = max(Min, Ta * N * Active),
    case Max of
        infinity -> V;
        _ -> min(V, Max)
    end.

route_all(TxActs, Now, S) ->
    lists:foldl(
        fun({send, {Via, To}, B}, {SA, AA}) ->
            {SB, AB} = webrtc_ice_gather:route(Via, To, B, Now, SA),
            {SB, AA ++ AB}
        end,
        {S, []},
        TxActs
    ).

%%====================================================================
%% Responses
%%====================================================================

-spec has_fingerprint(#stun{}) -> boolean().
has_fingerprint(#stun{attrs = A}) -> lists:keymember(fingerprint, 1, A).

%% @doc Response to one of our checks (`Meta' from the transaction).
-spec handle_response(binary(), {check, pair_id(), map()}, term(), webrtc_ice_candidate:address(),
                      #stun{}, binary(), integer(), #ice{}) -> {#ice{}, [term()]}.
handle_response(TxId, {check, Id, Info}, Via, From, Msg, Bin, Now, S) ->
    case has_fingerprint(Msg) andalso webrtc_stun:check_integrity(Bin, maps:get(pwd, Info)) =:= ok of
        false ->
            %% Discarded as if never received; retransmissions go on.
            {?INC(bad_responses, S), []};
        true ->
            {ok, #{dest := Dest, rtt := Rtt}, Tx} = webrtc_stun_tx:response(TxId, Now, S#ice.tx),
            S1 = ?INC(responses_received, S#ice{tx = Tx}),
            case webrtc_ice_checklist:pair(Id, S1) of
                undefined ->
                    {S1, []};
                #pair{} = P0 ->
                    P = P0#pair{
                        responses_received = P0#pair.responses_received + 1,
                        rtt = pick_rtt(Rtt, P0#pair.rtt),
                        txid = clear_txid(TxId, P0#pair.txid)
                    },
                    S2 = webrtc_ice_checklist:put_pair(P, S1),
                    case Dest =:= {Via, From} of
                        false -> fail_pair(P, Info, S2);
                        true -> response_class(Msg, P, Info, Now, S2)
                    end
            end
    end.

pick_rtt(undefined, Old) -> Old;
pick_rtt(New, _) -> New.

clear_txid(TxId, TxId) -> undefined;
clear_txid(_, Current) -> Current.

response_class(#stun{class = error} = Msg, P, Info, _Now, S) ->
    case webrtc_stun:get(error_code, Msg) of
        {ok, {487, _}} -> role_conflict(P, Info, S);
        _ -> fail_pair(P, Info, S)
    end;
response_class(#stun{class = success} = Msg, P, Info, Now, S) ->
    case webrtc_stun:get(xor_mapped_address, Msg) of
        {ok, Mapped} -> success(P, Info, Mapped, Now, S);
        error -> fail_pair(P, Info, S)
    end.

%% RFC 8445 §7.2.5.1.
role_conflict(P, Info, S) ->
    Want =
        case maps:get(controlling, Info) of
            true -> controlled;
            false -> controlling
        end,
    {S1, Acts} =
        case S#ice.role =:= Want of
            true -> {S, []};
            false -> switch_role(Want, S)
        end,
    S2 = webrtc_ice_checklist:put_pair(P#pair{state = waiting}, S1),
    {webrtc_ice_checklist:trigger(P#pair.id, S2), Acts}.

%% @doc Change role: new tie-breaker, recomputed pair priorities and a
%% `{role_change, Role}' event.
-spec switch_role(controlling | controlled, #ice{}) -> {#ice{}, [term()]}.
switch_role(Role, S) ->
    {T, R} = rand:uniform_s(1 bsl 64, S#ice.rand),
    Pairs =
        case Role of
            controlled ->
                maps:map(fun(_, P) -> P#pair{use_candidate = false} end, S#ice.pairs);
            controlling ->
                maps:map(fun(_, P) -> P#pair{nominate_on_success = false} end, S#ice.pairs)
        end,
    S1 = S#ice{role = Role, tiebreaker = T - 1, rand = R, pairs = Pairs, nominating = undefined},
    {webrtc_ice_checklist:recompute_priorities(S1), [{event, {role_change, Role}}]}.

fail_pair(#pair{} = P, Info, S) ->
    case maps:get(use_cand, Info) orelse maps:get(nominate, Info) of
        true -> nomination_failed(P, S);
        false -> {webrtc_ice_checklist:put_pair(P#pair{state = failed}, S), []}
    end.

%% RFC 8445 §7.2.5.3.4: the pair leaves the valid list and the checklist
%% fails (once the PAC timer allows it, RFC 8863).
nomination_failed(#pair{id = Id} = P, S) ->
    Pairs = maps:map(
        fun
            (_, #pair{generated_by = G} = V) when G =:= Id -> V#pair{valid = false};
            (_, V) -> V
        end,
        S#ice.pairs
    ),
    S1 = S#ice{pairs = Pairs, nomination_failed = true, nominating = undefined},
    {webrtc_ice_checklist:put_pair(P#pair{state = failed, valid = false}, S1), []}.

%% RFC 8445 §7.2.5.3.
success(#pair{} = P, Info, Mapped, Now, S) ->
    Base = webrtc_ice_checklist:local(P#pair.local, S),
    {LocalId, S1} = mapped_local(P#pair.local, Base, Mapped, maps:get(prio, Info), S),
    VId = {LocalId, P#pair.remote},
    P1 = P#pair{state = succeeded},
    S2 = webrtc_ice_checklist:put_pair(P1, S1),
    V0 =
        case webrtc_ice_checklist:pair(VId, S2) of
            #pair{} = Existing ->
                Existing;
            undefined ->
                LC = webrtc_ice_checklist:local(LocalId, S2),
                RC = webrtc_ice_checklist:remote(P#pair.remote, S2),
                #pair{
                    id = VId,
                    local = LocalId,
                    remote = P#pair.remote,
                    component = P#pair.component,
                    foundation = {LC#ice_cand.foundation, RC#ice_cand.foundation},
                    priority = webrtc_ice_checklist:pair_priority(LC, RC, S2#ice.role),
                    in_checklist = false,
                    rtt = P1#pair.rtt
                }
        end,
    V = V0#pair{
        state = succeeded,
        valid = true,
        generated_by = P#pair.id,
        rtt = P1#pair.rtt,
        consent_expires = Now + S#ice.consent_expiry,
        consent_ok = Now,
        consent_next = case V0#pair.consent_next of
            undefined -> Now + S#ice.consent_interval;
            Next -> Next
        end
    },
    S3 = webrtc_ice_checklist:put_pair(V, S2),
    S4 = webrtc_ice_checklist:unfreeze(P#pair.foundation, S3),
    S5 =
        case S4#ice.first_valid_at of
            undefined -> S4#ice{first_valid_at = Now};
            _ -> S4
        end,
    Nominate =
        (maps:get(use_cand, Info) andalso S5#ice.role =:= controlling) orelse
            (P#pair.nominate_on_success andalso S5#ice.role =:= controlled),
    case Nominate of
        true -> nominated(VId, Now, S5);
        false -> {S5, []}
    end.

%% Local candidate matching the mapped address, or a new peer-reflexive
%% one (RFC 8445 §7.2.5.3.1).
mapped_local(BaseId, Base, {MIP, MPort}, Prio, S) ->
    Match = [Id || Id := #ice_cand{address = A, port = Po} <- S#ice.local,
                   A =:= MIP, Po =:= MPort, webrtc_ice_checklist:base(Id, S) =:= BaseId],
    case Match of
        [Id | _] ->
            {Id, S};
        [] ->
            Cand = #ice_cand{
                foundation = webrtc_ice_candidate:foundation(prflx, Base#ice_cand.address, undefined, udp),
                component = Base#ice_cand.component,
                priority = Prio,
                address = MIP,
                port = MPort,
                type = prflx,
                related_address = Base#ice_cand.address,
                related_port = Base#ice_cand.port,
                base = Base#ice_cand.base,
                socket = Base#ice_cand.socket,
                server = Base#ice_cand.server
            },
            Id = S#ice.next_id,
            {Id, S#ice{
                next_id = Id + 1,
                local = (S#ice.local)#{Id => Cand},
                base_of = (S#ice.base_of)#{Id => BaseId}
            }}
    end.

%% @doc A valid pair got nominated: it becomes the selected pair of its
%% component unless a higher priority one already is (RFC 8445 §8.1.1),
%% other pairs of the component leave the checklist (§8.1.2).
-spec nominated(pair_id(), integer(), #ice{}) -> {#ice{}, [term()]}.
nominated(VId, Now, S) ->
    #pair{component = Comp} = V0 = webrtc_ice_checklist:pair(VId, S),
    V = V0#pair{nominated = true},
    S1 = webrtc_ice_checklist:put_pair(V, S),
    case maps:find(Comp, S1#ice.selected) of
        {ok, VId} ->
            {S1, []};
        {ok, Other} ->
            case webrtc_ice_checklist:pair(Other, S1) of
                #pair{priority = OP} when OP >= V#pair.priority -> {S1, []};
                _ -> select(V, Now, S1)
            end;
        error ->
            select(V, Now, S1)
    end.

select(#pair{id = VId, component = Comp} = V, Now, S) ->
    {Jitter, R} = rand:uniform_s(S#ice.rand),
    Interval = round(S#ice.consent_interval * (0.8 + 0.4 * Jitter)),
    V1 = V#pair{
        consent_next = case V#pair.consent_next of
            undefined -> Now + Interval;
            Next -> min(Next, Now + Interval)
        end,
        consent_expires = case V#pair.consent_expires of
            undefined -> Now + S#ice.consent_expiry;
            E -> E
        end,
        consent_ok = case V#pair.consent_ok of
            undefined -> Now;
            O -> O
        end
    },
    Pairs = maps:map(
        fun
            (Id, #pair{component = C, in_checklist = true} = P) when C =:= Comp, Id =/= VId ->
                P#pair{in_checklist = false};
            (_, P) ->
                P
        end,
        S#ice.pairs
    ),
    Tx = lists:foldl(
        fun(#pair{txid = T}, Acc) -> webrtc_stun_tx:cancel(T, Acc) end,
        S#ice.tx,
        [P || _ := #pair{component = C, state = in_progress, txid = T} = P <- S#ice.pairs,
              C =:= Comp, is_binary(T), P#pair.id =/= VId]
    ),
    Triggered = [Id || Id <- S#ice.triggered,
                       case maps:find(Id, Pairs) of
                           {ok, #pair{component = C}} -> C =/= Comp;
                           error -> false
                       end],
    Selected = (S#ice.selected)#{Comp => VId},
    Done = lists:all(fun(C) -> maps:is_key(C, Selected) end, S#ice.components),
    Prev =
        case S#ice.prev of
            #prev{pairs = PP} = Pv when not Done -> Pv#prev{pairs = maps:remove(Comp, PP)};
            _ -> undefined
        end,
    S1 = S#ice{
        pairs = Pairs#{VId => V1},
        tx = Tx,
        triggered = Triggered,
        selected = Selected,
        rand = R,
        prev = Prev,
        nominating = undefined,
        cl_state = case Done of
            true -> completed;
            false -> S#ice.cl_state
        end
    },
    Local = webrtc_ice_checklist:local(V#pair.local, S1),
    Remote = webrtc_ice_checklist:remote(V#pair.remote, S1),
    {S2, ChanActs} = webrtc_ice_relay:bind_channel(V1, Now, S1),
    {S2, [{event, {selected_pair, Local, Remote}} | ChanActs]}.

%% @doc A check transaction timed out.
-spec check_timeout(binary(), {check, pair_id(), map()}, integer(), #ice{}) -> {#ice{}, [term()]}.
check_timeout(TxId, {check, Id, Info}, _Now, S) ->
    case webrtc_ice_checklist:pair(Id, S) of
        #pair{txid = TxId} = P ->
            P1 = P#pair{txid = undefined},
            case maps:get(use_cand, Info) orelse maps:get(nominate, Info) of
                true -> nomination_failed(P1, S);
                false when P#pair.state =:= in_progress ->
                    {webrtc_ice_checklist:put_pair(P1#pair{state = failed}, S), []};
                false ->
                    {webrtc_ice_checklist:put_pair(P1, S), []}
            end;
        _ ->
            {S, []}
    end.

%%====================================================================
%% Incoming checks (RFC 8445 §7.3)
