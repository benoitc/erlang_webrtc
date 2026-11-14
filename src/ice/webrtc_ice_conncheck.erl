%% @private
%% @doc Connectivity checks of the ICE agent (RFC 8445 §7): sending
%% Binding requests, processing their responses (role conflicts,
%% failures, peer-reflexive local candidates, valid pairs, nomination)
%% and answering incoming checks (short-term credentials, role conflict
%% repair, peer-reflexive remote candidates, triggered checks,
%% nomination by the controlling peer, ICE-Lite behavior).
-module(webrtc_ice_conncheck).

-include("webrtc_ice_int.hrl").

-export([
    send_check/3,
    binding_request/4,
    handle_request/6,
    handle_response/8,
    check_timeout/4,
    replay_early/2,
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
        consent_ok = Now
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
        consent_next = Now + Interval,
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
    {S2, ChanActs} = webrtc_ice_gather:bind_channel(V1, Now, S1),
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
%%====================================================================

%% @doc Binding request received on `Via' from `From'. `Bin' is the raw
%% message, `Msg' its decoding.
-spec handle_request(term(), webrtc_ice_candidate:address(), #stun{}, binary(), integer(), #ice{}) ->
    {#ice{}, [term()]}.
handle_request(Via, From, Msg, Bin, Now, S) ->
    case has_fingerprint(Msg) of
        false -> {?INC(bad_requests, S), []};
        true -> authenticate(Via, From, Msg, Bin, Now, S)
    end.

authenticate(Via, From, Msg, Bin, Now, S) ->
    case {webrtc_stun:get(username, Msg), webrtc_stun:has_integrity(Msg)} of
        {{ok, User}, true} ->
            case credentials(User, S) of
                {ok, Session, Pwd, RemoteUfrag} ->
                    case webrtc_stun:check_integrity(Bin, Pwd) of
                        ok -> checked(Via, From, Msg, Session, Pwd, RemoteUfrag, Now, S);
                        {error, _} -> reject(Via, From, Msg, 401, undefined, Now, S)
                    end;
                error ->
                    reject(Via, From, Msg, 401, undefined, Now, S)
            end;
        _ ->
            reject(Via, From, Msg, 400, undefined, Now, S)
    end.

%% USERNAME is "local-ufrag:remote-ufrag" (RFC 8445 §7.3).
credentials(User, #ice{ufrag = U, pwd = P, prev = Prev}) ->
    case binary:split(User, <<":">>) of
        [U, Remote] when Remote =/= <<>> ->
            {ok, current, P, Remote};
        [PU, Remote] when is_record(Prev, prev), PU =:= Prev#prev.ufrag, Remote =/= <<>> ->
            {ok, prev, Prev#prev.pwd, Remote};
        _ ->
            error
    end.

reject(Via, From, Msg, Code, Pwd, Now, S) ->
    Attrs =
        case Code of
            420 -> [{unknown_attributes, Msg#stun.unknown}];
            _ -> []
        end,
    Resp = webrtc_stun:error_response(Msg, Code, Attrs),
    Opts =
        case Pwd of
            undefined -> #{fingerprint => true};
            _ -> #{integrity => {sha1, Pwd}, fingerprint => true}
        end,
    S1 = ?INC(error_responses, S),
    webrtc_ice_gather:route(Via, From, webrtc_stun:encode(Resp, Opts), Now, S1).

checked(Via, From, #stun{unknown = [_ | _]} = Msg, _Session, Pwd, _RU, Now, S) ->
    reject(Via, From, Msg, 420, Pwd, Now, S);
checked(Via, From, Msg, Session, Pwd, RU, Now, S) ->
    Prio = webrtc_stun:get(priority, Msg, undefined),
    Ctl = webrtc_stun:get(ice_controlling, Msg, undefined),
    Cld = webrtc_stun:get(ice_controlled, Msg, undefined),
    UseCand = webrtc_stun:get(use_candidate, Msg, false),
    case Prio =/= undefined andalso ((Ctl =:= undefined) xor (Cld =:= undefined)) of
        false ->
            reject(Via, From, Msg, 400, Pwd, Now, S);
        true ->
            case role_check(Ctl, Cld, S) of
                conflict ->
                    reject(Via, From, Msg, 487, Pwd, Now, S);
                {ok, S1, RoleActs} ->
                    Resp = webrtc_stun:success(Msg, [{xor_mapped_address, From}]),
                    RBin = webrtc_stun:encode(Resp, #{integrity => {sha1, Pwd}, fingerprint => true}),
                    {S2, SendActs} = webrtc_ice_gather:route(Via, From, RBin, Now, ?INC(requests_received, S1)),
                    {S3, Acts} = accepted(Session, Via, From, Prio, UseCand, RU, Now, S2),
                    {S3, RoleActs ++ SendActs ++ Acts}
            end
    end.

%% RFC 8445 §7.3.1.1. A lite agent does not repair role conflicts.
role_check(_Ctl, _Cld, #ice{lite = true} = S) ->
    {ok, S, []};
role_check(Ctl, _Cld, #ice{role = controlling, tiebreaker = T} = S) when is_integer(Ctl) ->
    case T >= Ctl of
        true -> conflict;
        false -> ok(switch_role(controlled, S))
    end;
role_check(_Ctl, Cld, #ice{role = controlled, tiebreaker = T} = S) when is_integer(Cld) ->
    case T >= Cld of
        true -> ok(switch_role(controlling, S));
        false -> conflict
    end;
role_check(_, _, S) ->
    {ok, S, []}.

ok({S, Acts}) -> {ok, S, Acts}.

%% A request for the session before an ICE restart keeps the old pairs
%% alive but triggers nothing.
accepted(prev, Via, From, _Prio, _UseCand, _RU, Now, #ice{prev = Prev} = S) ->
    Pairs = maps:map(
        fun(_, {#pair{} = P, #ice_cand{} = RC}) ->
            case webrtc_ice_candidate:transport_address(RC) =:= From andalso
                     webrtc_ice_gather:via(webrtc_ice_checklist:pair_local(P, S), S) =:= Via of
                true when S#ice.lite -> {lite_consent(P, Now, S), RC};
                true -> {P#pair{requests_received = P#pair.requests_received + 1}, RC};
                false -> {P, RC}
            end
        end,
        Prev#prev.pairs
    ),
    {S#ice{prev = Prev#prev{pairs = Pairs}}, []};
accepted(current, Via, From, Prio, UseCand, RU, Now, S) ->
    case webrtc_ice_gather:base_by_via(Via, S) of
        error ->
            {S, []};
        {ok, LId} ->
            case S#ice.remote_ufrag of
                undefined ->
                    Early = {Via, From, LId, Prio, UseCand, RU},
                    {S#ice{early = S#ice.early ++ [Early]}, []};
                RU ->
                    learned(LId, From, Prio, UseCand, Now, S);
                _ ->
                    {S, []}
            end
    end.

%% @doc Apply the requests received before the remote credentials
%% (RFC 8445 §7.3).
-spec replay_early(integer(), #ice{}) -> {#ice{}, [term()]}.
replay_early(Now, #ice{early = Early, remote_ufrag = RU} = S) ->
    lists:foldl(
        fun
            ({_Via, From, LId, Prio, UseCand, U}, {SA, AA}) when U =:= RU ->
                case webrtc_ice_checklist:local(LId, SA) of
                    #ice_cand{} ->
                        {SB, AB} = learned(LId, From, Prio, UseCand, Now, SA),
                        {SB, AA ++ AB};
                    undefined ->
                        {SA, AA}
                end;
            (_, Acc) ->
                Acc
        end,
        {S#ice{early = []}, []},
        Early
    ).

%% RFC 8445 §7.3.1.3 to §7.3.1.5 and §7.3.2.
learned(LId, From, Prio, UseCand, Now, S) ->
    #ice_cand{component = Comp} = webrtc_ice_checklist:local(LId, S),
    {RId, S1} =
        case webrtc_ice_checklist:find_remote(Comp, From, S) of
            {ok, Id} ->
                {Id, S};
            error ->
                {IP, Port} = From,
                Cand = #ice_cand{
                    foundation = <<"prflx", (integer_to_binary(S#ice.next_id))/binary>>,
                    component = Comp,
                    priority = Prio,
                    address = IP,
                    port = Port,
                    type = prflx
                },
                webrtc_ice_checklist:add_remote(Cand, S)
        end,
    case S1#ice.lite of
        true -> lite_request(LId, RId, UseCand, Now, S1);
        false -> triggered(LId, RId, UseCand, Now, S1)
    end.

triggered(LId, RId, UseCand, Now, #ice{cl_state = running} = S) ->
    case webrtc_ice_checklist:ensure_pair(LId, RId, Now, S) of
        {none, S1} ->
            {S1, []};
        {Id, S1} ->
            P = count_request(webrtc_ice_checklist:pair(Id, S1)),
            Nominate = UseCand andalso S1#ice.role =:= controlled,
            case P of
                #pair{in_checklist = false} ->
                    {webrtc_ice_checklist:put_pair(P, S1), []};
                #pair{state = succeeded} when Nominate ->
                    nominate_generated(P, Now, webrtc_ice_checklist:put_pair(P, S1));
                #pair{state = succeeded} ->
                    {webrtc_ice_checklist:put_pair(P, S1), []};
                #pair{state = St, txid = T} ->
                    Tx =
                        case St =:= in_progress andalso is_binary(T) of
                            true -> webrtc_stun_tx:cancel(T, S1#ice.tx);
                            false -> S1#ice.tx
                        end,
                    P1 = P#pair{state = waiting, nominate_on_success = P#pair.nominate_on_success orelse Nominate},
                    S2 = webrtc_ice_checklist:put_pair(P1, S1#ice{tx = Tx}),
                    {webrtc_ice_checklist:trigger(Id, S2), []}
            end
    end;
triggered(LId, RId, UseCand, Now, S) ->
    %% Checklist concluded: only a nomination of an existing valid pair
    %% by a controlling peer still matters (RFC 8445 §8.1.1).
    case webrtc_ice_checklist:pair({LId, RId}, S) of
        #pair{} = P0 ->
            P = count_request(P0),
            S1 = webrtc_ice_checklist:put_pair(P, S),
            case UseCand andalso S1#ice.role =:= controlled andalso S1#ice.cl_state =:= completed of
                true -> nominate_generated(P, Now, S1);
                false -> {S1, []}
            end;
        undefined ->
            {S, []}
    end.

count_request(#pair{requests_received = N} = P) ->
    P#pair{requests_received = N + 1, responses_sent = P#pair.responses_sent + 1}.

%% The valid pair produced by a succeeded pair gets nominated.
nominate_generated(#pair{id = Id, valid = Valid} = P, Now, S) ->
    Generated = [V || _ := #pair{generated_by = G, valid = true} = V <- S#ice.pairs, G =:= Id],
    case lists:sort(fun(A, B) -> A#pair.priority >= B#pair.priority end, Generated) of
        [#pair{id = VId} | _] ->
            nominated(VId, Now, S);
        [] when Valid ->
            nominated(Id, Now, S);
        [] ->
            {webrtc_ice_checklist:put_pair(P#pair{nominate_on_success = true}, S), []}
    end.

%% ICE-Lite (RFC 8445 §7.3.2): a nomination makes the pair valid and
%% selected at once; authenticated checks keep consent fresh.
lite_request(LId, RId, UseCand, Now, S) ->
    {Id, S1} = webrtc_ice_checklist:ensure_pair(LId, RId, Now, S),
    case Id of
        none ->
            {S1, []};
        _ ->
            P = lite_consent(count_request(webrtc_ice_checklist:pair(Id, S1)), Now, S1),
            case UseCand of
                true ->
                    P1 = P#pair{state = succeeded, valid = true, generated_by = Id},
                    nominated(Id, Now, webrtc_ice_checklist:put_pair(P1, S1));
                false ->
                    {webrtc_ice_checklist:put_pair(P, S1), []}
            end
    end.

lite_consent(#pair{consent_lost = true} = P, _Now, _S) ->
    P;
lite_consent(#pair{} = P, Now, S) ->
    P#pair{consent_ok = Now, consent_expires = Now + S#ice.consent_expiry}.
