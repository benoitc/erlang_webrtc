%% @private
%% @doc Session-level logic of the ICE agent: nomination policy of the
%% controlling agent (RFC 8445 §8.1.1), checklist failure with the RFC
%% 8863 PAC timer and RFC 8838 end-of-candidates, the connection state,
%% data sending on the selected pair, ICE restart (§9) and statistics.
-module(webrtc_ice_session).

-include("webrtc_ice_int.hrl").

-export([
    nominate/2,
    evaluate/2,
    derive/2,
    recheck_at/2,
    send_data/4,
    is_valid_remote/3,
    restart/4,
    stats/1
]).

%%--------------------------------------------------------------------
%% Nomination (controlling, full agent)
%%--------------------------------------------------------------------

%% @doc Regular nomination: once a valid pair exists, the controlling
%% agent repeats the check that produced the chosen valid pair with
%% USE-CANDIDATE. Policy `first' nominates the first valid pair; `best'
%% waits until no higher priority pair is still pending, or until
%% `nomination_timeout' after the first valid pair.
-spec nominate(integer(), #ice{}) -> {#ice{}, [term()]}.
nominate(Now, #ice{role = controlling, lite = false, cl_state = running, nominating = undefined,
                   nomination_failed = false, remote_pwd = RP} = S) when RP =/= undefined ->
    Missing = [C || C <- S#ice.components, not maps:is_key(C, S#ice.selected)],
    nominate_comps(Missing, Now, S);
nominate(_Now, S) ->
    {S, []}.

nominate_comps([], _Now, S) ->
    {S, []};
nominate_comps([C | Rest], Now, S) ->
    case usable_valid(C, Now, S) of
        undefined ->
            nominate_comps(Rest, Now, S);
        #pair{} = V ->
            case ready(V, C, Now, S) of
                true -> {start_nomination(V, S), []};
                false -> nominate_comps(Rest, Now, S)
            end
    end.

usable_valid(C, Now, S) ->
    case [P || P <- webrtc_ice_checklist:valid_pairs(C, S), webrtc_ice_consent:usable(P, Now)] of
        [P | _] -> P;
        [] -> undefined
    end.

ready(_V, _C, _Now, #ice{nomination = first}) ->
    true;
ready(#pair{priority = Pr}, C, Now, #ice{first_valid_at = F, nomination_timeout = T} = S) ->
    Better = [P || _ := #pair{component = C2, in_checklist = true, state = St, priority = Pr2} = P <- S#ice.pairs,
                   C2 =:= C, Pr2 > Pr, St =:= frozen orelse St =:= waiting orelse St =:= in_progress],
    Better =:= [] orelse (is_integer(F) andalso Now >= F + T).

start_nomination(#pair{id = VId, generated_by = G}, S) ->
    GId =
        case webrtc_ice_checklist:pair(G, S) of
            #pair{in_checklist = true} -> G;
            _ -> VId
        end,
    P = webrtc_ice_checklist:pair(GId, S),
    S1 = webrtc_ice_checklist:put_pair(P#pair{use_candidate = true, state = waiting}, S),
    webrtc_ice_checklist:trigger(GId, S1#ice{nominating = VId}).

%%--------------------------------------------------------------------
%% Checklist failure (RFC 8445 §7.2.5.4, RFC 8838 §8, RFC 8863 §4)
%%--------------------------------------------------------------------

-spec evaluate(integer(), #ice{}) -> #ice{}.
evaluate(Now, #ice{cl_state = running, lite = false, started_at = Start} = S) when is_integer(Start) ->
    PacOver = Now >= Start + S#ice.pac_timeout,
    EocKnown = S#ice.remote_eoc orelse Now >= Start + S#ice.eoc_timeout,
    Exhausted =
        not webrtc_ice_checklist:has_pending(S) andalso
            not webrtc_ice_checklist:all_components_valid(S) andalso
            EocKnown andalso S#ice.gather_state =/= gathering,
    case PacOver andalso (S#ice.nomination_failed orelse Exhausted) of
        true -> S#ice{cl_state = failed, triggered = []};
        false -> S
    end;
evaluate(_Now, S) ->
    S.

%%--------------------------------------------------------------------
%% Connection state
%%--------------------------------------------------------------------

%% @doc Connection state derived from the checklist, the selected pairs
%% and their consent.
-spec derive(integer(), #ice{}) -> atom().
derive(_Now, #ice{state = closed}) ->
    closed;
derive(_Now, #ice{cl_state = failed}) ->
    failed;
derive(Now, #ice{cl_state = completed} = S) ->
    Sel = selected_pairs(S),
    case length(Sel) =:= length(S#ice.components) of
        false -> failed;
        true -> consent_state(Sel, completed, Now, S)
    end;
derive(Now, S) ->
    Comps = S#ice.components,
    AllValid = lists:all(fun(C) -> webrtc_ice_checklist:best_valid(C, S) =/= undefined end, Comps),
    PrevPairs = prev_pairs(S),
    if
        Comps =/= [], AllValid ->
            connected;
        PrevPairs =/= [] ->
            consent_state(PrevPairs, connected, Now, S);
        is_integer(S#ice.started_at) ->
            checking;
        true ->
            new
    end.

consent_state(Pairs, Good, Now, #ice{consent = Consent, disconnect_timeout = D}) ->
    Lost = lists:any(fun(#pair{consent_lost = L}) -> L end, Pairs),
    Stale = Consent andalso
        lists:any(fun(#pair{consent_ok = O}) -> is_integer(O) andalso Now - O >= D end, Pairs),
    if
        Lost -> failed;
        Stale -> disconnected;
        true -> Good
    end.

selected_pairs(S) ->
    [P || _ := Id <- S#ice.selected, #pair{} = P <- [webrtc_ice_checklist:pair(Id, S)]].

prev_pairs(#ice{prev = #prev{pairs = PP}}) -> [P || _ := {P, _} <- PP];
prev_pairs(_) -> [].

%% @doc Next instant at which the state may change with time alone (PAC
%% and end-of-candidates timers, nomination timeout, disconnection).
-spec recheck_at(integer(), #ice{}) -> integer() | infinity.
recheck_at(Now, S) ->
    Running = S#ice.cl_state =:= running andalso not S#ice.lite,
    Start = S#ice.started_at,
    Timers =
        [Start + S#ice.pac_timeout || Running, is_integer(Start)] ++
            [Start + S#ice.eoc_timeout || Running, is_integer(Start), not S#ice.remote_eoc] ++
            [F + S#ice.nomination_timeout
             || Running, S#ice.role =:= controlling, F <- [S#ice.first_valid_at], is_integer(F)] ++
            [O + S#ice.disconnect_timeout
             || S#ice.consent, #pair{consent_ok = O, consent_lost = false} <- selected_pairs(S) ++ prev_pairs(S),
                is_integer(O)],
    lists:min([infinity | [T || T <- Timers, T > Now]]).

%%--------------------------------------------------------------------
%% Data
%%--------------------------------------------------------------------

-spec send_data(1..256, binary(), integer(), #ice{}) -> {ok, #ice{}, [term()]} | {error, term()}.
send_data(Comp, Data, Now, S) ->
    Selected = [P || {ok, Id} <- [maps:find(Comp, S#ice.selected)], #pair{} = P <- [webrtc_ice_checklist:pair(Id, S)]],
    Valid = webrtc_ice_checklist:valid_pairs(Comp, S),
    Prev = [{prev, P} || #prev{pairs = #{Comp := {P, _}}} <- [S#ice.prev]],
    Candidates = [{current, P} || P <- Selected ++ Valid] ++ Prev,
    case [C || {_, P} = C <- Candidates, webrtc_ice_consent:usable(P, Now)] of
        [{Where, P} | _] ->
            {S1, Acts} = send_on(Where, P, Data, Now, S),
            {ok, S1, Acts};
        [] ->
            case lists:any(fun({_, #pair{consent_lost = L}}) -> L end, Candidates) of
                true -> {error, consent_lost};
                false -> {error, no_valid_pair}
            end
    end.

send_on(Where, #pair{component = C} = P, Data, Now, S) ->
    RC =
        case Where of
            current -> webrtc_ice_checklist:remote(P#pair.remote, S);
            prev -> element(2, maps:get(C, (S#ice.prev)#prev.pairs))
        end,
    P1 = P#pair{last_sent = Now},
    S1 =
        case Where of
            current ->
                webrtc_ice_checklist:put_pair(P1, S);
            prev ->
                #prev{pairs = PP} = Pv = S#ice.prev,
                S#ice{prev = Pv#prev{pairs = PP#{C => {P1, RC}}}}
        end,
    webrtc_ice_gather:route(webrtc_ice_tcp:pair_via(P1, RC, S1), webrtc_ice_candidate:transport_address(RC),
                            Data, Now, S1).

-spec is_valid_remote(term(), webrtc_ice_candidate:address(), #ice{}) -> boolean().
is_valid_remote(Via, From, S) ->
    Current = [{P, webrtc_ice_checklist:remote(P#pair.remote, S)} || _ := P <- S#ice.pairs],
    Old = case S#ice.prev of
        #prev{pairs = PP} -> maps:values(PP);
        undefined -> []
    end,
    lists:any(
        fun({#pair{valid = V, requests_received = N, consent_lost = Lost} = P, #ice_cand{} = RC}) ->
                not Lost andalso (V orelse N > 0) andalso
                    webrtc_ice_candidate:transport_address(RC) =:= From andalso
                    webrtc_ice_tcp:pair_via(P, RC, S) =:= Via;
           (_) ->
                false
        end,
        Current ++ Old
    ).



%%--------------------------------------------------------------------
%% ICE restart (RFC 8445 §9)
%%--------------------------------------------------------------------

-spec restart(binary(), binary(), integer(), #ice{}) -> #ice{}.
restart(U, P, Now, S) ->
    Keep = maps:from_list(
        [{C, {Pair, webrtc_ice_checklist:remote(Pair#pair.remote, S)}}
         || C := Id <- S#ice.selected, #pair{} = Pair <- [webrtc_ice_checklist:pair(Id, S)],
            webrtc_ice_consent:usable(Pair, Now)]
    ),
    Prev =
        case {map_size(Keep), S#ice.prev} of
            {0, Old} ->
                Old;
            {_, _} ->
                #prev{
                    ufrag = S#ice.ufrag,
                    pwd = S#ice.pwd,
                    remote_ufrag = S#ice.remote_ufrag,
                    remote_pwd = S#ice.remote_pwd,
                    pairs = Keep
                }
        end,
    CheckTx = [T || _ := #pair{txid = T} <- S#ice.pairs, is_binary(T)],
    Tx = lists:foldl(fun webrtc_stun_tx:remove/2, S#ice.tx, CheckTx),
    %% Peer-reflexive local candidates belong to the old session, unless
    %% a kept pair uses one.
    InUse = [L || #prev{pairs = PP} <- [Prev], _ := {#pair{local = L}, _} <- PP],
    Prflx = [Id || Id := #ice_cand{type = prflx} <- S#ice.local, not lists:member(Id, InUse)],
    S#ice{
        ufrag = U,
        pwd = P,
        remote_ufrag = undefined,
        remote_pwd = undefined,
        prev = Prev,
        local = maps:without(Prflx, S#ice.local),
        base_of = maps:without(Prflx, S#ice.base_of),
        remote = #{},
        remote_eoc = false,
        pairs = #{},
        triggered = [],
        cl_state = running,
        started_at = undefined,
        first_valid_at = undefined,
        nominating = undefined,
        nomination_failed = false,
        selected = #{},
        tx = Tx,
        early = []
    }.

%%--------------------------------------------------------------------
%% Statistics
%%--------------------------------------------------------------------

-spec stats(#ice{}) -> map().
stats(S) ->
    Pairs = [pair_stats(P, S) || _ := P <- maps:iterator(S#ice.pairs, ordered)],
    #{
        state => S#ice.state,
        role => S#ice.role,
        lite => S#ice.lite,
        checklist => S#ice.cl_state,
        gathering => S#ice.gather_state,
        local_candidates => map_size(S#ice.local),
        remote_candidates => map_size(S#ice.remote),
        pairs => lists:sort(fun(A, B) -> maps:get(priority, A) >= maps:get(priority, B) end, Pairs),
        counters => S#ice.counters,
        remote_ufrag => S#ice.remote_ufrag,
        ta => S#ice.ta,
        transactions => webrtc_stun_tx:size(S#ice.tx)
    }.

pair_stats(#pair{} = P, S) ->
    #{
        local => webrtc_ice_checklist:local(P#pair.local, S),
        remote => webrtc_ice_checklist:remote(P#pair.remote, S),
        component => P#pair.component,
        state => P#pair.state,
        priority => P#pair.priority,
        in_checklist => P#pair.in_checklist,
        valid => P#pair.valid,
        nominated => P#pair.nominated,
        selected => lists:member(P#pair.id, maps:values(S#ice.selected)),
        rtt => P#pair.rtt,
        total_rtt => P#pair.total_rtt,
        consent_requests_sent => P#pair.consent_requests,
        requests_sent => P#pair.requests_sent,
        responses_received => P#pair.responses_received,
        requests_received => P#pair.requests_received,
        responses_sent => P#pair.responses_sent,
        consent_lost => P#pair.consent_lost
    }.
