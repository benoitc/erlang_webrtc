%% @private
%% @doc Checklist of the ICE agent (RFC 8445 §6.1.2, §6.1.4, RFC 8838
%% §10 to §12): pair formation and pruning, pair states and the
%% foundation-based freezing algorithm, check scheduling, triggered
%% check queue and valid list.
%%
%% Pure functions over the agent state (`#ice{}', see
%% webrtc_ice_int.hrl); no actions are produced here.
-module(webrtc_ice_checklist).

-include("webrtc_ice_int.hrl").

-export([
    local/2,
    remote/2,
    base/2,
    pair/2,
    put_pair/2,
    pair_local/2,
    find_remote/3,
    add_remote/2,
    pair_new_local/2,
    pair_new_remote/2,
    ensure_pair/4,
    initial_states/1,
    has_check/1,
    next_check/1,
    trigger/2,
    unfreeze/2,
    recompute_priorities/1,
    remove_pairs/2,
    valid_pairs/2,
    best_valid/2,
    has_pending/1,
    all_components_valid/1,
    rto_counts/1,
    pair_priority/3
]).

-type pair_id() :: {pos_integer(), pos_integer()}.

%%--------------------------------------------------------------------
%% Accessors
%%--------------------------------------------------------------------

-spec local(pos_integer(), #ice{}) -> #ice_cand{} | undefined.
local(Id, #ice{local = L}) -> maps:get(Id, L, undefined).

-spec remote(pos_integer(), #ice{}) -> #ice_cand{} | undefined.
remote(Id, #ice{remote = R}) -> maps:get(Id, R, undefined).

%% @doc Id of the base candidate of a local candidate (itself for host
%% and relayed candidates).
-spec base(pos_integer(), #ice{}) -> pos_integer().
base(Id, #ice{base_of = B}) -> maps:get(Id, B, Id).

-spec pair(pair_id(), #ice{}) -> #pair{} | undefined.
pair(Id, #ice{pairs = P}) -> maps:get(Id, P, undefined).

-spec put_pair(#pair{}, #ice{}) -> #ice{}.
put_pair(#pair{id = Id} = P, #ice{pairs = Ps} = S) -> S#ice{pairs = Ps#{Id => P}}.

%% @doc Local base candidate of a pair (the candidate packets leave from).
-spec pair_local(#pair{}, #ice{}) -> #ice_cand{} | undefined.
pair_local(#pair{local = L}, S) -> local(base(L, S), S).

-spec find_remote(1..256, webrtc_ice_candidate:address(), #ice{}) -> {ok, pos_integer()} | error.
find_remote(Comp, {IP, Port}, #ice{remote = R}) ->
    case [Id || Id := #ice_cand{address = A, port = P, component = C} <- R, A =:= IP, P =:= Port, C =:= Comp] of
        [Id | _] -> {ok, Id};
        [] -> error
    end.

-spec add_remote(#ice_cand{}, #ice{}) -> {pos_integer(), #ice{}}.
add_remote(Cand, #ice{next_id = Id, remote = R} = S) ->
    {Id, S#ice{next_id = Id + 1, remote = R#{Id => Cand}}}.

%%--------------------------------------------------------------------
%% Pair formation (RFC 8445 §6.1.2.2 to §6.1.2.5, RFC 8838 §10 to §12)
%%--------------------------------------------------------------------

-spec pair_priority(#ice_cand{}, #ice_cand{}, controlling | controlled) -> non_neg_integer().
pair_priority(L, R, Role) ->
    webrtc_ice_candidate:pair_priority(L#ice_cand.priority, R#ice_cand.priority, Role).

%% @doc Pair a new local candidate with every known remote candidate.
%% Reflexive candidates are replaced by their base, so only host and
%% relayed candidates form checklist pairs.
-spec pair_new_local(pos_integer(), #ice{}) -> #ice{}.
pair_new_local(LId, #ice{lite = true} = S) ->
    _ = LId,
    S;
pair_new_local(LId, S) ->
    BaseId = base(LId, S),
    case local(BaseId, S) of
        #ice_cand{type = T} when T =:= host; T =:= relay ->
            lists:foldl(fun(RId, Acc) -> insert(BaseId, RId, Acc) end, S, maps:keys(S#ice.remote));
        _ ->
            S
    end.

-spec pair_new_remote(pos_integer(), #ice{}) -> #ice{}.
pair_new_remote(_RId, #ice{lite = true} = S) ->
    S;
pair_new_remote(RId, S) ->
    Bases = [Id || Id := #ice_cand{type = T} <- S#ice.local, T =:= host orelse T =:= relay],
    lists:foldl(fun(LId, Acc) -> insert(LId, RId, Acc) end, S, lists:sort(Bases)).

insert(LId, RId, S) ->
    L = local(LId, S),
    R = remote(RId, S),
    case maps:is_key({LId, RId}, S#ice.pairs) orelse not webrtc_ice_candidate:can_pair(L, R) of
        true -> S;
        false -> add_pair(new_pair(LId, RId, L, R, S), S)
    end.

new_pair(LId, RId, L, R, S) ->
    #pair{
        id = {LId, RId},
        local = LId,
        remote = RId,
        component = L#ice_cand.component,
        foundation = {L#ice_cand.foundation, R#ice_cand.foundation},
        priority = pair_priority(L, R, S#ice.role)
    }.

%% Enforce the pair limit: drop a Failed pair first, then a lower
%% priority Frozen or Waiting pair (RFC 8838 §10 item 6).
add_pair(#pair{} = P, #ice{pairs = Ps, max_pairs = Max} = S) ->
    InList = [X || _ := #pair{in_checklist = true} = X <- Ps],
    case length(InList) < Max of
        true ->
            put_pair(P#pair{state = new_state(P, S)}, S);
        false ->
            Failed = [X || #pair{state = failed} = X <- InList],
            Lower = lists:sort(
                fun(A, B) -> A#pair.priority =< B#pair.priority end,
                [X || #pair{state = St, priority = Pr} = X <- InList,
                      St =:= frozen orelse St =:= waiting, Pr < P#pair.priority]
            ),
            case Failed ++ Lower of
                [#pair{id = Drop} | _] ->
                    S1 = S#ice{pairs = maps:remove(Drop, Ps), triggered = S#ice.triggered -- [Drop]},
                    put_pair(P#pair{state = new_state(P, S1)}, S1);
                [] ->
                    S
            end
    end.

%% Before checks start every pair is Frozen (initial_states/1 sets the
%% first states). Afterwards RFC 8838 §12 rules apply.
new_state(_P, #ice{started_at = undefined}) ->
    frozen;
new_state(#pair{foundation = F, component = C, priority = Pr}, #ice{pairs = Ps}) ->
    Same = [X || _ := #pair{foundation = F2, in_checklist = true} = X <- Ps, F2 =:= F],
    Top = lists:all(
        fun(#pair{component = C2, priority = Pr2}) -> C < C2 orelse (C =:= C2 andalso Pr >= Pr2) end,
        Same
    ),
    Succeeded = lists:any(fun(#pair{state = St}) -> St =:= succeeded end, Same),
    case Top orelse Succeeded of
        true -> waiting;
        false -> frozen
    end.

%% @doc Find or create the pair for a request received on local base
%% `LId' from remote `RId' (RFC 8445 §7.3.1.4).
-spec ensure_pair(pos_integer(), pos_integer(), integer(), #ice{}) -> {pair_id() | none, #ice{}}.
ensure_pair(LId, RId, _Now, S) ->
    Id = {LId, RId},
    case maps:is_key(Id, S#ice.pairs) of
        true ->
            {Id, S};
        false ->
            L = local(LId, S),
            R = remote(RId, S),
            S1 = add_pair(new_pair(LId, RId, L, R, S), S),
            case maps:is_key(Id, S1#ice.pairs) of
                true -> {Id, S1};
                false -> {none, S1}
            end
    end.

%% @doc RFC 8445 §6.1.2.6: for each foundation, the pair with the
%% lowest component and highest priority becomes Waiting.
-spec initial_states(#ice{}) -> #ice{}.
initial_states(#ice{pairs = Ps} = S) ->
    Frozen = lists:sort(
        fun(A, B) -> order(A) =< order(B) end,
        [P || _ := #pair{state = frozen, in_checklist = true} = P <- Ps]
    ),
    {Ps2, _} = lists:foldl(
        fun(#pair{id = Id, foundation = F}, {Acc, Seen}) ->
            case lists:member(F, Seen) of
                true -> {Acc, Seen};
                false -> {Acc#{Id => (maps:get(Id, Acc))#pair{state = waiting}}, [F | Seen]}
            end
        end,
        {Ps, []},
        Frozen
    ),
    S#ice{pairs = Ps2}.

order(#pair{component = C, priority = P}) -> {C, -P}.

%%--------------------------------------------------------------------
%% Scheduling (RFC 8445 §6.1.4.2)
%%--------------------------------------------------------------------

-spec has_check(#ice{}) -> boolean().
has_check(#ice{remote_pwd = undefined}) ->
    false;
has_check(#ice{lite = true}) ->
    false;
has_check(#ice{cl_state = St}) when St =/= running ->
    false;
has_check(#ice{pairs = Ps, triggered = T} = S) ->
    InList = [P || _ := #pair{in_checklist = true} = P <- Ps],
    lists:any(
        fun(Id) ->
            case maps:find(Id, Ps) of
                {ok, #pair{in_checklist = true} = P} -> needs_check(P, S);
                _ -> false
            end
        end,
        T
    ) orelse
        lists:any(fun(#pair{state = St}) -> St =:= waiting end, InList) orelse
        unfreezable(InList) =/= [].

%% Frozen pairs whose foundation has no Waiting or In-Progress pair.
unfreezable(InList) ->
    Busy = [F || #pair{state = St, foundation = F} <- InList, St =:= waiting orelse St =:= in_progress],
    [P || #pair{state = frozen, foundation = F} = P <- InList, not lists:member(F, Busy)].

%% @doc Pick the pair to check when Ta fires: the head of the triggered
%% queue, else the best Waiting pair, after unfreezing one pair per
%% idle foundation when nothing is Waiting.
-spec next_check(#ice{}) -> {pair_id(), triggered | ordinary, #ice{}} | none.
next_check(S) ->
    case has_check(S) of
        false -> none;
        true -> pick(S)
    end.

pick(#ice{triggered = [Id | Rest]} = S) ->
    case pair(Id, S) of
        #pair{in_checklist = true} = P ->
            case needs_check(P, S) of
                true -> {Id, triggered, S#ice{triggered = Rest}};
                false -> next_check(S#ice{triggered = Rest})
            end;
        _ ->
            next_check(S#ice{triggered = Rest})
    end;
pick(#ice{pairs = Ps} = S) ->
    InList = [P || _ := #pair{in_checklist = true} = P <- Ps],
    case [P || #pair{state = waiting} = P <- InList] of
        [] ->
            {Ps2, _} = lists:foldl(
                fun(#pair{id = Id, foundation = F} = P, {Acc, Done}) ->
                    case lists:member(F, Done) of
                        true -> {Acc, Done};
                        false -> {Acc#{Id => P#pair{state = waiting}}, [F | Done]}
                    end
                end,
                {Ps, []},
                lists:sort(fun(A, B) -> order(A) =< order(B) end, unfreezable(InList))
            ),
            pick(S#ice{pairs = Ps2});
        Waiting ->
            [#pair{id = Id} | _] = lists:sort(fun(A, B) -> best_first(A, B) end, Waiting),
            {Id, ordinary, S}
    end.

%% A queued pair that succeeded meanwhile needs no new check (RFC 8445
%% §7.3.1.4), unless the controlling agent nominates it.
needs_check(#pair{state = succeeded, use_candidate = U}, #ice{role = Role}) ->
    U andalso Role =:= controlling;
needs_check(_P, _S) ->
    true.

best_first(#pair{priority = P1, component = C1}, #pair{priority = P2, component = C2}) ->
    P1 > P2 orelse (P1 =:= P2 andalso C1 =< C2).

-spec trigger(pair_id(), #ice{}) -> #ice{}.
trigger(Id, #ice{triggered = T} = S) ->
    case lists:member(Id, T) of
        true -> S;
        false -> S#ice{triggered = T ++ [Id]}
    end.

%% @doc RFC 8445 §7.2.5.3.3: Frozen pairs with the foundation become
%% Waiting.
-spec unfreeze({binary(), binary()}, #ice{}) -> #ice{}.
unfreeze(F, #ice{pairs = Ps} = S) ->
    S#ice{
        pairs = maps:map(
            fun
                (_, #pair{state = frozen, foundation = F2} = P) when F2 =:= F -> P#pair{state = waiting};
                (_, P) -> P
            end,
            Ps
        )
    }.

-spec recompute_priorities(#ice{}) -> #ice{}.
recompute_priorities(#ice{pairs = Ps, role = Role} = S) ->
    S#ice{
        pairs = maps:map(
            fun(_, #pair{local = L, remote = R} = P) ->
                case {local(L, S), remote(R, S)} of
                    {#ice_cand{} = LC, #ice_cand{} = RC} -> P#pair{priority = pair_priority(LC, RC, Role)};
                    _ -> P
                end
            end,
            Ps
        )
    }.

%% @doc Remove the pairs matching `Pred'; returns their in-flight
%% transaction ids so the caller can cancel them.
-spec remove_pairs(fun((#pair{}) -> boolean()), #ice{}) -> {[#pair{}], #ice{}}.
remove_pairs(Pred, #ice{pairs = Ps, triggered = T} = S) ->
    {Gone, Kept} = maps:fold(
        fun(Id, P, {G, K}) ->
            case Pred(P) of
                true -> {[P | G], K};
                false -> {G, K#{Id => P}}
            end
        end,
        {[], #{}},
        Ps
    ),
    GoneIds = [Id || #pair{id = Id} <- Gone],
    {Gone, S#ice{pairs = Kept, triggered = T -- GoneIds}}.

%%--------------------------------------------------------------------
%% Valid list
%%--------------------------------------------------------------------

-spec valid_pairs(1..256, #ice{}) -> [#pair{}].
valid_pairs(Comp, #ice{pairs = Ps}) ->
    lists:sort(
        fun(A, B) -> A#pair.priority >= B#pair.priority end,
        [P || _ := #pair{valid = true, component = C} = P <- Ps, C =:= Comp]
    ).

-spec best_valid(1..256, #ice{}) -> #pair{} | undefined.
best_valid(Comp, S) ->
    case valid_pairs(Comp, S) of
        [P | _] -> P;
        [] -> undefined
    end.

%% @doc True while checks may still produce results.
-spec has_pending(#ice{}) -> boolean().
has_pending(#ice{triggered = [_ | _]}) ->
    true;
has_pending(#ice{pairs = Ps}) ->
    lists:any(
        fun(#pair{state = St, in_checklist = In}) ->
            In andalso (St =:= frozen orelse St =:= waiting orelse St =:= in_progress)
        end,
        maps:values(Ps)
    ).

-spec all_components_valid(#ice{}) -> boolean().
all_components_valid(#ice{components = Cs} = S) ->
    lists:all(fun(C) -> valid_pairs(C, S) =/= [] end, Cs).

%% @doc Inputs of the RFC 8445 §14.3 check RTO: number of pairs in the
%% checklist, and number of Waiting plus In-Progress pairs.
-spec rto_counts(#ice{}) -> {non_neg_integer(), non_neg_integer()}.
rto_counts(#ice{pairs = Ps}) ->
    InList = [P || _ := #pair{in_checklist = true} = P <- Ps],
    Active = [P || #pair{state = St} = P <- InList, St =:= waiting orelse St =:= in_progress],
    {length(InList), length(Active)}.
