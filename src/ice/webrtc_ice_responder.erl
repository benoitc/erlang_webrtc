%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @private
%% @doc Incoming connectivity checks of the ICE agent (RFC 8445 §7.3):
%% short-term credential authentication (RFC 8489 §9.1.3), 400, 401,
%% 420 and 487 responses, role conflict repair, peer-reflexive remote
%% candidates, triggered checks, nomination by the controlling peer and
%% ICE-Lite behavior.
-module(webrtc_ice_responder).

-include("webrtc_ice_int.hrl").

-export([handle_request/6, replay_early/2]).

%% Checks remembered before the remote credentials are known.
-define(MAX_EARLY, 64).

%%====================================================================

%% @doc Binding request received on `Via' from `From'. `Bin' is the raw
%% message, `Msg' its decoding.
-spec handle_request(term(), webrtc_ice_candidate:address(), #stun{}, binary(), integer(), #ice{}) ->
    {#ice{}, [term()]}.
handle_request(Via, From, Msg, Bin, Now, S) ->
    case webrtc_ice_conncheck:has_fingerprint(Msg) of
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
        false -> ok(webrtc_ice_conncheck:switch_role(controlled, S))
    end;
role_check(_Ctl, Cld, #ice{role = controlled, tiebreaker = T} = S) when is_integer(Cld) ->
    case T >= Cld of
        true -> ok(webrtc_ice_conncheck:switch_role(controlling, S));
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
                     webrtc_ice_tcp:pair_via(P, RC, S) =:= Via of
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
                    %% Bounded: one entry per source and local base.
                    Early = {Via, From, LId, Prio, UseCand, RU},
                    Kept = [E || {V, F, L, _, _, _} = E <- S#ice.early, {V, F, L} =/= {Via, From, LId}],
                    Room =
                        case length(Kept) >= ?MAX_EARLY of
                            true -> tl(Kept);
                            false -> Kept
                        end,
                    {S#ice{early = Room ++ [Early]}, []};
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
    #ice_cand{component = Comp, transport = Tr} = webrtc_ice_checklist:local(LId, S),
    case webrtc_ice_checklist:find_remote(Comp, From, Tr, S) of
        error when map_size(S#ice.remote) >= S#ice.max_remote ->
            %% Answered, but no more state for new sources.
            {S, []};
        Found ->
            learned(LId, From, Prio, UseCand, Comp, Found, Now, S)
    end.

learned(LId, From, Prio, UseCand, Comp, Found, Now, S) ->
    {RId, S1} =
        case Found of
            {ok, Id} ->
                {Id, S};
            error ->
                {IP, Port} = From,
                %% Learned on a TCP passive candidate: the peer connected
                %% from an active one (RFC 6544 §7.2).
                {Transport, TcpType} =
                    case webrtc_ice_checklist:local(LId, S) of
                        #ice_cand{transport = tcp} -> {tcp, active};
                        _ -> {udp, undefined}
                    end,
                Cand = #ice_cand{
                    foundation = <<"prflx", (integer_to_binary(S#ice.next_id))/binary>>,
                    component = Comp,
                    transport = Transport,
                    tcptype = TcpType,
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
            webrtc_ice_conncheck:nominated(VId, Now, S);
        [] when Valid ->
            webrtc_ice_conncheck:nominated(Id, Now, S);
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
                    webrtc_ice_conncheck:nominated(Id, Now, webrtc_ice_checklist:put_pair(P1, S1));
                false ->
                    {webrtc_ice_checklist:put_pair(P, S1), []}
            end
    end.

lite_consent(#pair{consent_lost = true} = P, _Now, _S) ->
    P;
lite_consent(#pair{} = P, Now, S) ->
    P#pair{consent_ok = Now, consent_expires = Now + S#ice.consent_expiry}.
