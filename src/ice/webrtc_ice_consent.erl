%% @private
%% @doc Consent freshness (RFC 7675) and keepalives (RFC 8445 §11) on
%% the selected pairs, and on the pairs kept alive across an ICE
%% restart.
%%
%% <ul>
%% <li>A full agent sends a consent request (an authenticated Binding
%%     request, sent once, new transaction id) every `consent_interval'
%%     randomized between 0.8 and 1.2 times. Any matching authenticated
%%     success response from the remote address, received on the same
%%     path, refreshes consent for `consent_expiry' (30 s). A response may
%%     answer any outstanding consent request.</li>
%% <li>An authenticated 403 response revokes consent at once (§5.2).</li>
%% <li>When consent expires the pair is marked lost, outstanding consent
%%     transactions are dropped and `{consent_lost, Local, Remote}' is
%%     emitted. The agent refuses to send data on the pair afterwards.</li>
%% <li>Consent requests also keep NAT bindings open, so no Binding
%%     indication is sent while consent runs (RFC 7675 §4). With consent
%%     disabled, and for lite agents, a Binding indication with only
%%     FINGERPRINT is sent when nothing was sent on the pair for
%%     `keepalive_interval' (Tr, 15 s).</li>
%% <li>A lite agent never sends requests; its consent is refreshed by the
%%     authenticated checks of the full peer (local policy, documented in
%%     docs/compliance/ice.md).</li>
%% </ul>
-module(webrtc_ice_consent).

-include("webrtc_ice_int.hrl").

-export([tick/2, match/2, response/7, next_timeout/1, usable/2]).

%% A consent target: where the pair lives, its component, the pair,
%% its remote candidate and the credentials {LocalUfrag, RemoteUfrag,
%% RemotePwd} to use.
-type where() :: current | prev.

%% Consent runs on the pair data would use: the selected pair, or the
%% best valid pair before nomination (RFC 8445 §12.1).
targets(#ice{prev = Prev} = S) ->
    Current = [{current, C, P, webrtc_ice_checklist:remote(P#pair.remote, S),
                {S#ice.ufrag, S#ice.remote_ufrag, S#ice.remote_pwd}}
               || C <- S#ice.components, #pair{} = P <- [active(C, S)]],
    Old =
        case Prev of
            #prev{pairs = PP, ufrag = U, remote_ufrag = RU, remote_pwd = RP} ->
                [{prev, C, P, RC, {U, RU, RP}} || C := {P, RC} <- PP];
            undefined ->
                []
        end,
    Current ++ Old.

active(C, #ice{selected = Sel} = S) ->
    case maps:find(C, Sel) of
        {ok, Id} -> webrtc_ice_checklist:pair(Id, S);
        error when S#ice.lite -> undefined;
        error -> webrtc_ice_checklist:best_valid(C, S)
    end.

put(current, _C, P, S) -> webrtc_ice_checklist:put_pair(P, S);
put(prev, C, P, #ice{prev = #prev{pairs = PP} = Pv} = S) ->
    {_, RC} = maps:get(C, PP),
    S#ice{prev = Pv#prev{pairs = PP#{C => {P, RC}}}}.

%% @doc True when data may be sent on the pair.
-spec usable(#pair{}, integer()) -> boolean().
usable(#pair{consent_lost = true}, _Now) -> false;
usable(#pair{consent_expires = undefined}, _Now) -> false;
usable(#pair{consent_expires = E}, Now) -> Now < E.

-spec tick(integer(), #ice{}) -> {#ice{}, [term()]}.
tick(Now, S) ->
    lists:foldl(
        fun(T, {SA, AA}) ->
            {SB, AB} = tick_one(T, Now, SA),
            {SB, AA ++ AB}
        end,
        {S, []},
        targets(S)
    ).

tick_one({_W, _C, #pair{consent_lost = true}, _RC, _Cr}, _Now, S) ->
    {S, []};
tick_one({W, C, P, RC, Creds}, Now, #ice{consent = true} = S) when
    P#pair.consent_expires =/= undefined, Now >= P#pair.consent_expires
->
    _ = Creds,
    lost(W, C, P, RC, S);
tick_one({W, C, P, RC, Creds}, Now, #ice{consent = true, lite = false} = S) ->
    case P#pair.consent_next of
        Next when is_integer(Next), Now >= Next -> request(W, C, P, RC, Creds, Now, S);
        _ -> {S, []}
    end;
tick_one({W, C, P, RC, _Creds}, Now, S) ->
    case keepalive_due(P, Now, S) of
        true -> keepalive(W, C, P, RC, Now, S);
        false -> {S, []}
    end.

lost(W, C, P, RC, S) ->
    P1 = P#pair{consent_lost = true, consent_txids = []},
    Local = webrtc_ice_checklist:local(P#pair.local, S),
    {put(W, C, P1, S), [{event, {consent_lost, Local, RC}}]}.

request(W, C, P, RC, {LU, RU, RP}, Now, S) ->
    Base = webrtc_ice_checklist:pair_local(P, S),
    Prio = webrtc_ice_candidate:priority(prflx, (Base#ice_cand.priority bsr 8) band 16#FFFF, C),
    Msg = webrtc_ice_conncheck:binding_request({LU, RU}, Prio, false, S),
    Bin = webrtc_stun:encode(Msg, #{integrity => {sha1, RP}, fingerprint => true}),
    {J, R} = rand:uniform_s(S#ice.rand),
    Interval = round(S#ice.consent_interval * (0.8 + 0.4 * J)),
    Keep = [{T, At} || {T, At} <- P#pair.consent_txids, Now - At < S#ice.consent_expiry],
    P1 = P#pair{
        consent_next = Now + Interval,
        consent_txids = [{Msg#stun.txid, Now} | Keep],
        last_sent = Now,
        requests_sent = P#pair.requests_sent + 1,
        consent_requests = P#pair.consent_requests + 1
    },
    S1 = put(W, C, P1, S#ice{rand = R}),
    Via = webrtc_ice_tcp:pair_via(P1, RC, S1),
    To = webrtc_ice_candidate:transport_address(RC),
    {S2, Acts} = webrtc_ice_gather:route(Via, To, Bin, Now, ?INC(consent_sent, S1)),
    %% RFC 8835 §4.2: the same with each DSCP in use, on the current pair.
    case W of
        current ->
            {S3, Marked} = webrtc_ice_marks:requests(Via, To, {LU, RU}, {RP, Prio}, Now, S2),
            {S3, Acts ++ Marked};
        prev ->
            {S2, Acts}
    end.

keepalive_due(#pair{last_sent = undefined}, _Now, _S) -> true;
keepalive_due(#pair{last_sent = L}, Now, #ice{keepalive_interval = Tr}) -> Now - L >= Tr.

keepalive(W, C, P, RC, Now, S) ->
    Bin = webrtc_stun:encode(webrtc_stun:indication(binding, []), #{fingerprint => true}),
    S1 = put(W, C, P#pair{last_sent = Now}, S),
    webrtc_ice_gather:route(webrtc_ice_tcp:pair_via(P, RC, S1), webrtc_ice_candidate:transport_address(RC),
                            Bin, Now, ?INC(keepalives_sent, S1)).

%% @doc Find the consent target owning a transaction id.
-spec match(binary(), #ice{}) -> {where(), 1..256} | none.
match(TxId, S) ->
    case [{W, C} || {W, C, #pair{consent_txids = Ts}, _, _} <- targets(S), lists:keymember(TxId, 1, Ts)] of
        [Hit | _] -> Hit;
        [] -> none
    end.

%% @doc Response to a consent request.
-spec response({where(), 1..256}, term(), webrtc_ice_candidate:address(), #stun{}, binary(), integer(),
               #ice{}) -> {#ice{}, [term()]}.
response({W, C}, Via, From, #stun{txid = TxId} = Msg, Bin, Now, S) ->
    [{W, C, P, RC, {_, _, RP}}] = [T || {W2, C2, _, _, _} = T <- targets(S), W2 =:= W, C2 =:= C],
    Symmetric =
        Via =:= webrtc_ice_tcp:pair_via(P, RC, S) andalso
            From =:= webrtc_ice_candidate:transport_address(RC),
    Authentic =
        webrtc_ice_conncheck:has_fingerprint(Msg) andalso webrtc_stun:check_integrity(Bin, RP) =:= ok,
    case Symmetric andalso Authentic of
        false ->
            {?INC(bad_responses, S), []};
        true ->
            {value, {_, SentAt}, Rest} = lists:keytake(TxId, 1, P#pair.consent_txids),
            P1 = P#pair{consent_txids = Rest, responses_received = P#pair.responses_received + 1},
            case Msg#stun.class of
                success ->
                    P2 = P1#pair{
                        consent_ok = Now,
                        consent_expires = Now + S#ice.consent_expiry,
                        rtt = Now - SentAt,
                        total_rtt = P1#pair.total_rtt + (Now - SentAt)
                    },
                    {put(W, C, P2, S), []};
                error ->
                    case webrtc_stun:get(error_code, Msg) of
                        {ok, {403, _}} -> lost(W, C, P1, RC, S);
                        _ -> {put(W, C, P1, S), []}
                    end
            end
    end.

-spec next_timeout(#ice{}) -> integer() | infinity.
next_timeout(S) ->
    lists:min([infinity | lists:flatmap(fun(T) -> deadlines(T, S) end, targets(S))]).

deadlines({_, _, #pair{consent_lost = true}, _, _}, _S) ->
    [];
deadlines({_, _, P, _, _}, #ice{consent = true, lite = false}) ->
    [X || X <- [P#pair.consent_next, P#pair.consent_expires], is_integer(X)];
deadlines({_, _, P, _, _}, #ice{consent = Consent, keepalive_interval = Tr}) ->
    Keep =
        case P#pair.last_sent of
            undefined -> [0];
            L -> [L + Tr]
        end,
    Exp = [E || Consent, E <- [P#pair.consent_expires], is_integer(E)],
    Keep ++ Exp.
