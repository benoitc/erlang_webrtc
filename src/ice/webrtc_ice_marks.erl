%% @private
%% @doc Blocked DSCP marks on the selected pair (RFC 8835 §4.2, its
%% suggested method). Each consent request goes once more per DSCP the
%% flows use, with that DSCP in the IP header; a marked request that
%% three times in a row gets no answer while the unmarked ones do means
%% the network drops that mark, and the owner gets
%% `{dscp_blocked, Dscp}' to send those flows unmarked. Connectivity
%% checks before selection stay unmarked.
-module(webrtc_ice_marks).

-include("webrtc_ice_int.hrl").

-export([set/2, requests/6, response/4, tick/2, next_timeout/1]).

%% A marked request unanswered this long counts as lost.
-define(TIMEOUT, 3000).
-define(MISSES, 3).

%% @doc The DSCPs to probe.
-spec set([1..63], #ice{}) -> #ice{}.
set(Marks, S) ->
    Keep = lists:usort(Marks),
    S#ice{marks = Keep, mark_miss = maps:with(Keep, S#ice.mark_miss),
          mark_tx = #{T => V || T := {D, _} = V <- S#ice.mark_tx, lists:member(D, Keep)}}.

%% @doc Marked copies of a consent request on `Via' to `To' with
%% credentials `{LocalUfrag, RemoteUfrag}', the remote key and the
%% PRIORITY of the request.
-spec requests(term(), term(), {binary(), binary()}, {binary(), pos_integer()}, integer(), #ice{}) ->
    {#ice{}, [term()]}.
requests(_Via, _To, _Users, _Key, _Now, #ice{marks = []} = S) ->
    {S, []};
requests(Via, To, Users, {RP, Prio}, Now, S) when not is_tuple(Via), Via =/= none ->
    lists:foldl(
        fun(D, {SA, AA}) ->
            Msg = webrtc_ice_conncheck:binding_request(Users, Prio, false, SA),
            Bin = webrtc_stun:encode(Msg, #{integrity => {sha1, RP}, fingerprint => true}),
            SB = SA#ice{mark_tx = (SA#ice.mark_tx)#{Msg#stun.txid => {D, Now}}},
            {SB, AA ++ [{send_tos, Via, To, D bsl 2, Bin}]}
        end,
        {S, []},
        S#ice.marks
    );
requests(_Via, _To, _Users, _Key, _Now, S) ->
    %% Relayed and TCP paths are not probed.
    {S, []}.

%% @doc A response to a marked request: the mark gets through.
-spec response(binary(), #stun{}, binary(), #ice{}) -> {ok, #ice{}} | none.
response(TxId, Msg, Bin, #ice{mark_tx = Tx} = S) ->
    case maps:take(TxId, Tx) of
        {{D, _}, Tx1} ->
            Ok = Msg#stun.class =:= success andalso S#ice.remote_pwd =/= undefined andalso
                webrtc_stun:check_integrity(Bin, S#ice.remote_pwd) =:= ok,
            Miss = case Ok of
                       true -> maps:remove(D, S#ice.mark_miss);
                       false -> S#ice.mark_miss
                   end,
            {ok, S#ice{mark_tx = Tx1, mark_miss = Miss}};
        error ->
            none
    end.

%% @doc Requests that timed out; a mark missed ?MISSES times in a row
%% while consent holds is reported and no longer probed.
-spec tick(integer(), #ice{}) -> {#ice{}, [term()]}.
tick(Now, #ice{mark_tx = Tx} = S) ->
    {Late, Pending} = maps:fold(
        fun(_T, {D, At}, {L, P}) when Now - At >= ?TIMEOUT -> {[D | L], P};
           (T, V, {L, P}) -> {L, P#{T => V}}
        end,
        {[], #{}},
        Tx
    ),
    Miss = lists:foldl(fun(D, Acc) -> maps:update_with(D, fun(N) -> N + 1 end, 1, Acc) end, S#ice.mark_miss, Late),
    Alive = consent_holds(Now, S),
    Blocked = [D || D := N <- Miss, N >= ?MISSES, Alive],
    S1 = S#ice{mark_tx = Pending, mark_miss = maps:without(Blocked, Miss), marks = S#ice.marks -- Blocked},
    {S1, [{event, {dscp_blocked, D}} || D <- lists:sort(Blocked)]}.

%% The unmarked requests are answered: consent was refreshed lately.
consent_holds(Now, S) ->
    lists:any(fun(Id) ->
                      case webrtc_ice_checklist:pair(Id, S) of
                          #pair{consent_ok = Ok} when is_integer(Ok) -> Now - Ok < 2 * S#ice.consent_interval;
                          _ -> false
                      end
              end, maps:values(S#ice.selected)).

-spec next_timeout(#ice{}) -> integer() | infinity.
next_timeout(#ice{mark_tx = Tx}) ->
    lists:min([infinity | [At + ?TIMEOUT || _ := {_, At} <- Tx]]).
