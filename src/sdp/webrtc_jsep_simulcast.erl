%% @private RTP stream identifiers (RFC 8851) and simulcast (RFC 8853)
%% for JSEP (RFC 9429 §5.2.1, §5.3.1, §5.8, §5.9).
%%
%% Sending: a transceiver created with several `send_encodings' offers
%% one `a=rid:<id> send' line per encoding and `a=simulcast:send' listing
%% them. The answer decides which layers are sent (RFC 8851 §6.4, RFC
%% 8853 §5.3.3).
%%
%% Receiving: `a=rid' send lines and `a=simulcast:send' of an offer are
%% answered with `a=rid' recv lines and `a=simulcast:recv' (RFC 8851
%% §6.2.2, §6.3, RFC 8853 §5.3.2).
%%
%% Layers can only be told apart with the RtpStreamId header extension
%% (RFC 8852): rids are accepted only when that extension is negotiated.
%% RTP stream pause/resume (RFC 7728) is not implemented, so streams are
%% never marked paused (`~') in our descriptions; the pause marks of the
%% peer are reported in the negotiated parameters.
-module(webrtc_jsep_simulcast).

-include("webrtc_sdp.hrl").

-export([encodings/2, offer_attrs/1, answer_attrs/3, validate/1, negotiated/3]).

-export_type([encoding/0]).

-define(URI_RID, <<"urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id">>).

-type encoding() :: #{
    rid := binary(),
    ssrc := 0..16#FFFFFFFF,
    rtx_ssrc := 0..16#FFFFFFFF,
    restrictions := [{binary(), binary() | undefined}]
}.

%%====================================================================
%% Encodings of a transceiver
%%====================================================================

%% @doc Encodings from the `send_encodings' option of `add_transceiver'.
%% `Primary' are the SSRCs of the transceiver, used by the first
%% encoding. One encoding without a rid means no rid (RFC 9429 §5.2.1);
%% missing rids are generated from a counter.
-spec encodings(term(), {0..16#FFFFFFFF, 0..16#FFFFFFFF}) -> {ok, [encoding()]} | {error, term()}.
encodings([], _Primary) ->
    {ok, []};
encodings([#{} = Only], _Primary) when not is_map_key(rid, Only) ->
    {ok, []};
encodings(Specs, {Ssrc, Rtx}) when is_list(Specs) ->
    case lists:all(fun is_map/1, Specs) of
        false ->
            {error, invalid_encodings};
        true ->
            Given = [R || #{rid := R} <- Specs],
            Rids = fill_rids(Specs, Given, 0),
            Encs = [
                #{
                    rid => Rid,
                    ssrc => S,
                    rtx_ssrc => X,
                    restrictions => maps:get(restrictions, Spec, [])
                }
             || {Rid, Spec, {S, X}} <- lists:zip3(Rids, Specs, [{Ssrc, Rtx} | fresh(length(Specs) - 1)])
            ],
            check_encodings(Encs)
    end;
encodings(_, _) ->
    {error, invalid_encodings}.

fill_rids([], _Used, _N) ->
    [];
fill_rids([#{rid := R} | Rest], Used, N) ->
    [R | fill_rids(Rest, Used, N)];
fill_rids([_ | Rest], Used, N) ->
    Rid = integer_to_binary(N),
    case lists:member(Rid, Used) of
        true -> fill_rids([#{} | Rest], Used, N + 1);
        false -> [Rid | fill_rids(Rest, [Rid | Used], N + 1)]
    end.

fresh(N) -> [{ssrc(), ssrc()} || _ <- lists:seq(1, N)].

check_encodings(Encs) ->
    Rids = [R || #{rid := R} <- Encs],
    Valid = lists:all(fun valid_encoding/1, Encs),
    Unique = length(lists:usort(Rids)) =:= length(Rids),
    case Valid andalso Unique of
        true -> {ok, Encs};
        false -> {error, invalid_encodings}
    end.

valid_encoding(#{rid := Rid, restrictions := Params} = E) when is_binary(Rid), is_list(Params) ->
    try
        _ = iolist_to_binary(webrtc_sdp_rid:encode(rid, rid_line(send, E))),
        true
    catch
        error:_ -> false
    end;
valid_encoding(_) ->
    false.

rid_line(Dir, #{rid := Rid, restrictions := Params}) ->
    #{id => Rid, direction => Dir, pts => [], params => Params}.

%%====================================================================
%% Offer (RFC 9429 §5.2.1, RFC 8851 §6.1, RFC 8853 §5.3.1)
%%====================================================================

%% @doc `a=rid' send lines and, with more than one, `a=simulcast:send'.
-spec offer_attrs([encoding()]) -> [webrtc_sdp:attribute()].
offer_attrs([]) ->
    [];
offer_attrs(Encs) ->
    Rids = [{rid, rid_line(send, E)} || E <- Encs],
    Sim = [{simulcast, [{send, [[{Rid, false}] || #{rid := Rid} <- Encs]}]} || length(Encs) > 1],
    Rids ++ Sim.

%%====================================================================
%% Answer (RFC 8851 §6.2.2, §6.3, RFC 8853 §5.3.2)
%%====================================================================

%% @doc `a=rid' recv lines and `a=simulcast:recv' answering the send
%% layers of an offered section, given the codecs and header extensions
%% of the answer. Offered recv rids (a request that we send simulcast)
%% are discarded: JSEP has no way to configure that from an incoming
%% offer (RFC 9429 §3.7).
-spec answer_attrs(#sdp_media{}, [map()], [map()]) -> [webrtc_sdp:attribute()].
answer_attrs(M, Codecs, Exts) ->
    case has_uri(?URI_RID, Exts) of
        false ->
            [];
        true ->
            Offered = webrtc_sdp_media:attrs(rid, M),
            AllIds = [Id || #{id := Id} <- Offered],
            %% §6.2.2 step 2: every line with a duplicated rid-id goes.
            Unique = [R || #{id := Id} = R <- Offered, count(Id, AllIds) =:= 1],
            Ids = [Id || #{id := Id} <- Unique],
            Pts = [Pt || #{pt := Pt} <- Codecs],
            Kept = [R1 || #{direction := send} = R <- Unique, {ok, R1} <- [answer_rid(R, Pts, Ids)]],
            KeptIds = [Id || #{id := Id} <- Kept],
            [{rid, R} || R <- Kept] ++ answer_simulcast(webrtc_sdp_media:attrs(simulcast, M), KeptIds)
    end.

answer_rid(#{pts := Pts, params := Params} = R, Answered, Ids) ->
    Pts1 = [P || P <- Pts, lists:member(P, Answered)],
    Depend =
        case lists:keyfind(<<"depend">>, 1, Params) of
            {_, V} when is_binary(V) -> lists:all(fun(D) -> lists:member(D, Ids) end, binary:split(V, <<",">>, [global]));
            _ -> true
        end,
    if
        Pts =/= [], Pts1 =:= [] -> error;
        not Depend -> error;
        true -> {ok, R#{direction => recv, pts => Pts1}}
    end.

%% Exactly one simulcast line, or simulcast is disabled (RFC 8853 §5.3.2).
answer_simulcast([Desc], KeptIds) ->
    Streams = [
        S1
     || S <- proplists:get_value(send, Desc, []),
        %% Without pause/resume we must not mark streams paused.
        S1 <- [[{Id, false} || {Id, _Paused} <- S, lists:member(Id, KeptIds)]],
        S1 =/= []
    ],
    [{simulcast, [{recv, Streams}]} || Streams =/= []];
answer_simulcast(_, _) ->
    [].

%%====================================================================
%% Validation (RFC 9429 §5.8.3)
%%====================================================================

%% @doc Every rid-id of `a=simulcast' exists as an `a=rid' line.
-spec validate(#sdp_media{}) -> ok | {error, unknown_rid}.
validate(M) ->
    Ids = [Id || #{id := Id} <- webrtc_sdp_media:attrs(rid, M)],
    Used = [Id || Desc <- webrtc_sdp_media:attrs(simulcast, M), {_, Streams} <- Desc, S <- Streams, {Id, _} <- S],
    case lists:all(fun(Id) -> lists:member(Id, Ids) end, Used) of
        true -> ok;
        false -> {error, unknown_rid}
    end.

%%====================================================================
%% Negotiated layers
%%====================================================================

%% @doc Layers we send and layers we receive for one m= section, from
%% the local and remote sections and the encodings of the transceiver.
-spec negotiated([encoding()], #sdp_media{}, #sdp_media{}) ->
    #{send_rids := [map()], recv_rids := [map()]}.
negotiated(Encs, L, R) ->
    #{send_rids => send_rids(Encs, L, R), recv_rids => recv_rids(L, R)}.

%% RFC 8851 §6.4 and RFC 8853 §5.3.3. Without simulcast in the answer
%% only the first encoding is sent (RFC 9429 §3.7).
send_rids([], _L, _R) ->
    [];
send_rids([First | _] = Encs, L, R) ->
    Offered = [X || #{direction := send} = X <- webrtc_sdp_media:attrs(rid, L)],
    Accepted = [
        Id
     || #{id := Id, direction := recv} = A <- webrtc_sdp_media:attrs(rid, R),
        #{id := OId} = O <- Offered,
        OId =:= Id,
        answer_acceptable(A, O, R, L)
    ],
    case has_uri(?URI_RID, webrtc_sdp_media:attrs(extmap, R)) of
        false ->
            [];
        true ->
            case streams(recv, R) of
                none ->
                    [layer(First, false) || lists:member(maps:get(rid, First), Accepted)];
                Streams ->
                    [
                        layer(E, Paused)
                     || #{rid := Rid} = E <- Encs,
                        lists:member(Rid, Accepted),
                        {ok, Paused} <- [in_streams(Rid, Streams)]
                    ]
            end
    end.

layer(#{rid := Rid, ssrc := S, rtx_ssrc := X}, Paused) ->
    #{rid => Rid, ssrc => S, rtx_ssrc => X, paused => Paused}.

%% RFC 8851 §6.4 steps 2 to 5.
answer_acceptable(#{pts := APts, params := AParams}, #{pts := OPts, params := OParams}, R, L) ->
    Restrictions = lists:all(
        fun({N, V}) ->
            case lists:keyfind(N, 1, OParams) of
                false -> false;
                {_, undefined} -> true;
                {_, OV} -> more_restrictive(N, V, OV)
            end
        end,
        AParams
    ),
    Pts =
        case {APts, OPts} of
            {[], _} -> true;
            {_, []} -> false;
            _ -> same_formats(APts, R, OPts, L)
        end,
    Restrictions andalso Pts.

more_restrictive(<<"max-", _/binary>>, V, OV) ->
    case {number(V), number(OV)} of
        {{ok, A}, {ok, B}} -> A =< B;
        _ -> false
    end;
more_restrictive(_, V, OV) ->
    V =:= OV.

number(undefined) ->
    error;
number(B) ->
    try
        {ok, binary_to_integer(B)}
    catch
        error:badarg ->
            try
                {ok, binary_to_float(B)}
            catch
                error:badarg -> error
            end
    end.

%% Payload types are compared by codec, not by number (§6.4 step 5).
same_formats(APts, R, OPts, L) ->
    RC = webrtc_sdp_media:codecs(R),
    LC = webrtc_sdp_media:codecs(L),
    Offered = [C || #{pt := Pt} = C <- LC, lists:member(Pt, OPts)],
    lists:all(
        fun(Pt) ->
            case [C || #{pt := P} = C <- RC, P =:= Pt] of
                [C | _] -> lists:any(fun(O) -> webrtc_jsep_caps:same_codec(C, O) end, Offered);
                [] -> false
            end
        end,
        APts
    ).

%% Receive layers: our recv rids matched by send rids of the peer, in
%% the order of our simulcast recv description when there is one.
recv_rids(L, R) ->
    case has_uri(?URI_RID, webrtc_sdp_media:attrs(extmap, L)) of
        false ->
            [];
        true ->
            Remote = [Id || #{id := Id, direction := send} <- webrtc_sdp_media:attrs(rid, R)],
            Local = [Id || #{id := Id, direction := recv} <- webrtc_sdp_media:attrs(rid, L)],
            Matched = [Id || Id <- Local, lists:member(Id, Remote)],
            Ids =
                case streams(recv, L) of
                    none -> Matched;
                    Streams -> [Id || S <- Streams, {Id, _} <- S, lists:member(Id, Matched)]
                end,
            RemoteStreams =
                case streams(send, R) of
                    none -> [];
                    RS -> RS
                end,
            [
                #{rid => Id, paused => in_streams(Id, RemoteStreams) =:= {ok, true}}
             || Id <- Ids
            ]
    end.

streams(Dir, M) ->
    case webrtc_sdp_media:attrs(simulcast, M) of
        [Desc] ->
            case proplists:get_value(Dir, Desc) of
                undefined -> none;
                Streams -> Streams
            end;
        _ ->
            none
    end.

in_streams(Rid, Streams) ->
    case [P || S <- Streams, {Id, P} <- S, Id =:= Rid] of
        [P | _] -> {ok, P};
        [] -> error
    end.

has_uri(Uri, Exts) ->
    lists:any(fun(#{uri := U}) -> U =:= Uri end, Exts).

count(X, L) -> length([Y || Y <- L, Y =:= X]).

ssrc() ->
    <<S:32>> = crypto:strong_rand_bytes(4),
    case S of
        0 -> ssrc();
        _ -> S
    end.
