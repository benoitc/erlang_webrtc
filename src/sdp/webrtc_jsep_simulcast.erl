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
%% §6.2.2, §6.3, RFC 8853 §5.3.2). A transceiver created with
%% `recv_rids' offers to receive them.
%%
%% Sending as answerer: an offer asking to receive layers (`a=rid' recv
%% lines and `a=simulcast:recv') gives a transceiver without encodings
%% one per offered rid (RFC 9429 §5.10), answered with `a=rid' send lines
%% and `a=simulcast:send'.
%%
%% Layers can only be told apart with the RtpStreamId header extension
%% (RFC 8852): rids are accepted only when that extension is negotiated.
%% Answers never mark streams paused (`~'); the pause marks of the peer
%% are reported in the negotiated parameters, and a layer we send that
%% the peer marked paused starts paused when RTP stream pause (RFC 7728)
%% is negotiated.
-module(webrtc_jsep_simulcast).

-include("webrtc_sdp.hrl").

-export([encodings/2, recv_rids/1, proposed/2, offer_attrs/2, answer_attrs/4, validate/1, negotiated/4]).

-export_type([encoding/0]).

-define(URI_RID, <<"urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id">>).

-type encoding() :: #{
    rid := binary(),
    ssrc := 0..16#FFFFFFFF,
    rtx_ssrc := 0..16#FFFFFFFF,
    restrictions := [{binary(), binary() | undefined}],
    priority => webrtc_dscp:priority()
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
                (maps:with([priority], Spec))#{
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
    Valid = lists:all(fun valid_encoding/1, Encs) andalso
        lists:all(fun(E) -> webrtc_dscp:priority(maps:get(priority, E, low)) =/= error end, Encs),
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

%% @doc Layers to receive from the `recv_rids' option of
%% `add_transceiver': rids, or `#{rid => Rid, paused => true}' to ask
%% for a layer paused from the start (RFC 8853 §5.1).
-spec recv_rids(term()) -> {ok, [{binary(), boolean()}]} | {error, invalid_recv_rids}.
recv_rids(L) when is_list(L) ->
    Rids = [case X of
                #{rid := R} -> {R, maps:get(paused, X, false) =:= true};
                R -> {R, false}
            end || X <- L],
    Ids = [R || {R, _} <- Rids],
    Valid = lists:all(fun(R) -> is_binary(R) andalso valid_encoding(#{rid => R, restrictions => []}) end, Ids),
    case Valid andalso length(lists:usort(Ids)) =:= length(Ids) of
        true -> {ok, Rids};
        false -> {error, invalid_recv_rids}
    end;
recv_rids(_) ->
    {error, invalid_recv_rids}.

%% @doc Encodings proposed by a remote offer that asks to receive
%% simulcast (RFC 9429 §5.10, RFC 8853 §5.3.2), for a transceiver that
%% has none, the first with the transceiver's SSRCs.
-spec proposed(#sdp_media{}, {0..16#FFFFFFFF, 0..16#FFFFFFFF}) -> [encoding()].
proposed(M, {Ssrc, Rtx}) ->
    Lines = [R || #{direction := recv} = R <- webrtc_sdp_media:attrs(rid, M)],
    Ids = [Id || S <- case streams(recv, M) of none -> []; St -> St end, [{Id, _} | _] <- [S]],
    Rids = [Id || Id <- Ids, lists:any(fun(#{id := I}) -> I =:= Id end, Lines)],
    case has_uri(?URI_RID, webrtc_sdp_media:attrs(extmap, M)) andalso length(Rids) > 1 of
        false ->
            [];
        true ->
            [
                #{rid => Rid, ssrc => S, rtx_ssrc => X, restrictions => []}
             || {Rid, {S, X}} <- lists:zip(Rids, [{Ssrc, Rtx} | fresh(length(Rids) - 1)])
            ]
    end.

%%====================================================================
%% Offer (RFC 9429 §5.2.1, RFC 8851 §6.1, RFC 8853 §5.3.1)
%%====================================================================

%% @doc `a=rid' send lines and, with more than one, `a=simulcast:send'
%% for the encodings we send; `a=rid' recv lines and `a=simulcast:recv'
%% for the layers we ask to receive.
-spec offer_attrs([encoding()], [{binary(), boolean()}]) -> [webrtc_sdp:attribute()].
offer_attrs(Encs, Recv) ->
    Send = [{rid, rid_line(send, E)} || E <- Encs],
    RecvLines = [{rid, #{id => Rid, direction => recv, pts => [], params => []}} || {Rid, _} <- Recv],
    Descs = [{send, [[{Rid, false}] || #{rid := Rid} <- Encs]} || length(Encs) > 1] ++
        [{recv, [[{Rid, P}] || {Rid, P} <- Recv]} || length(Recv) > 1],
    Send ++ RecvLines ++ [{simulcast, Descs} || Descs =/= []].

%%====================================================================
%% Answer (RFC 8851 §6.2.2, §6.3, RFC 8853 §5.3.2)
%%====================================================================

%% @doc The `a=rid' and `a=simulcast' lines answering an offered
%% section, given the codecs and header extensions of the answer: recv
%% lines for the layers the offer sends, and send lines for the layers
%% it asks to receive among our encodings `Encs' when we send.
-spec answer_attrs(#sdp_media{}, [map()], [map()], {[encoding()], boolean()}) -> [webrtc_sdp:attribute()].
answer_attrs(M, Codecs, Exts, {Encs, Sending}) ->
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
            Recv = [R1 || #{direction := send} = R <- Unique, {ok, R1} <- [answer_rid(R, recv, Pts, Ids)]],
            Ours = [Rid || Sending, #{rid := Rid} <- Encs],
            Send = [
                R1
             || #{direction := recv, id := Id} = R <- Unique,
                lists:member(Id, Ours),
                {ok, R1} <- [answer_rid(R, send, Pts, Ids)]
            ],
            [{rid, R} || R <- Recv ++ Send] ++
                answer_simulcast(webrtc_sdp_media:attrs(simulcast, M), [Id || #{id := Id} <- Recv], [Id || #{id := Id} <- Send])
    end.

answer_rid(#{pts := Pts, params := Params} = R, Dir, Answered, Ids) ->
    Pts1 = [P || P <- Pts, lists:member(P, Answered)],
    Depend =
        case lists:keyfind(<<"depend">>, 1, Params) of
            {_, V} when is_binary(V) -> lists:all(fun(D) -> lists:member(D, Ids) end, binary:split(V, <<",">>, [global]));
            _ -> true
        end,
    if
        Pts =/= [], Pts1 =:= [] -> error;
        not Depend -> error;
        true -> {ok, R#{direction => Dir, pts => Pts1}}
    end.

%% Exactly one simulcast line, or simulcast is disabled (RFC 8853
%% §5.3.2). The offer's send streams are answered recv and its recv
%% streams send; we never mark a stream paused.
answer_simulcast([Desc], RecvIds, SendIds) ->
    Answer = fun(Offered, Kept) ->
        [S1 || S <- proplists:get_value(Offered, Desc, []), S1 <- [[{Id, false} || {Id, _} <- S, lists:member(Id, Kept)]], S1 =/= []]
    end,
    Recv = Answer(send, RecvIds),
    Send = Answer(recv, SendIds),
    Descs = [{recv, Recv} || Recv =/= []] ++ [{send, Send} || Send =/= []],
    [{simulcast, Descs} || Descs =/= []];
answer_simulcast(_, _, _) ->
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
%% `Answerer' when the local description is the answer: its send rids
%% are then the accepted ones.
-spec negotiated([encoding()], #sdp_media{}, #sdp_media{}, boolean()) ->
    #{send_rids := [map()], recv_rids := [map()]}.
negotiated(Encs, L, R, Answerer) ->
    #{send_rids => send_rids(Encs, L, R, Answerer), recv_rids => recv_rids(L, R)}.

%% RFC 8851 §6.4 and RFC 8853 §5.3.3. Without simulcast in the answer
%% only the first encoding is sent (RFC 9429 §3.7).
send_rids([], _L, _R, _Answerer) ->
    [];
send_rids([First | _] = Encs, L, R, Answerer) ->
    Offered = [X || #{direction := send} = X <- webrtc_sdp_media:attrs(rid, L)],
    Accepted = [
        Id
     || #{id := Id, direction := recv} = A <- webrtc_sdp_media:attrs(rid, R),
        #{id := OId} = O <- Offered,
        OId =:= Id,
        Answerer orelse answer_acceptable(A, O, R, L)
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

layer(#{rid := Rid, ssrc := S, rtx_ssrc := X} = E, Paused) ->
    (maps:with([priority], E))#{rid => Rid, ssrc => S, rtx_ssrc => X, paused => Paused}.

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
