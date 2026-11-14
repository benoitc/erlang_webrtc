%% @private Construction of offers and answers (RFC 9429 §5.2, §5.3) as
%% `#sdp{}' records. Never manipulates SDP text.
-module(webrtc_jsep_build).

-include("webrtc_sdp.hrl").
-include("webrtc_jsep.hrl").

-export([offer/2, answer/2, session/2, media_kind/1]).

-define(PROTO_RTP, <<"UDP/TLS/RTP/SAVPF">>).
-define(PROTO_SCTP, <<"UDP/DTLS/SCTP">>).
-define(NULL_C, #sdp_connection{nettype = <<"IN">>, addrtype = <<"IP4">>, address = <<"0.0.0.0">>}).

-spec media_kind(binary()) -> audio | video | application | other.
media_kind(<<"audio">>) -> audio;
media_kind(<<"video">>) -> video;
media_kind(<<"application">>) -> application;
media_kind(_) -> other.

%%====================================================================
%% Offer
%%====================================================================

%% @doc Build an offer. Media sections keep their position from earlier
%% negotiations; new transceivers and the data section are appended.
%% Returns the offer and the state with mids and m-line indexes assigned.
-spec offer(map(), #jsep{}) -> {#sdp{}, #jsep{}}.
offer(_Opts, J0) ->
    J1 = assign_lines(J0),
    Slots = slots(J1),
    Setup =
        case J1#jsep.dtls_role of
            undefined -> actpass;
            client -> active;
            server -> passive
        end,
    Active = [Mid || {_, Mid, Sec} <- Slots, Sec =/= rejected],
    Tag = case Active of [T | _] -> T; [] -> undefined end,
    Media = [offer_section(Slot, Setup, Tag, J1) || Slot <- Slots],
    Session = session(Active, J1),
    {Session#sdp{media = Media}, J1}.

%% Give every new transceiver (and the data channel) a mid and an m-line.
assign_lines(#jsep{transceivers = Trs} = J) ->
    Used = used_lines(J),
    {Trs1, Next, Mids} = lists:foldl(
        fun
            (#tr{mline = undefined, stopped = false} = T, {Acc, N, Ms}) ->
                Mid = fresh_mid(Ms, T#tr.mid),
                {[T#tr{mline = N, mid = Mid} | Acc], N + 1, [Mid | Ms]};
            (T, {Acc, N, Ms}) ->
                {[T | Acc], N, Ms}
        end,
        {[], Used, all_mids(J)},
        Trs
    ),
    J1 = J#jsep{transceivers = lists:reverse(Trs1)},
    case J1#jsep.want_data andalso J1#jsep.data_mline =:= undefined of
        true -> J1#jsep{data_mline = Next, data_mid = fresh_mid(Mids, undefined)};
        false -> J1
    end.

used_lines(#jsep{transceivers = Trs, data_mline = D}) ->
    Lines = [L || #tr{mline = L} <- Trs, L =/= undefined] ++ [D || D =/= undefined],
    case Lines of
        [] -> 0;
        _ -> lists:max(Lines) + 1
    end.

all_mids(#jsep{transceivers = Trs, data_mid = D}) ->
    [M || #tr{mid = M} <- Trs, M =/= undefined] ++ [D || D =/= undefined].

fresh_mid(Used, undefined) -> fresh_mid(Used, 0);
fresh_mid(Used, Mid) when is_binary(Mid) ->
    case lists:member(Mid, Used) of
        false -> Mid;
        true -> fresh_mid(Used, 0)
    end;
fresh_mid(Used, N) ->
    Mid = integer_to_binary(N),
    case lists:member(Mid, Used) of
        true -> fresh_mid(Used, N + 1);
        false -> Mid
    end.

%% Media sections in m-line order: {Index, Mid, #tr{} | data | rejected}.
slots(#jsep{transceivers = Trs, data_mline = D, data_mid = DM}) ->
    Tr = [
        {L, M, case T#tr.stopped of true -> rejected; false -> T end}
     || #tr{mline = L, mid = M} = T <- Trs, L =/= undefined
    ],
    Data = [{D, DM, data} || D =/= undefined],
    lists:keysort(1, Tr ++ Data).

offer_section({_, Mid, rejected}, _Setup, _Tag, J) ->
    #tr{kind = K} = lists:keyfind(Mid, #tr.mid, J#jsep.transceivers),
    rejected_section(atom_to_binary(K), ?PROTO_RTP, [<<"0">>], Mid);
offer_section({_, Mid, data}, Setup, Tag, J) ->
    data_section(Mid, Setup, Mid =:= Tag, J);
offer_section({_, Mid, #tr{direction = Dir} = T}, Setup, Tag, J) ->
    %% RFC 9429 §5.2.1: a=rid and a=simulcast only when sending.
    Rids =
        case Dir =:= sendrecv orelse Dir =:= sendonly of
            true -> webrtc_jsep_simulcast:offer_attrs(T#tr.encodings);
            false -> []
        end,
    rtp_section(T, Mid, Dir, T#tr.codecs, T#tr.extensions, Setup, Mid =:= Tag, J, Rids).

%%====================================================================
%% Answer
%%====================================================================

%% @doc Build an answer to the pending remote offer. Transceivers were
%% associated with the offered m-lines when the offer was applied.
-spec answer(map(), #jsep{}) -> #sdp{}.
answer(_Opts, #jsep{pending_remote = Offer} = J) ->
    Setup =
        case J#jsep.dtls_role of
            client -> active;
            server -> passive;
            undefined -> answer_setup(Offer)
        end,
    Sections = lists:zip(lists:seq(0, length(Offer#sdp.media) - 1), Offer#sdp.media),
    Built = [answer_section(I, M, Offer, Setup, J) || {I, M} <- Sections],
    Accepted = [Mid || {Mid, #sdp_media{port = P}} <- Built, P =/= 0, Mid =/= undefined],
    Offered = case webrtc_sdp_media:groups(<<"BUNDLE">>, Offer) of
        [G | _] -> G;
        [] -> []
    end,
    Bundle = [M || M <- Offered, lists:member(M, Accepted)],
    Tag = case Bundle of [T | _] -> T; [] -> hd(Accepted ++ [undefined]) end,
    Media = [maybe_candidates(Mid, Tag, Sec, J) || {Mid, Sec} <- Built],
    Session = session(Bundle, J),
    Session#sdp{media = Media}.

%% RFC 8842 §5.3: answer actpass with active.
answer_setup(Offer) ->
    case [S || M <- Offer#sdp.media, {ok, S} <- [webrtc_sdp_media:setup(M, Offer)]] of
        [passive | _] -> active;
        [active | _] -> passive;
        _ -> active
    end.

answer_section(I, #sdp_media{port = 0} = M, _Offer, _Setup, _J) ->
    Mid = webrtc_sdp_media:mid(M),
    {Mid, rejected_section(M#sdp_media.media, M#sdp_media.proto, M#sdp_media.fmts, Mid, I)};
answer_section(I, #sdp_media{media = Kind} = M, Offer, Setup, J) ->
    Mid = webrtc_sdp_media:mid(M),
    Reject = {Mid, rejected_section(Kind, M#sdp_media.proto, M#sdp_media.fmts, Mid, I)},
    case media_kind(Kind) of
        application when Mid =:= J#jsep.data_mid ->
            {Mid, data_section(Mid, Setup, false, J)};
        K when K =:= audio; K =:= video ->
            case lists:keyfind(I, #tr.mline, J#jsep.transceivers) of
                #tr{stopped = false} = T ->
                    Offered = webrtc_sdp_media:codecs(M),
                    Dir = answer_direction(webrtc_sdp_media:direction(M, Offer), T#tr.direction),
                    Codecs = webrtc_jsep_caps:answer_codecs(Offered, T#tr.codecs),
                    Exts = webrtc_jsep_caps:answer_extensions(
                        webrtc_sdp_media:attrs(extmap, M), T#tr.extensions
                    ),
                    Rids = webrtc_jsep_simulcast:answer_attrs(M, Codecs, Exts),
                    case Codecs of
                        [] -> Reject;
                        _ -> {Mid, rtp_section(T, Mid, Dir, Codecs, Exts, Setup, false, J, Rids)}
                    end;
                _ ->
                    Reject
            end;
        _ ->
            Reject
    end.

%% RFC 3264 §6.1 direction rules from the answerer's point of view.
answer_direction(Offered, Desired) ->
    Send = lists:member(Desired, [sendrecv, sendonly]) andalso lists:member(Offered, [sendrecv, recvonly]),
    Recv = lists:member(Desired, [sendrecv, recvonly]) andalso lists:member(Offered, [sendrecv, sendonly]),
    case {Send, Recv} of
        {true, true} -> sendrecv;
        {true, false} -> sendonly;
        {false, true} -> recvonly;
        {false, false} -> inactive
    end.

maybe_candidates(Mid, Mid, Sec, J) -> add_candidates(Sec, J);
maybe_candidates(_, _, Sec, _J) -> Sec.

%%====================================================================
%% Sections
%%====================================================================

session(Bundle, #jsep{} = J) ->
    Group = [{group, #{semantics => <<"BUNDLE">>, mids => Bundle}} || Bundle =/= []],
    Lite = [{ice_lite, true} || J#jsep.ice_lite],
    #sdp{
        origin = #sdp_origin{
            username = <<"-">>,
            sess_id = J#jsep.session_id,
            sess_version = J#jsep.session_version,
            address = <<"127.0.0.1">>
        },
        session_name = <<"-">>,
        times = [#sdp_time{}],
        attributes = Group ++ [{extmap_allow_mixed, true}] ++ Lite
    }.

transport_attrs(Setup, J) ->
    [
        {ice_ufrag, J#jsep.ice_ufrag},
        {ice_pwd, J#jsep.ice_pwd},
        {ice_options, [<<"trickle">>]}
    ] ++
        [{fingerprint, #{hash => H, value => V}} || {H, V} <- J#jsep.fingerprints] ++
        [{setup, Setup}].

%% `Rids' are the a=rid and a=simulcast lines of the section. Layers sent
%% with rids are identified by the RtpStreamId header extension (RFC
%% 8852), so their SSRCs are not announced, as browsers do.
rtp_section(T, Mid, Dir, Codecs, Exts, Setup, Tag, J, Rids) ->
    Sending = Dir =:= sendrecv orelse Dir =:= sendonly,
    Msid = [{msid, #{stream => T#tr.stream_id, track => T#tr.track_id}} || Sending],
    HasRtx = lists:any(fun(#{name := N}) -> string:lowercase(N) =:= <<"rtx">> end, Codecs),
    SendRids = [R || {rid, #{direction := send}} = R <- Rids] =/= [],
    Ssrcs =
        case Sending andalso not SendRids of
            false -> [];
            true -> ssrc_attrs(T, HasRtx, J)
        end,
    Attrs =
        [{rtcp, #{port => 9, connection => ?NULL_C}}] ++
            transport_attrs(Setup, J) ++
            [{mid, Mid}] ++
            [{extmap, #{id => Id, direction => undefined, uri => U, attributes => undefined}}
             || #{id := Id, uri := U} <- Exts] ++
            [{direction, Dir}] ++ Msid ++
            [{rtcp_mux, true}, {rtcp_rsize, true}] ++
            webrtc_sdp_media:codec_attributes(Codecs) ++ Ssrcs ++ Rids,
    Sec = #sdp_media{
        media = atom_to_binary(T#tr.kind),
        port = 9,
        proto = ?PROTO_RTP,
        fmts = [integer_to_binary(Pt) || #{pt := Pt} <- Codecs],
        connections = [?NULL_C],
        attributes = Attrs
    },
    case Tag of
        true -> add_candidates(Sec, J);
        false -> Sec
    end.

ssrc_attrs(T, HasRtx, J) ->
    Ssrcs = [T#tr.ssrc] ++ [T#tr.rtx_ssrc || HasRtx],
    Group = [{ssrc_group, #{semantics => <<"FID">>, ssrcs => Ssrcs}} || HasRtx],
    Group ++
        lists:flatmap(
            fun(S) ->
                [
                    {ssrc, #{ssrc => S, attribute => <<"cname">>, value => J#jsep.cname}},
                    {ssrc, #{
                        ssrc => S,
                        attribute => <<"msid">>,
                        value => <<(T#tr.stream_id)/binary, " ", (T#tr.track_id)/binary>>
                    }}
                ]
            end,
            Ssrcs
        ).

data_section(Mid, Setup, Tag, J) ->
    Sec = #sdp_media{
        media = <<"application">>,
        port = 9,
        proto = ?PROTO_SCTP,
        fmts = [<<"webrtc-datachannel">>],
        connections = [?NULL_C],
        attributes =
            transport_attrs(Setup, J) ++
                [
                    {mid, Mid},
                    {sctp_port, J#jsep.sctp_port},
                    {max_message_size, J#jsep.max_message_size}
                ]
    },
    case Tag of
        true -> add_candidates(Sec, J);
        false -> Sec
    end.

rejected_section(Kind, Proto, Fmts, Mid) ->
    rejected_section(Kind, Proto, Fmts, Mid, 0).

rejected_section(Kind, Proto, Fmts, Mid, _I) ->
    #sdp_media{
        media = Kind,
        port = 0,
        proto = Proto,
        fmts = case Fmts of [] -> [<<"0">>]; _ -> Fmts end,
        connections = [?NULL_C],
        attributes = [{mid, Mid} || Mid =/= undefined]
    }.

%% Candidates gathered so far are included when not trickling (RFC 8839
%% §4.3, RFC 8838 §4).
add_candidates(#sdp_media{attributes = A} = Sec, #jsep{local_candidates = Cs, local_eoc = Eoc}) ->
    Sec#sdp_media{
        attributes = A ++ [{candidate, C} || C <- Cs] ++ [{end_of_candidates, true} || Eoc]
    }.
