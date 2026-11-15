%% @private Construction of offers and answers (RFC 9429 §5.2, §5.3) as
%% `#sdp{}' records. Never manipulates SDP text.
-module(webrtc_jsep_build).

-include("webrtc_sdp.hrl").
-include("webrtc_jsep.hrl").

-export([offer/2, answer/2, session/2, media_kind/1, creds/3]).

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
    Order = [Mid || {_, Mid, _} <- Slots],
    Groups = webrtc_jsep_transport:offer(J1#jsep.groups, Active, Order, J1#jsep.bundle),
    J2 = ensure_creds(Groups, J1),
    Media = [offer_section(Slot, Setup, (ctx(Mid, Groups, J2))#{cryptex => J2#jsep.cryptex}, J2) || {_, Mid, _} = Slot <- Slots],
    Session = session(webrtc_jsep_transport:bundles(Groups), J2),
    {Session#sdp{media = Media}, J2}.

%% Transport of a section: its credentials and candidates; the first
%% section of a transport (its tag) carries the candidates.
ctx(Mid, Groups, J) ->
    Key = webrtc_jsep_transport:key_of(Mid, Groups),
    #{creds => creds(Key, Groups, J), tag => Mid =:= Key andalso Key =/= undefined, cands => cands(Key, Groups, J)}.

%% @doc Local ICE credentials of a transport: the first one uses the
%% engine's ufrag and password, the others their own.
-spec creds(binary() | undefined, [webrtc_jsep_transport:group()], #jsep{}) -> {binary(), binary()}.
creds(Key, Groups, J) ->
    case {Groups, maps:find(Key, J#jsep.ice_extra)} of
        {[{Key, _, _} | _], _} -> {J#jsep.ice_ufrag, J#jsep.ice_pwd};
        {_, {ok, C}} -> C;
        {_, error} -> {J#jsep.ice_ufrag, J#jsep.ice_pwd}
    end.

cands(Key, Groups, J) ->
    case {Groups, maps:find(Key, J#jsep.local_cands)} of
        {[{Key, _, _} | _], _} -> {J#jsep.local_candidates, J#jsep.local_eoc};
        {_, {ok, C}} -> C;
        {_, error} -> {[], false}
    end.

%% Every transport after the first gets credentials of its own (RFC 8445
%% §5.3); they stay the same across renegotiations.
ensure_creds([_ | Rest], J) ->
    Extra = lists:foldl(
        fun({Key, _, _}, Acc) ->
            case maps:is_key(Key, Acc) of
                true -> Acc;
                false -> Acc#{Key => {webrtc_ice_candidate:random_ufrag(), webrtc_ice_candidate:random_pwd()}}
            end
        end,
        J#jsep.ice_extra,
        Rest
    ),
    J#jsep{ice_extra = Extra};
ensure_creds([], J) ->
    J.

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

offer_section({_, Mid, rejected}, _Setup, _Ctx, J) ->
    #tr{kind = K} = lists:keyfind(Mid, #tr.mid, J#jsep.transceivers),
    rejected_section(atom_to_binary(K), ?PROTO_RTP, [<<"0">>], Mid);
offer_section({_, Mid, data}, Setup, Ctx, J) ->
    data_section(Mid, Setup, Ctx, J);
offer_section({_, Mid, #tr{direction = Dir} = T}, Setup, Ctx, J) ->
    %% RFC 9429 §5.2.1: a=rid and a=simulcast only when sending.
    Send = [E || Dir =:= sendrecv orelse Dir =:= sendonly, E <- T#tr.encodings],
    Recv = [R || Dir =:= sendrecv orelse Dir =:= recvonly, R <- T#tr.recv_rids],
    Rids = webrtc_jsep_simulcast:offer_attrs(Send, Recv),
    rtp_section(T, Mid, Dir, T#tr.codecs, T#tr.extensions, Setup, Ctx, J, Rids).

%%====================================================================
%% Answer
%%====================================================================

%% @doc Build an answer to the pending remote offer. Transceivers were
%% associated with the offered m-lines when the offer was applied.
-spec answer(map(), #jsep{}) -> {#sdp{}, #jsep{}}.
answer(_Opts, #jsep{pending_remote = Offer} = J) ->
    Setup =
        case J#jsep.dtls_role of
            client -> active;
            server -> passive;
            undefined -> answer_setup(Offer)
        end,
    Sections = lists:zip(lists:seq(0, length(Offer#sdp.media) - 1), Offer#sdp.media),
    %% First pass: which sections are accepted. Every offered BUNDLE
    %% group keeps its accepted sections together, the first one as the
    %% tag; an unbundled section keeps its own transport (RFC 9143 §7.3).
    Probe = #{creds => {J#jsep.ice_ufrag, J#jsep.ice_pwd}, tag => false, cands => {[], false}},
    Accepted = [Mid || {Mid, #sdp_media{port = P}} <- [answer_section(I, M, Offer, Setup, Probe, J) || {I, M} <- Sections],
                       P =/= 0, Mid =/= undefined],
    Groups = lists:filtermap(
        fun({_, Ms, Bundled}) ->
            case [M || M <- Ms, lists:member(M, Accepted)] of
                [] -> false;
                [First | _] = A -> {true, {First, A, Bundled}}
            end
        end,
        webrtc_jsep_transport:groups(Offer)
    ),
    J1 = ensure_creds(Groups, J),
    Cryptex = cryptex_mids(Groups, Offer, J1),
    Media = [
        element(2, answer_section(I, M, Offer, Setup, (ctx(Mid, Groups, J1))#{cryptex => lists:member(Mid, Cryptex)}, J1))
     || {I, M} <- Sections, Mid <- [webrtc_sdp_media:mid(M)]
    ],
    Session = session(webrtc_jsep_transport:bundles(Groups), J1),
    {Session#sdp{media = Media}, J1}.

%% RFC 9335 §6.1: cryptex is answered for the RTP sections of a
%% transport when the offer has it on all of them.
cryptex_mids(_Groups, _Offer, #jsep{cryptex = false}) ->
    [];
cryptex_mids(Groups, #sdp{media = Media} = Offer, _J) ->
    Rtp = maps:from_list([
        {webrtc_sdp_media:mid(M), webrtc_sdp_media:find_attr(cryptex, M, Offer) =:= {ok, true}}
     || M <- Media, media_kind(M#sdp_media.media) =/= application
    ]),
    lists:append([
        RtpMs
     || {_, Ms, _} <- Groups,
        RtpMs <- [[M || M <- Ms, is_map_key(M, Rtp)]],
        lists:all(fun(M) -> maps:get(M, Rtp) end, RtpMs)
    ]).

%% RFC 8842 §5.3: answer actpass with active.
answer_setup(Offer) ->
    case [S || M <- Offer#sdp.media, {ok, S} <- [webrtc_sdp_media:setup(M, Offer)]] of
        [passive | _] -> active;
        [active | _] -> passive;
        _ -> active
    end.

answer_section(I, #sdp_media{port = 0} = M, _Offer, _Setup, _Ctx, _J) ->
    Mid = webrtc_sdp_media:mid(M),
    {Mid, rejected_section(M#sdp_media.media, M#sdp_media.proto, M#sdp_media.fmts, Mid, I)};
answer_section(I, #sdp_media{media = Kind} = M, Offer, Setup, Ctx, J) ->
    Mid = webrtc_sdp_media:mid(M),
    Reject = {Mid, rejected_section(Kind, M#sdp_media.proto, M#sdp_media.fmts, Mid, I)},
    case media_kind(Kind) of
        application when Mid =:= J#jsep.data_mid ->
            {Mid, data_section(Mid, Setup, Ctx, J)};
        K when K =:= audio; K =:= video ->
            case lists:keyfind(I, #tr.mline, J#jsep.transceivers) of
                #tr{stopped = false} = T ->
                    Offered = webrtc_sdp_media:codecs(M),
                    Dir = answer_direction(webrtc_sdp_media:direction(M, Offer), T#tr.direction),
                    Codecs = webrtc_jsep_caps:answer_codecs(Offered, T#tr.codecs),
                    Exts = webrtc_jsep_caps:answer_extensions(
                        webrtc_sdp_media:attrs(extmap, M), T#tr.extensions
                    ),
                    Rids = webrtc_jsep_simulcast:answer_attrs(
                        M, Codecs, Exts, {T#tr.encodings, Dir =:= sendrecv orelse Dir =:= sendonly}
                    ),
                    case Codecs of
                        [] -> Reject;
                        _ -> {Mid, rtp_section(T, Mid, Dir, Codecs, Exts, Setup, Ctx, J, Rids)}
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

%%====================================================================
%% Sections
%%====================================================================

session(Bundles, #jsep{} = J) ->
    Group = [{group, #{semantics => <<"BUNDLE">>, mids => B}} || B <- Bundles, B =/= []],
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

transport_attrs(Setup, #{creds := {U, P}}, J) ->
    [
        {ice_ufrag, U},
        {ice_pwd, P},
        {ice_options, [<<"trickle">>]}
    ] ++
        [{fingerprint, #{hash => H, value => V}} || {H, V} <- J#jsep.fingerprints] ++
        [{setup, Setup}, {tls_id, J#jsep.tls_id}].

%% `Rids' are the a=rid and a=simulcast lines of the section. Layers sent
%% with rids are identified by the RtpStreamId header extension (RFC
%% 8852), so their SSRCs are not announced, as browsers do.
rtp_section(T, Mid, Dir, Codecs, Exts, Setup, Ctx, J, Rids) ->
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
            transport_attrs(Setup, Ctx, J) ++
            [{mid, Mid}] ++
            [{extmap, #{id => Id, direction => undefined, uri => U, attributes => undefined}}
             || #{id := Id, uri := U} <- Exts] ++
            [{direction, Dir}] ++ Msid ++
            [{rtcp_mux, true}, {rtcp_rsize, true}] ++ [{cryptex, true} || maps:get(cryptex, Ctx, false)] ++
            webrtc_sdp_media:codec_attributes(Codecs) ++ Ssrcs ++ Rids,
    Sec = #sdp_media{
        media = atom_to_binary(T#tr.kind),
        port = 9,
        proto = ?PROTO_RTP,
        fmts = [integer_to_binary(Pt) || #{pt := Pt} <- Codecs],
        connections = [?NULL_C],
        attributes = Attrs
    },
    add_candidates(Sec, Ctx).

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

data_section(Mid, Setup, Ctx, J) ->
    Sec = #sdp_media{
        media = <<"application">>,
        port = 9,
        proto = ?PROTO_SCTP,
        fmts = [<<"webrtc-datachannel">>],
        connections = [?NULL_C],
        attributes =
            transport_attrs(Setup, Ctx, J) ++
                [
                    {mid, Mid},
                    {sctp_port, J#jsep.sctp_port},
                    {max_message_size, J#jsep.max_message_size}
                ]
    },
    add_candidates(Sec, Ctx).

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
%% §4.3, RFC 8838 §4), in the tag section of their transport.
add_candidates(#sdp_media{attributes = A} = Sec, #{tag := true, cands := {Cs, Eoc}}) ->
    Sec#sdp_media{
        attributes = A ++ [{candidate, C} || C <- Cs] ++ [{end_of_candidates, true} || Eoc]
    };
add_candidates(Sec, _Ctx) ->
    Sec.
