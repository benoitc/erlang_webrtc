%% @doc JSEP (RFC 9429) negotiation on structured SDP.
%%
%% A pure state machine: it creates offers and answers, applies local and
%% remote descriptions with the signaling state transitions of RFC 9429
%% §3.2 (including pranswer and rollback), associates transceivers with
%% m= sections (§5.10) and computes the negotiated parameters the
%% transport needs.
%%
%% ```
%% J0 = webrtc_jsep:new(#{ice_ufrag => U, ice_pwd => P, fingerprints => [FP]}),
%% {ok, _Id, J1} = webrtc_jsep:add_transceiver(audio, #{}, J0),
%% {ok, Offer, J2} = webrtc_jsep:create_offer(#{}, J1),
%% {ok, J3} = webrtc_jsep:set_local_description(offer, Offer, J2),
%% {ok, J4} = webrtc_jsep:set_remote_description(answer, Answer, J3),
%% #{media := [_ | _]} = webrtc_jsep:negotiated(J4).
%% '''
%%
%% Limitation: all active m= sections must share one transport, either
%% through a BUNDLE group (RFC 9143) or because there is only one. This
%% matches the max-bundle policy every browser offers by default.
-module(webrtc_jsep).

-include("webrtc_sdp.hrl").
-include("webrtc_jsep.hrl").

-export([
    new/1,
    add_transceiver/3,
    set_direction/3,
    stop_transceiver/2,
    transceivers/1,
    add_data_channel/1,
    restart_ice/3,
    set_local_candidates/3,
    create_offer/2,
    create_answer/2,
    set_local_description/3,
    set_remote_description/3,
    signaling_state/1,
    local_description/1,
    remote_description/1,
    negotiated/1,
    close/1
]).

-export_type([state/0, sdp_type/0]).

-opaque state() :: #jsep{}.
-type sdp_type() :: offer | answer | pranswer | rollback.

%%====================================================================
%% Configuration
%%====================================================================

%% @doc Options: `ice_ufrag', `ice_pwd' and `fingerprints' (required);
%% `ice_lite', `sctp_port', `max_message_size', `codecs' and
%% `extensions' (maps keyed by `audio' and `video').
-spec new(map()) -> state().
new(#{ice_ufrag := U, ice_pwd := P, fingerprints := FPs} = Opts) ->
    Codecs = maps:get(codecs, Opts, #{}),
    Exts = maps:get(extensions, Opts, #{}),
    Caps = maps:from_list([
        {K, {
            maps:get(K, Codecs, webrtc_jsep_caps:default_codecs(K)),
            maps:get(K, Exts, webrtc_jsep_caps:default_extensions(K))
        }}
     || K <- [audio, video]
    ]),
    <<Sid:62, _:2>> = crypto:strong_rand_bytes(8),
    #jsep{
        ice_ufrag = U,
        ice_pwd = P,
        ice_lite = maps:get(ice_lite, Opts, false),
        fingerprints = FPs,
        cname = token(16),
        session_id = Sid,
        caps = Caps,
        sctp_port = maps:get(sctp_port, Opts, 5000),
        max_message_size = maps:get(max_message_size, Opts, 262144)
    }.

%% @doc Add a transceiver (RTCPeerConnection.addTransceiver). Returns a
%% handle that stays valid for the life of the connection.
%%
%% `send_encodings' is a list of `#{rid => Rid, restrictions => [{Name,
%% Value}]}' maps, one per simulcast layer (RFC 8853), most preferred
%% first. Rids are offered as given, or generated when missing (RFC 9429
%% §5.2.1); `restrictions' are RFC 8851 §5 restrictions such as
%% `{<<"max-width">>, <<"640">>}'.
-spec add_transceiver(audio | video, map(), state()) -> {ok, pos_integer(), state()} | {error, term()}.
add_transceiver(Kind, Opts, J) when Kind =:= audio; Kind =:= video ->
    T = new_tr(Kind, maps:get(direction, Opts, sendrecv), J),
    case webrtc_jsep_simulcast:encodings(maps:get(send_encodings, Opts, []), {T#tr.ssrc, T#tr.rtx_ssrc}) of
        {ok, Encs} ->
            T1 = T#tr{
                stream_id = maps:get(stream_id, Opts, T#tr.stream_id),
                track_id = maps:get(track_id, Opts, T#tr.track_id),
                encodings = Encs
            },
            {ok, T1#tr.id, J#jsep{transceivers = J#jsep.transceivers ++ [T1], next_id = T1#tr.id + 1}};
        {error, _} = E ->
            E
    end.

new_tr(Kind, Dir, #jsep{next_id = Id, caps = Caps}) ->
    {Codecs, Exts} = maps:get(Kind, Caps),
    #tr{
        id = Id,
        kind = Kind,
        direction = Dir,
        codecs = Codecs,
        extensions = Exts,
        ssrc = ssrc(),
        rtx_ssrc = ssrc(),
        stream_id = token(12),
        track_id = token(12)
    }.

-spec set_direction(pos_integer(), webrtc_sdp_rtp:direction(), state()) -> {ok, state()} | {error, term()}.
set_direction(Id, Dir, J) ->
    update_tr(Id, fun(T) -> T#tr{direction = Dir} end, J).

%% @doc Stop a transceiver. Its m= section is rejected (port 0) in the
%% next offer.
-spec stop_transceiver(pos_integer(), state()) -> {ok, state()} | {error, term()}.
stop_transceiver(Id, J) ->
    update_tr(Id, fun(T) -> T#tr{stopped = true, direction = inactive} end, J).

update_tr(Id, F, #jsep{transceivers = Trs} = J) ->
    case lists:keyfind(Id, #tr.id, Trs) of
        false -> {error, unknown_transceiver};
        T -> {ok, J#jsep{transceivers = lists:keyreplace(Id, #tr.id, Trs, F(T))}}
    end.

-spec transceivers(state()) -> [map()].
transceivers(#jsep{transceivers = Trs}) ->
    [
        #{
            id => T#tr.id,
            kind => T#tr.kind,
            mid => T#tr.mid,
            direction => T#tr.direction,
            current_direction => T#tr.current_direction,
            stopped => T#tr.stopped,
            ssrc => T#tr.ssrc,
            rtx_ssrc => T#tr.rtx_ssrc,
            send_encodings => [maps:with([rid, ssrc, rtx_ssrc], E) || E <- T#tr.encodings]
        }
     || T <- Trs
    ].

%% @doc Ask for an SCTP m= section (the first createDataChannel call).
-spec add_data_channel(state()) -> state().
add_data_channel(J) ->
    J#jsep{want_data = true}.

%% @doc New local ICE credentials for an ICE restart; used by the next
%% offer or answer (RFC 9429 §5.2.1, RFC 8445 §9).
-spec restart_ice(binary(), binary(), state()) -> state().
restart_ice(U, P, J) ->
    J#jsep{ice_ufrag = U, ice_pwd = P, ice_restart = true}.

%% @doc Candidates to include in descriptions created from now on.
-spec set_local_candidates([#sdp_candidate{}], boolean(), state()) -> state().
set_local_candidates(Cands, EndOfCandidates, J) ->
    J#jsep{local_candidates = Cands, local_eoc = EndOfCandidates}.

%%====================================================================
%% Offer and answer creation
%%====================================================================

-spec create_offer(map(), state()) -> {ok, #sdp{}, state()} | {error, term()}.
create_offer(_Opts, #jsep{signaling = S}) when S =/= stable, S =/= have_local_offer ->
    {error, invalid_state};
create_offer(Opts, J0) ->
    J = J0#jsep{session_version = J0#jsep.session_version + 1},
    {Offer, J1} = webrtc_jsep_build:offer(Opts, J),
    {ok, Offer, J1}.

-spec create_answer(map(), state()) -> {ok, #sdp{}, state()} | {error, term()}.
create_answer(Opts, #jsep{signaling = S} = J0) when
    S =:= have_remote_offer; S =:= have_local_pranswer
->
    J = J0#jsep{session_version = J0#jsep.session_version + 1},
    {ok, webrtc_jsep_build:answer(Opts, J), J};
create_answer(_Opts, _J) ->
    {error, invalid_state}.

%%====================================================================
%% Applying descriptions (RFC 9429 §5.7, §5.8)
%%====================================================================

-spec set_local_description(sdp_type(), #sdp{} | undefined, state()) -> {ok, state()} | {error, term()}.
set_local_description(_, _, #jsep{signaling = closed}) ->
    {error, closed};
set_local_description(offer, Sdp, #jsep{signaling = S} = J) when
    S =:= stable; S =:= have_local_offer
->
    {ok, J#jsep{pending_local = Sdp, signaling = have_local_offer}};
set_local_description(Type, Sdp, #jsep{signaling = S} = J) when
    (Type =:= answer orelse Type =:= pranswer),
    (S =:= have_remote_offer orelse S =:= have_local_pranswer)
->
    J1 = negotiate(answerer, Sdp, J#jsep.pending_remote, J),
    case Type of
        pranswer ->
            {ok, J1#jsep{pending_local = Sdp, signaling = have_local_pranswer}};
        answer ->
            {ok, J1#jsep{
                current_local = Sdp,
                current_remote = J#jsep.pending_remote,
                pending_local = undefined,
                pending_remote = undefined,
                snapshot = undefined,
                signaling = stable,
                ice_restart = false
            }}
    end;
set_local_description(rollback, _, #jsep{signaling = have_local_offer} = J) ->
    {ok, J#jsep{pending_local = undefined, signaling = stable}};
set_local_description(_, _, _) ->
    {error, invalid_state}.

-spec set_remote_description(sdp_type(), #sdp{} | undefined, state()) -> {ok, state()} | {error, term()}.
set_remote_description(_, _, #jsep{signaling = closed}) ->
    {error, closed};
set_remote_description(offer, Sdp, #jsep{signaling = S} = J) when
    S =:= stable; S =:= have_remote_offer
->
    maybe
        ok ?= validate(offer, Sdp, J),
        J0 = restore(J),
        Snap = {J0#jsep.transceivers, J0#jsep.next_id, J0#jsep.data_mid, J0#jsep.data_mline},
        J1 = associate(Sdp, J0#jsep{snapshot = Snap}),
        {ok, J1#jsep{pending_remote = Sdp, signaling = have_remote_offer, remote_ice = remote_ice(Sdp)}}
    end;
set_remote_description(Type, Sdp, #jsep{signaling = S} = J) when
    (Type =:= answer orelse Type =:= pranswer),
    (S =:= have_local_offer orelse S =:= have_remote_pranswer)
->
    maybe
        ok ?= validate(answer, Sdp, J),
        ok ?= check_answer_mids(Sdp, J#jsep.pending_local),
        J1 = negotiate(offerer, J#jsep.pending_local, Sdp, J),
        J2 = J1#jsep{remote_ice = remote_ice(Sdp)},
        case Type of
            pranswer ->
                {ok, J2#jsep{pending_remote = Sdp, signaling = have_remote_pranswer}};
            answer ->
                {ok, J2#jsep{
                    current_local = J#jsep.pending_local,
                    current_remote = Sdp,
                    pending_local = undefined,
                    pending_remote = undefined,
                    signaling = stable,
                    ice_restart = false
                }}
        end
    end;
set_remote_description(rollback, _, #jsep{signaling = have_remote_offer} = J) ->
    J1 = restore(J),
    {ok, J1#jsep{pending_remote = undefined, signaling = stable, snapshot = undefined}};
set_remote_description(_, _, _) ->
    {error, invalid_state}.

%% Undo the transceiver changes of a previous remote offer (§4.1.10.2).
restore(#jsep{snapshot = undefined} = J) ->
    J;
restore(#jsep{snapshot = {Trs, Next, DMid, DLine}} = J) ->
    J#jsep{transceivers = Trs, next_id = Next, data_mid = DMid, data_mline = DLine}.

-spec signaling_state(state()) -> atom().
signaling_state(#jsep{signaling = S}) -> S.

-spec local_description(state()) -> #sdp{} | undefined.
local_description(#jsep{pending_local = P, current_local = C}) -> first_defined(P, C).

-spec remote_description(state()) -> #sdp{} | undefined.
remote_description(#jsep{pending_remote = P, current_remote = C}) -> first_defined(P, C).

first_defined(undefined, B) -> B;
first_defined(A, _) -> A.

-spec close(state()) -> state().
close(J) -> J#jsep{signaling = closed}.

%%====================================================================
%% Validation (RFC 9429 §5.8, RFC 8839, RFC 8842)
%%====================================================================

validate(_Type, #sdp{media = []}, _J) ->
    {error, no_media};
validate(_Type, #sdp{} = Sdp, _J) ->
    Active = [M || M <- Sdp#sdp.media, M#sdp_media.port =/= 0],
    Mids = [webrtc_sdp_media:mid(M) || M <- Sdp#sdp.media],
    Bundles = webrtc_sdp_media:groups(<<"BUNDLE">>, Sdp),
    ActiveMids = [webrtc_sdp_media:mid(M) || M <- Active],
    Unique = length(Mids) =:= length(lists:usort(Mids)),
    if
        Active =:= [] -> {error, no_active_media};
        not Unique -> {error, duplicate_mid};
        true -> validate_bundle(ActiveMids, Bundles, Active, Sdp)
    end;
validate(_, _, _) ->
    {error, bad_description}.

validate_bundle(ActiveMids, Bundles, Active, Sdp) ->
    case lists:member(undefined, ActiveMids) of
        true ->
            {error, missing_mid};
        false ->
            Bundled =
                case Bundles of
                    [G | _] -> lists:all(fun(M) -> lists:member(M, G) end, ActiveMids);
                    [] -> length(ActiveMids) =:= 1
                end,
            case Bundled of
                false -> {error, {unsupported, unbundled_media}};
                true -> validate_sections(Active, Sdp)
            end
    end.

validate_sections([], _Sdp) ->
    ok;
validate_sections([M | Rest], Sdp) ->
    Rtp = webrtc_jsep_build:media_kind(M#sdp_media.media) =/= application,
    Checks = [
        {webrtc_sdp_media:ice_credentials(M, Sdp) =/= {error, missing_ice_credentials},
            missing_ice_credentials},
        {webrtc_sdp_media:fingerprints(M, Sdp) =/= [], missing_fingerprint},
        {webrtc_sdp_media:setup(M, Sdp) =/= error, missing_setup},
        {webrtc_sdp_media:setup(M, Sdp) =/= {ok, holdconn}, unsupported_setup},
        %% RFC 8834 §4.5 and the JSEP require policy: rtcp-mux.
        {(not Rtp) orelse webrtc_sdp_media:attr(rtcp_mux, M) =:= {ok, true}, missing_rtcp_mux},
        %% RFC 9429 §5.8.3: rid-ids of a=simulcast exist as a=rid lines.
        {(not Rtp) orelse webrtc_jsep_simulcast:validate(M) =:= ok, unknown_rid}
    ],
    case [R || {false, R} <- Checks] of
        [] -> validate_sections(Rest, Sdp);
        [R | _] -> {error, {R, webrtc_sdp_media:mid(M)}}
    end.

check_answer_mids(Answer, Offer) ->
    Om = [webrtc_sdp_media:mid(M) || M <- Offer#sdp.media],
    Am = [webrtc_sdp_media:mid(M) || M <- Answer#sdp.media],
    case Om =:= Am of
        true -> ok;
        false -> {error, mid_mismatch}
    end.

%%====================================================================
%% Transceiver association (RFC 9429 §5.10)
%%====================================================================

associate(#sdp{media = Media}, J0) ->
    Indexed = lists:zip(lists:seq(0, length(Media) - 1), Media),
    lists:foldl(fun({I, M}, J) -> associate_one(I, M, J) end, J0, Indexed).

associate_one(I, #sdp_media{media = K} = M, J) ->
    Mid = webrtc_sdp_media:mid(M),
    case webrtc_jsep_build:media_kind(K) of
        application ->
            case J#jsep.data_mid of
                undefined when M#sdp_media.port =/= 0 ->
                    J#jsep{data_mid = Mid, data_mline = I, want_data = true};
                _ ->
                    J
            end;
        Kind when Kind =:= audio; Kind =:= video ->
            Trs = J#jsep.transceivers,
            case lists:keyfind(Mid, #tr.mid, Trs) of
                #tr{} = T ->
                    replace(T#tr{mline = I}, J);
                false when M#sdp_media.port =:= 0 ->
                    J;
                false ->
                    case [T || T = #tr{mid = undefined, mline = undefined, kind = TK, stopped = false} <- Trs, TK =:= Kind] of
                        [T | _] ->
                            replace(T#tr{mid = Mid, mline = I}, J);
                        [] ->
                            New = (new_tr(Kind, recvonly, J))#tr{mid = Mid, mline = I, from_remote = true},
                            J#jsep{transceivers = Trs ++ [New], next_id = New#tr.id + 1}
                    end
            end;
        other ->
            J
    end.

replace(#tr{id = Id} = T, #jsep{transceivers = Trs} = J) ->
    J#jsep{transceivers = lists:keyreplace(Id, #tr.id, Trs, T)}.

%%====================================================================
%% Negotiated parameters
%%====================================================================

%% Record per-transceiver current direction and the DTLS role.
negotiate(Role, Local, Remote, J) ->
    Trs = [negotiate_tr(Role, T, Local, Remote) || T <- J#jsep.transceivers],
    DtlsRole =
        case first_setup(Local) of
            {ok, active} -> client;
            {ok, passive} -> server;
            _ -> J#jsep.dtls_role
        end,
    DtlsRole1 =
        case {DtlsRole, Role, first_setup(Remote)} of
            {undefined, offerer, {ok, active}} -> server;
            {undefined, offerer, {ok, passive}} -> client;
            {R, _, _} -> R
        end,
    J#jsep{transceivers = Trs, dtls_role = DtlsRole1}.

first_setup(#sdp{media = Media} = Sdp) ->
    case [S || M <- Media, M#sdp_media.port =/= 0, {ok, S} <- [webrtc_sdp_media:setup(M, Sdp)]] of
        [S | _] -> {ok, S};
        [] -> error
    end.

negotiate_tr(_Role, #tr{mline = undefined} = T, _L, _R) ->
    T;
negotiate_tr(Role, #tr{mline = I} = T, Local, Remote) ->
    case {section(I, Local), section(I, Remote)} of
        {#sdp_media{port = P}, _} when P =:= 0 -> T#tr{current_direction = inactive, stopped = true};
        {_, #sdp_media{port = 0}} -> T#tr{current_direction = inactive, stopped = true};
        {L, R} when L =/= undefined, R =/= undefined ->
            Dir =
                case Role of
                    answerer -> webrtc_sdp_media:direction(L, Local);
                    offerer -> reverse(webrtc_sdp_media:direction(R, Remote))
                end,
            T#tr{current_direction = Dir};
        _ ->
            T
    end.

section(I, #sdp{media = M}) when I < length(M) -> lists:nth(I + 1, M);
section(_, _) -> undefined.

reverse(sendonly) -> recvonly;
reverse(recvonly) -> sendonly;
reverse(D) -> D.

remote_ice(#sdp{media = Media} = Sdp) ->
    case [C || M <- Media, M#sdp_media.port =/= 0, {ok, C} <- [webrtc_sdp_media:ice_credentials(M, Sdp)]] of
        [C | _] -> C;
        [] -> undefined
    end.

%% @doc Negotiated parameters from the current (or provisional)
%% descriptions, or `undefined' before the first answer.
-spec negotiated(state()) -> map() | undefined.
negotiated(#jsep{} = J) ->
    {Local, Remote} =
        case J#jsep.signaling of
            S when S =:= have_local_pranswer; S =:= have_remote_pranswer ->
                {local_description(J), remote_description(J)};
            _ ->
                {J#jsep.current_local, J#jsep.current_remote}
        end,
    case Local =:= undefined orelse Remote =:= undefined of
        true -> undefined;
        false -> webrtc_jsep_params:negotiated(Local, Remote, J)
    end.

%%====================================================================
%% Helpers
%%====================================================================

ssrc() ->
    <<S:32>> = crypto:strong_rand_bytes(4),
    case S of
        0 -> ssrc();
        _ -> S
    end.

token(N) ->
    Alphabet = <<"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789">>,
    << <<(binary:at(Alphabet, B rem 62))>> || <<B>> <= crypto:strong_rand_bytes(N) >>.
