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
    frames_opts/1,
    set_direction/3,
    stop_transceiver/2,
    transceivers/1,
    add_data_channel/1,
    restart_ice/3,
    set_local_candidates/3,
    set_local_candidates/4,
    set_transport_credentials/4,
    data_mid/1,
    transports/1,
    create_offer/2,
    create_answer/2,
    set_local_description/3,
    set_remote_description/3,
    change_ssrc/4,
    signaling_state/1,
    local_description/1,
    remote_description/1,
    remote_view/1,
    bundle_view/1,
    negotiated/1,
    local_ice/1,
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
%% `extensions' (maps keyed by `audio' and `video'; an extension with
%% `encrypt => true' is offered encrypted, RFC 6904), and
%% `encrypt_header_extensions': `accept' (default) answers an offered
%% encrypted extension encrypted but offers none, `offer' also offers
%% the encrypted forms, `false' neither offers nor accepts them.
-spec new(map()) -> state().
new(#{ice_ufrag := U, ice_pwd := P, fingerprints := FPs} = Opts) ->
    Codecs = maps:get(codecs, Opts, #{}),
    Exts = maps:get(extensions, Opts, #{}),
    %% RFC 8834 §5.2.2: header extension encryption can be turned off.
    %% By default an offered encrypted form is accepted but none is
    %% offered: aiortc 1.16 cannot parse it and Chromium 149 then drops
    %% the extension altogether.
    EncryptMode = maps:get(encrypt_header_extensions, Opts, accept),
    Encrypt = EncryptMode =/= false,
    Caps = maps:from_list([
        {K, {
            maps:get(K, Codecs, webrtc_jsep_caps:default_codecs(K)),
            [E || E <- maps:get(K, Exts, webrtc_jsep_caps:default_extensions(K)),
                  Encrypt orelse maps:get(encrypt, E, false) =/= true]
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
        tls_id = token(24),
        session_id = Sid,
        caps = Caps,
        sctp_port = maps:get(sctp_port, Opts, 5000),
        max_message_size = maps:get(max_message_size, Opts, 262144),
        bundle = maps:get(bundle, Opts, true),
        frames = case frames_opts(maps:get(frames, Opts, false)) of
                     {ok, F} -> F;
                     {error, E} -> error(E)
                 end,
        encrypt_offer = EncryptMode =:= offer,
        cryptex = maps:get(cryptex, Opts, true),
        rtcp_mux_only = maps:get(rtcp_mux_policy, Opts, negotiate) =:= require
    }.

%% @doc Add a transceiver (RTCPeerConnection.addTransceiver). Returns a
%% handle that stays valid for the life of the connection.
%%
%% `send_encodings' is a list of `#{rid => Rid, restrictions => [{Name,
%% Value}]}' maps, one per simulcast layer (RFC 8853), most preferred
%% first. Rids are offered as given, or generated when missing (RFC 9429
%% §5.2.1); `restrictions' are RFC 8851 §5 restrictions such as
%% `{<<"max-width">>, <<"640">>}'. `recv_rids' lists the simulcast
%% layers to ask for, as rids or `#{rid => Rid, paused => true}' for a
%% layer to start paused.
%%
%% A transceiver without `send_encodings' that answers an offer asking
%% to receive simulcast sends the offered layers (RFC 9429 §5.10).
%%
%% `frames': `true', or `#{min_delay => Ms, max_delay => Ms}', delivers
%% assembled frames instead of packets (see `webrtc_frame_buffer').
-spec add_transceiver(audio | video, map(), state()) -> {ok, pos_integer(), state()} | {error, term()}.
add_transceiver(Kind, Opts, J) when Kind =:= audio; Kind =:= video ->
    T = new_tr(Kind, maps:get(direction, Opts, sendrecv), J),
    maybe
        {ok, Encs} ?= webrtc_jsep_simulcast:encodings(maps:get(send_encodings, Opts, []), {T#tr.ssrc, T#tr.rtx_ssrc}),
        {ok, Recv} ?= webrtc_jsep_simulcast:recv_rids(maps:get(recv_rids, Opts, [])),
        {ok, Frames} ?= frames_opts(maps:get(frames, Opts, T#tr.frames)),
        T1 = T#tr{
            stream_id = maps:get(stream_id, Opts, T#tr.stream_id),
            track_id = maps:get(track_id, Opts, T#tr.track_id),
            encodings = Encs,
            recv_rids = Recv,
            frames = Frames
        },
        {ok, T1#tr.id, J#jsep{transceivers = J#jsep.transceivers ++ [T1], next_id = T1#tr.id + 1}}
    end.

%% @doc Check the `frames' option: false, true, or the buffer delays.
-spec frames_opts(term()) -> {ok, false | map()} | {error, {badarg, {frames, term()}}}.
frames_opts(false) ->
    {ok, false};
frames_opts(true) ->
    {ok, #{}};
frames_opts(#{} = O) ->
    Min = maps:get(min_delay, O, 0),
    Max = maps:get(max_delay, O, 10000),
    case maps:keys(maps:without([min_delay, max_delay], O)) =:= [] andalso is_integer(Min) andalso
             is_integer(Max) andalso Min >= 0 andalso Max >= Min of
        true -> {ok, maps:with([min_delay, max_delay], O)};
        false -> {error, {badarg, {frames, O}}}
    end;
frames_opts(Other) ->
    {error, {badarg, {frames, Other}}}.

new_tr(Kind, Dir, #jsep{next_id = Id, caps = Caps, frames = Frames}) ->
    {Codecs, Exts} = maps:get(Kind, Caps),
    #tr{
        frames = Frames,
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
transceivers(#jsep{transceivers = Trs} = J) ->
    Neg = case negotiated(J) of
              #{media := Ms} -> maps:from_list([{Id, M} || #{id := Id} = M <- Ms]);
              _ -> #{}
          end,
    [
        maps:merge(
            maps:with([send_extensions, recv_extensions, send_encrypted, recv_encrypted], maps:get(T#tr.id, Neg, #{})),
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
        })
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
%% @doc Candidates of the transport `Key' (see `transports/1') to
%% include in descriptions created from now on.
-spec set_local_candidates(binary(), [#sdp_candidate{}], boolean(), state()) -> state().
set_local_candidates(Key, Cands, EndOfCandidates, J) ->
    case transports(J) of
        [#{key := Key} | _] -> set_local_candidates(Cands, EndOfCandidates, J);
        _ -> J#jsep{local_cands = (J#jsep.local_cands)#{Key => {Cands, EndOfCandidates}}}
    end.

%% @doc The mid of the data channel section, once it has one.
-spec data_mid(state()) -> binary() | undefined.
data_mid(#jsep{data_mid = D}) -> D.

%% @doc New local ICE credentials for a transport after the first (an
%% ICE restart of that transport); used by the next offer or answer.
-spec set_transport_credentials(binary(), binary(), binary(), state()) -> state().
set_transport_credentials(Key, U, P, J) ->
    J#jsep{ice_extra = (J#jsep.ice_extra)#{Key => {U, P}}}.

%% @doc The transports of the local description (current or pending,
%% else the offer to be created), first one first: `#{key, mids, ufrag,
%% pwd}'. A BUNDLE group is one transport (RFC 9143); an unbundled
%% section has its own.
-spec transports(state()) -> [map()].
transports(J) ->
    Groups =
        case local_description(J) of
            undefined -> [];
            Local -> webrtc_jsep_transport:groups(Local)
        end,
    [begin
         {U, P} = webrtc_jsep_build:creds(K, Groups, J),
         #{key => K, mids => Ms, ufrag => U, pwd => P}
     end
     || {K, Ms, _} <- Groups].

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
    {Answer, J1} = webrtc_jsep_build:answer(Opts, J),
    {ok, Answer, J1};
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
    {ok, snapshot(J#jsep{pending_local = Sdp, signaling = have_local_offer})};
set_local_description(Type, Sdp, #jsep{signaling = S} = J) when
    (Type =:= answer orelse Type =:= pranswer),
    (S =:= have_remote_offer orelse S =:= have_local_pranswer)
->
    J1 = negotiate(answerer, Sdp, J#jsep.pending_remote, J),
    case Type of
        pranswer ->
            {ok, J1#jsep{pending_local = Sdp, signaling = have_local_pranswer, answerer = true}};
        answer ->
            {ok, J1#jsep{
                answerer = true,
                groups = webrtc_jsep_transport:groups(Sdp),
                current_local = Sdp,
                current_remote = J#jsep.pending_remote,
                current_remote_orig = J#jsep.pending_remote_orig,
                pending_local = undefined,
                pending_remote = undefined,
                pending_remote_orig = undefined,
                snapshot = undefined,
                signaling = stable,
                ice_restart = false
            }}
    end;
set_local_description(rollback, _, J) ->
    rollback(J);
set_local_description(_, _, _) ->
    {error, invalid_state}.

-spec set_remote_description(sdp_type(), #sdp{} | undefined, state()) -> {ok, state()} | {error, term()}.
set_remote_description(_, _, #jsep{signaling = closed}) ->
    {error, closed};
set_remote_description(offer, Sdp0, #jsep{signaling = S} = J) when
    S =:= stable; S =:= have_remote_offer
->
    Sdp = bundle_view(Sdp0),
    maybe
        ok ?= validate(offer, Sdp, J),
        ok ?= validate_reoffer(Sdp, J),
        J0 = snapshot(restore(J)),
        {ok, J01} ?= dtls_identity(Sdp, J0),
        J1 = avoid_ssrcs(Sdp, associate(Sdp, J01)),
        {ok, J1#jsep{
            pending_remote = Sdp,
            pending_remote_orig = Sdp0,
            signaling = have_remote_offer,
            remote_ice = remote_ice(Sdp)
        }}
    end;
set_remote_description(Type, Sdp0, #jsep{signaling = S} = J) when
    (Type =:= answer orelse Type =:= pranswer),
    (S =:= have_local_offer orelse S =:= have_remote_pranswer)
->
    Sdp = bundle_view(Sdp0),
    maybe
        ok ?= validate(answer, Sdp, J),
        {ok, Jd} ?= dtls_identity(Sdp, J),
        ok ?= validate_answer(Sdp, J#jsep.pending_local, Jd),
        J1 = avoid_ssrcs(Sdp, negotiate(offerer, J#jsep.pending_local, Sdp, Jd)),
        J2 = J1#jsep{remote_ice = remote_ice(Sdp), answerer = false},
        case Type of
            pranswer ->
                {ok, J2#jsep{pending_remote = Sdp, pending_remote_orig = Sdp0, signaling = have_remote_pranswer}};
            answer ->
                {ok, J2#jsep{
                    groups = webrtc_jsep_transport:groups(Sdp),
                    current_local = J#jsep.pending_local,
                    current_remote = Sdp,
                    current_remote_orig = Sdp0,
                    pending_local = undefined,
                    pending_remote = undefined,
                    pending_remote_orig = undefined,
                    snapshot = undefined,
                    signaling = stable,
                    ice_restart = false
                }}
        end
    end;
set_remote_description(rollback, _, J) ->
    rollback(J);
set_remote_description(_, _, _) ->
    {error, invalid_state}.

%% RFC 9429 §5.7: a rollback is allowed in every state but stable, has
%% the same effect through either setter, and abandons the offer/answer
%% exchange in progress, provisional answers included.
rollback(#jsep{signaling = S} = J) when
    S =:= have_local_offer;
    S =:= have_remote_offer;
    S =:= have_local_pranswer;
    S =:= have_remote_pranswer
->
    J1 = restore(J),
    {ok, J1#jsep{
        pending_local = undefined,
        pending_remote = undefined,
        pending_remote_orig = undefined,
        snapshot = undefined,
        signaling = stable
    }};
rollback(_) ->
    {error, invalid_state}.

%% The state an offer/answer exchange changes, saved when it starts (the
%% first offer applied in stable state) so a rollback can undo it.
snapshot(#jsep{snapshot = undefined} = J) ->
    J#jsep{
        snapshot = #{
            transceivers => J#jsep.transceivers,
            next_id => J#jsep.next_id,
            data_mid => J#jsep.data_mid,
            data_mline => J#jsep.data_mline,
            dtls_role => J#jsep.dtls_role,
            tls_id => J#jsep.tls_id,
            remote_ice => J#jsep.remote_ice,
            ice_ufrag => J#jsep.ice_ufrag,
            ice_pwd => J#jsep.ice_pwd,
            ice_restart => J#jsep.ice_restart
        }
    };
snapshot(J) ->
    J.

%% Undo the changes of the exchange in progress (§4.1.10.2, §5.7).
restore(#jsep{snapshot = undefined} = J) ->
    J;
restore(#jsep{snapshot = Snap} = J) ->
    J#jsep{
        transceivers = maps:get(transceivers, Snap),
        next_id = maps:get(next_id, Snap),
        data_mid = maps:get(data_mid, Snap),
        data_mline = maps:get(data_mline, Snap),
        dtls_role = maps:get(dtls_role, Snap),
        tls_id = maps:get(tls_id, Snap),
        remote_ice = maps:get(remote_ice, Snap),
        ice_ufrag = maps:get(ice_ufrag, Snap),
        ice_pwd = maps:get(ice_pwd, Snap),
        ice_restart = maps:get(ice_restart, Snap),
        snapshot = undefined
    }.

-spec signaling_state(state()) -> atom().
signaling_state(#jsep{signaling = S}) -> S.

-spec local_description(state()) -> #sdp{} | undefined.
local_description(#jsep{pending_local = P, current_local = C}) -> first_defined(P, C).

-spec remote_description(state()) -> #sdp{} | undefined.
remote_description(#jsep{pending_remote_orig = P, current_remote_orig = C}) -> first_defined(P, C).

%% @private The remote description as negotiation sees it.
-spec remote_view(state()) -> #sdp{} | undefined.
remote_view(#jsep{pending_remote = P, current_remote = C}) -> first_defined(P, C).

%% @doc RFC 9143 §6, RFC 9429 §5.2.1: with the max-bundle policy an
%% offerer gives every bundled m= section except the tagged one a zero
%% port and `a=bundle-only'. Such a section is part of the BUNDLE group,
%% not rejected: give it the port of the tagged section so the offer and
%% answer rules treat it as accepted. Sections with port 0 and no
%% bundle-only, or outside every BUNDLE group, stay rejected.
-spec bundle_view(T) -> T when T :: #sdp{} | term().
bundle_view(#sdp{media = Media} = Sdp) ->
    Bundled = lists:append(webrtc_sdp_media:groups(<<"BUNDLE">>, Sdp)),
    Port = case [M#sdp_media.port || M <- Media, M#sdp_media.port =/= 0,
                                      lists:member(webrtc_sdp_media:mid(M), Bundled)] of
        [P | _] -> P;
        [] -> 9
    end,
    Sdp#sdp{media = [
        case M of
            #sdp_media{port = 0} ->
                case webrtc_sdp_media:attr(bundle_only, M) =:= {ok, true} andalso
                         lists:member(webrtc_sdp_media:mid(M), Bundled) of
                    true -> M#sdp_media{port = Port};
                    false -> M
                end;
            _ ->
                M
        end
     || M <- Media
    ]};
bundle_view(Other) ->
    Other.

first_defined(undefined, B) -> B;
first_defined(A, _) -> A.

-spec close(state()) -> state().
close(J) -> J#jsep{signaling = closed}.

%%====================================================================
%% DTLS identity (RFC 8842 §5, RFC 9429 §5.8.3)
%%====================================================================

%% A remote description whose fingerprints (or tls-id) differ from the
%% current ones asks for a new DTLS association. That is only allowed
%% with an ICE restart (new remote ufrag and pwd); then the DTLS role is
%% negotiated again and we pick a new tls-id. Otherwise the description
%% is refused: keeping the old association would leave the connection
%% authenticated against a certificate the peer no longer claims.
dtls_identity(_Sdp, #jsep{current_remote = undefined} = J) ->
    {ok, J};
dtls_identity(Sdp, #jsep{current_remote = Cur} = J) ->
    case identity(Sdp) =:= identity(Cur) of
        true ->
            {ok, J};
        false ->
            case remote_ice(Sdp) =/= remote_ice(Cur) of
                true -> {ok, J#jsep{dtls_role = undefined, tls_id = token(24)}};
                false -> {error, dtls_identity_changed}
            end
    end.

%% Fingerprints and tls-id of the first active m= section; a missing
%% tls-id (older peers) only compares the fingerprints.
identity(#sdp{media = Media} = Sdp) ->
    case [M || M <- Media, M#sdp_media.port =/= 0] of
        [M | _] ->
            FPs = lists:sort([{H, V} || #{hash := H, value := V} <- webrtc_sdp_media:fingerprints(M, Sdp)]),
            TlsId =
                case webrtc_sdp_media:find_attr(tls_id, M, Sdp) of
                    {ok, T} -> T;
                    error -> undefined
                end,
            case TlsId of
                undefined -> {FPs, any};
                _ -> {FPs, TlsId}
            end;
        [] ->
            undefined
    end.

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
            %% RFC 9143 §7: a mid belongs to one BUNDLE group at most;
            %% sections outside the groups have their own transport.
            InGroups = lists:append(Bundles),
            case length(InGroups) =:= length(lists:usort(InGroups)) of
                false -> {error, mid_in_two_bundle_groups};
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

%% RFC 9429 §5.8.3, RFC 3264 §6: an answer has the offer's m= sections,
%% in order, with the same mid, media type and protocol; an active
%% section chooses `active' or `passive' (the established DTLS role
%% kept unless the association is replaced), a direction the offer
%% allows, and payload types the offer has, for the same codecs.
validate_answer(#sdp{media = Am}, #sdp{media = Om}, _J) when length(Am) =/= length(Om) ->
    {error, mline_count_mismatch};
validate_answer(#sdp{media = Am} = A, #sdp{media = Om} = O, J) ->
    case answer_bundles(A, O) of
        ok -> check_sections([{OM, AM} || {OM, AM} <- lists:zip(Om, Am)], fun(OM, AM) -> answer_section(OM, O, AM, A, J) end);
        {error, _} = E -> E
    end.

%% RFC 9143 §7.3: an answer keeps or removes sections of the offered
%% BUNDLE groups, it never bundles what the offer did not.
answer_bundles(A, O) ->
    Offered = webrtc_sdp_media:groups(<<"BUNDLE">>, O),
    Within = fun(G) -> lists:any(fun(OG) -> G -- OG =:= [] end, Offered) end,
    case lists:all(Within, webrtc_sdp_media:groups(<<"BUNDLE">>, A)) of
        true -> ok;
        false -> {error, bundle_not_offered}
    end.

check_sections([], _Check) ->
    ok;
check_sections([{OM, AM} | Rest], Check) ->
    case Check(OM, AM) of
        ok -> check_sections(Rest, Check);
        {error, R} -> {error, {R, webrtc_sdp_media:mid(AM)}}
    end.

answer_section(OM, O, AM, A, J) ->
    Active = AM#sdp_media.port =/= 0,
    Rtp = webrtc_jsep_build:media_kind(AM#sdp_media.media) =/= application,
    Checks = [
        {webrtc_sdp_media:mid(OM) =:= webrtc_sdp_media:mid(AM), mid_mismatch},
        {OM#sdp_media.media =:= AM#sdp_media.media, media_type_mismatch},
        {not Active orelse same_proto(OM, AM), proto_mismatch},
        {not Active orelse answer_setup(AM, A, J), bad_setup},
        {not Active orelse not Rtp orelse
            direction_allowed(webrtc_sdp_media:direction(OM, O), webrtc_sdp_media:direction(AM, A)),
            direction_mismatch},
        {not Active orelse not Rtp orelse offered_formats(OM, AM), payload_type_mismatch},
        %% RFC 5761 §4: payload types 64..95 clash with RTCP when muxed.
        {not Active orelse not Rtp orelse
            lists:all(fun(F) -> case string:to_integer(F) of {N, <<>>} -> N < 64 orelse N > 95; _ -> true end end,
                      AM#sdp_media.fmts),
            payload_type_conflicts_with_rtcp},
        %% RFC 6904 §4.1: never both the clear and the encrypted form.
        {not Active orelse webrtc_jsep_caps:single_forms(webrtc_sdp_media:attrs(extmap, AM)), both_extension_forms}
    ],
    case [R || {false, R} <- Checks] of
        [] -> ok;
        [R | _] -> {error, R}
    end.

same_proto(#sdp_media{proto = P1}, #sdp_media{proto = P2}) ->
    string:uppercase(P1) =:= string:uppercase(P2).

answer_setup(M, Sdp, #jsep{dtls_role = Role}) ->
    case {webrtc_sdp_media:setup(M, Sdp), Role} of
        {{ok, active}, R} -> R =:= undefined orelse R =:= server;
        {{ok, passive}, R} -> R =:= undefined orelse R =:= client;
        _ -> false
    end.

%% RFC 3264 §6.1.
direction_allowed(sendrecv, _) -> true;
direction_allowed(sendonly, A) -> A =:= recvonly orelse A =:= inactive;
direction_allowed(recvonly, A) -> A =:= sendonly orelse A =:= inactive;
direction_allowed(inactive, A) -> A =:= inactive.

offered_formats(OM, AM) ->
    Offered = maps:from_list([{Pt, C} || #{pt := Pt} = C <- webrtc_sdp_media:codecs(OM)]),
    lists:all(fun(F) -> lists:member(F, OM#sdp_media.fmts) end, AM#sdp_media.fmts) andalso
        lists:all(
            fun(#{pt := Pt, name := N, clock_rate := R}) ->
                case Offered of
                    #{Pt := #{name := ON, clock_rate := OR}} ->
                        string:uppercase(ON) =:= string:uppercase(N) andalso OR =:= R;
                    _ ->
                        false
                end
            end,
            webrtc_sdp_media:codecs(AM)
        ).

%% RFC 9429 §5.8.3: a subsequent offer keeps every m= section of the
%% current description in place, with its mid and media type; only a
%% rejected section may be reused for something else (§5.2.2).
validate_reoffer(_Sdp, #jsep{current_remote = undefined}) ->
    ok;
validate_reoffer(#sdp{media = New}, #jsep{current_remote = #sdp{media = Cur}}) when length(New) < length(Cur) ->
    {error, mline_removed};
validate_reoffer(#sdp{media = New}, #jsep{current_remote = #sdp{media = Cur}, current_local = Local}) ->
    Pairs = lists:zip(lists:sublist(New, length(Cur)), lists:zip(Cur, local_sections(Local, length(Cur)))),
    check_sections(
        [{{C, L}, N} || {N, {C, L}} <- Pairs],
        fun({C, L}, N) ->
            Rejected = C#sdp_media.port =:= 0 orelse L#sdp_media.port =:= 0,
            if
                Rejected -> ok;
                C#sdp_media.media =/= N#sdp_media.media -> {error, media_type_changed};
                true ->
                    case webrtc_sdp_media:mid(C) =:= webrtc_sdp_media:mid(N) of
                        true -> ok;
                        false -> {error, mid_changed}
                    end
            end
        end
    ).

local_sections(#sdp{media = M}, N) when length(M) >= N -> lists:sublist(M, N);
local_sections(_, N) -> lists:duplicate(N, #sdp_media{port = 0}).

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
                    replace(propose_layers(M, T#tr{mline = I}), J);
                false when M#sdp_media.port =:= 0 ->
                    J;
                false ->
                    case [T || T = #tr{mid = undefined, mline = undefined, kind = TK, stopped = false} <- Trs, TK =:= Kind] of
                        [T | _] ->
                            replace(propose_layers(M, T#tr{mid = Mid, mline = I}), J);
                        [] ->
                            New0 = (new_tr(Kind, recvonly, J))#tr{mid = Mid, mline = I, from_remote = true},
                            New = propose_layers(M, New0),
                            J#jsep{transceivers = Trs ++ [New], next_id = New#tr.id + 1}
                    end
            end;
        other ->
            J
    end.

%% An offer asking to receive simulcast gives a transceiver without
%% encodings the offered layers (RFC 9429 §5.10).
propose_layers(M, #tr{encodings = []} = T) ->
    T#tr{encodings = webrtc_jsep_simulcast:proposed(M, {T#tr.ssrc, T#tr.rtx_ssrc})};
propose_layers(_M, T) ->
    T.

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
%% @doc The local ICE ufrag and password.
-spec local_ice(state()) -> {binary(), binary()}.
local_ice(#jsep{ice_ufrag = U, ice_pwd = P}) -> {U, P}.

negotiated(#jsep{} = J) ->
    {Local, Remote} =
        case J#jsep.signaling of
            S when S =:= have_local_pranswer; S =:= have_remote_pranswer ->
                {local_description(J), remote_view(J)};
            _ ->
                {J#jsep.current_local, J#jsep.current_remote}
        end,
    case Local =:= undefined orelse Remote =:= undefined of
        true -> undefined;
        false -> webrtc_jsep_params:negotiated(Local, Remote, J)
    end.

%%====================================================================
%% SSRC collisions (RFC 3550 §8.2)
%%====================================================================

%% @doc A sender changed SSRC after a collision seen in the media: later
%% descriptions carry the new one.
-spec change_ssrc(binary(), 0..16#FFFFFFFF, 0..16#FFFFFFFF, state()) -> state().
change_ssrc(Mid, Old, New, #jsep{transceivers = Trs} = J) ->
    J#jsep{transceivers = [case T#tr.mid of Mid -> swap_ssrc(Old, New, T); _ -> T end || T <- Trs]}.

swap_ssrc(Old, New, #tr{ssrc = S, rtx_ssrc = R, encodings = Es} = T) ->
    Sw = fun(X) when X =:= Old -> New; (X) -> X end,
    T#tr{ssrc = Sw(S), rtx_ssrc = Sw(R),
         encodings = [maps:map(fun(K, V) when K =:= ssrc; K =:= rtx_ssrc -> Sw(V); (_, V) -> V end, E) || E <- Es]}.

%% Our SSRCs that the remote description also uses are replaced before
%% any media goes out with them.
avoid_ssrcs(#sdp{media = Ms}, #jsep{transceivers = Trs} = J) ->
    Remote = lists:usort([S || M <- Ms, #{ssrc := S} <- webrtc_sdp_media:attrs(ssrc, M)]),
    Mine = [X || #tr{ssrc = A, rtx_ssrc = B, encodings = Es} <- Trs,
                 X <- [A, B | [maps:get(K, E) || E <- Es, K <- [ssrc, rtx_ssrc], is_map_key(K, E)]]],
    case [S || S <- Remote, lists:member(S, Mine)] of
        [] ->
            J;
        Clashes ->
            lists:foldl(fun(Old, JA) ->
                                New = fresh_ssrc(Remote ++ Mine),
                                JA#jsep{transceivers = [swap_ssrc(Old, New, T) || T <- JA#jsep.transceivers]}
                        end, J, Clashes)
    end.

fresh_ssrc(Used) ->
    S = ssrc(),
    case lists:member(S, Used) of
        true -> fresh_ssrc(Used);
        false -> S
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
