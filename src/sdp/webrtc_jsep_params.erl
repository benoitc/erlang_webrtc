%% @private Negotiated parameters (`webrtc_jsep:negotiated/1') from a
%% local and a remote description: the contract between negotiation and
%% the transport (ICE, DTLS, per-mid media and the data channel).
-module(webrtc_jsep_params).

-include("webrtc_sdp.hrl").
-include("webrtc_jsep.hrl").

-export([negotiated/3]).

%% `undefined' when the remote description has no usable section (the
%% validation of `webrtc_jsep' refuses such descriptions).
-spec negotiated(#sdp{}, #sdp{}, #jsep{}) -> map() | undefined.
negotiated(Local, Remote, J) ->
    case [{M, I} || M <- Remote#sdp.media, M#sdp_media.port =/= 0, {ok, I} <- [webrtc_sdp_media:ice_credentials(M, Remote)]] of
        [{Tag, Ice} | _] -> negotiated(Tag, Ice, Local, Remote, J);
        [] -> undefined
    end.

negotiated(Tag0, Ice0, Local, Remote, J) ->
    Groups = webrtc_jsep_transport:groups(Local),
    Transports = [transport_params(K, Ms, Groups, Remote, J) || {K, Ms, _} <- Groups],
    Key = fun(Mid) -> webrtc_jsep_transport:key_of(Mid, Groups) end,
    Media = [
        M#{transport => Key(maps:get(mid, M))}
     || #tr{mline = L, stopped = false} = T <- J#jsep.transceivers,
        L =/= undefined,
        section(L, Local) =/= undefined,
        M <- [media_params(T, section(T#tr.mline, Local), section(T#tr.mline, Remote), {Local, Remote, J})],
        M =/= undefined
    ],
    Data =
        case J#jsep.data_mline of
            undefined -> undefined;
            DL ->
                case data_params(J, section(DL, Remote)) of
                    undefined -> undefined;
                    D -> D#{transport => Key(J#jsep.data_mid)}
                end
        end,
    %% The first transport keeps the top level ice and dtls.
    {Tag, Ice} =
        case Transports of
            [#{tag_section := TS, remote_ice := RI} | _] -> {TS, RI};
            [] -> {Tag0, Ice0}
        end,
    Base = #{
        ice => #{
            remote_ufrag => maps:get(ufrag, Ice),
            remote_pwd => maps:get(pwd, Ice),
            remote_lite => webrtc_sdp_media:ice_lite(Remote),
            remote_candidates => lists:flatmap(
                fun(M) -> webrtc_sdp_media:candidates(M) end, Remote#sdp.media
            ),
            remote_end_of_candidates => lists:any(
                fun(M) -> webrtc_sdp_media:end_of_candidates(M) end, Remote#sdp.media
            ),
            local_ufrag => J#jsep.ice_ufrag,
            local_pwd => J#jsep.ice_pwd
        },
        dtls => #{
            role => J#jsep.dtls_role,
            remote_tls_id =>
                case webrtc_sdp_media:find_attr(tls_id, Tag, Remote) of
                    {ok, T} -> T;
                    error -> undefined
                end,
            remote_fingerprints => [
                {H, V}
             || #{hash := H, value := V} <- webrtc_sdp_media:fingerprints(Tag, Remote), is_atom(H)
            ]
        },
        media => Media,
        data => Data,
        bundle => case webrtc_sdp_media:groups(<<"BUNDLE">>, Remote) of
            [G | _] -> G;
            [] -> []
        end
    },
    Base#{transports => [maps:without([tag_section, remote_ice], T) || T <- Transports]}.

%% ICE and DTLS parameters of one transport, from its first active
%% section in the remote description (the tag when it is active).
transport_params(Key, Mids, Groups, Remote, J) ->
    Sections = [M || M <- Remote#sdp.media, lists:member(webrtc_sdp_media:mid(M), Mids)],
    Active = [M || M <- Sections, M#sdp_media.port =/= 0],
    Tag =
        case [M || M <- Active, webrtc_sdp_media:mid(M) =:= Key] ++ Active of
            [T | _] -> T;
            [] -> hd(Sections ++ Remote#sdp.media)
        end,
    Ice =
        case webrtc_sdp_media:ice_credentials(Tag, Remote) of
            {ok, I} -> I;
            _ -> #{ufrag => <<>>, pwd => <<>>}
        end,
    {U, P} = webrtc_jsep_build:creds(Key, Groups, J),
    #{
        key => Key,
        mids => Mids,
        tag_section => Tag,
        remote_ice => Ice,
        ice => #{
            remote_ufrag => maps:get(ufrag, Ice),
            remote_pwd => maps:get(pwd, Ice),
            remote_lite => webrtc_sdp_media:ice_lite(Remote),
            remote_candidates => lists:flatmap(fun webrtc_sdp_media:candidates/1, Sections),
            remote_end_of_candidates => lists:any(fun webrtc_sdp_media:end_of_candidates/1, Sections),
            local_ufrag => U,
            local_pwd => P
        },
        dtls => #{
            role => J#jsep.dtls_role,
            remote_tls_id =>
                case webrtc_sdp_media:find_attr(tls_id, Tag, Remote) of
                    {ok, Id} -> Id;
                    error -> undefined
                end,
            remote_fingerprints => [
                {H, V}
             || #{hash := H, value := V} <- webrtc_sdp_media:fingerprints(Tag, Remote), is_atom(H)
            ]
        }
    }.

media_params(_T, _L, undefined, _Ctx) ->
    undefined;
media_params(_T, _L, #sdp_media{port = 0}, _Ctx) ->
    undefined;
media_params(T, L, R, {Local, Remote, J}) ->
    RemoteCodecs = webrtc_sdp_media:codecs(R),
    LocalCodecs = webrtc_sdp_media:codecs(L),
    LX = webrtc_sdp_media:attrs(extmap, L),
    RX = webrtc_sdp_media:attrs(extmap, R),
    %% Only extensions both descriptions have, in the same form, clear or
    %% encrypted (RFC 8285 §6, RFC 6904 §4.1): the remote ids for sending,
    %% ours for receiving.
    Send = webrtc_jsep_caps:common_extensions(RX, LX),
    Recv = webrtc_jsep_caps:common_extensions(LX, RX),
    Layers = webrtc_jsep_simulcast:negotiated(T#tr.encodings, L, R, J#jsep.answerer),
    Layers#{
        id => T#tr.id,
        mid => T#tr.mid,
        kind => T#tr.kind,
        direction => T#tr.current_direction,
        send_codecs => webrtc_jsep_caps:match_remote(RemoteCodecs, T#tr.codecs),
        recv_codecs => LocalCodecs,
        send_extensions => webrtc_jsep_caps:extension_map(Send),
        recv_extensions => webrtc_jsep_caps:extension_map(Recv),
        send_encrypted => webrtc_jsep_caps:encrypted_ids(Send),
        recv_encrypted => webrtc_jsep_caps:encrypted_ids(Recv),
        ssrc => T#tr.ssrc,
        rtx_ssrc => T#tr.rtx_ssrc,
        frames => T#tr.frames,
        cname => undefined,
        remote_ssrcs => remote_ssrcs(R),
        rtcp_rsize => webrtc_sdp_media:attr(rtcp_rsize, R) =:= {ok, true},
        pause => pause(LocalCodecs, RemoteCodecs),
        %% RFC 8888 §6: both descriptions have `ack ccfb'.
        ccfb => ccfb(LocalCodecs) andalso ccfb(RemoteCodecs),
        %% RFC 9335: both sides receive encrypted CSRCs and extensions.
        cryptex => webrtc_sdp_media:find_attr(cryptex, L, Local) =:= {ok, true} andalso
            webrtc_sdp_media:find_attr(cryptex, R, Remote) =:= {ok, true}
    }.

%% RTP stream pause and resume (RFC 7728 §9): both descriptions have a
%% `ccm pause' line; no hold-off when both say `nowait'.
pause(Local, Remote) ->
    Params = fun(Cs) -> [P || #{rtcp_fb := Fb} <- Cs, F <- Fb, P <- [webrtc_jsep_caps:pause_params(F)], P =/= undefined] end,
    case {Params(Local), Params(Remote)} of
        {[L | _], [R | _]} -> #{nowait => lists:member(<<"nowait">>, L) andalso lists:member(<<"nowait">>, R)};
        _ -> undefined
    end.

ccfb(Codecs) ->
    lists:any(fun(#{rtcp_fb := Fb}) -> lists:member(#{type => <<"ack">>, param => <<"ccfb">>}, Fb) end, Codecs).

remote_ssrcs(R) ->
    Ssrcs = webrtc_sdp_media:attrs(ssrc, R),
    Groups = webrtc_sdp_media:attrs(ssrc_group, R),
    Rtx = maps:from_list([{P, X} || #{semantics := <<"FID">>, ssrcs := [P, X]} <- Groups]),
    Primary = lists:usort([S || #{ssrc := S} <- Ssrcs]) -- maps:values(Rtx),
    [
        #{
            ssrc => S,
            rtx_ssrc => maps:get(S, Rtx, undefined),
            cname => hd([V || #{ssrc := S1, attribute := <<"cname">>, value := V} <- Ssrcs, S1 =:= S] ++ [undefined])
        }
     || S <- Primary
    ].

data_params(_J, undefined) ->
    undefined;
data_params(_J, #sdp_media{port = 0}) ->
    undefined;
data_params(J, R) ->
    #{
        mid => J#jsep.data_mid,
        local_port => J#jsep.sctp_port,
        local_max_message_size => J#jsep.max_message_size,
        remote_port =>
            case webrtc_sdp_media:attr(sctp_port, R) of
                {ok, P} -> P;
                error -> 5000
            end,
        %% RFC 8841 §6: absent means 64 KiB.
        remote_max_message_size =>
            case webrtc_sdp_media:attr(max_message_size, R) of
                {ok, N} -> N;
                error -> 65536
            end
    }.

section(I, #sdp{media = M}) when I < length(M) -> lists:nth(I + 1, M);
section(_, _) -> undefined.
