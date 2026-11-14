%% @private Negotiated parameters (`webrtc_jsep:negotiated/1') from a
%% local and a remote description: the contract between negotiation and
%% the transport (ICE, DTLS, per-mid media and the data channel).
-module(webrtc_jsep_params).

-include("webrtc_sdp.hrl").
-include("webrtc_jsep.hrl").

-export([negotiated/3]).

-spec negotiated(#sdp{}, #sdp{}, #jsep{}) -> map().
negotiated(Local, Remote, J) ->
    [Tag | _] = [M || M <- Remote#sdp.media, M#sdp_media.port =/= 0],
    {ok, Ice} = webrtc_sdp_media:ice_credentials(Tag, Remote),
    Media = [
        media_params(T, section(T#tr.mline, Local), section(T#tr.mline, Remote), Remote)
     || #tr{mline = L, stopped = false} = T <- J#jsep.transceivers,
        L =/= undefined,
        section(L, Local) =/= undefined
    ],
    Data =
        case J#jsep.data_mline of
            undefined -> undefined;
            DL -> data_params(J, section(DL, Remote))
        end,
    #{
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
        media => [M || M <- Media, M =/= undefined],
        data => Data,
        bundle => case webrtc_sdp_media:groups(<<"BUNDLE">>, Remote) of
            [G | _] -> G;
            [] -> []
        end
    }.

media_params(_T, _L, #sdp_media{port = 0}, _Remote) ->
    undefined;
media_params(T, L, R, _Remote) ->
    RemoteCodecs = webrtc_sdp_media:codecs(R),
    LocalCodecs = webrtc_sdp_media:codecs(L),
    Layers = webrtc_jsep_simulcast:negotiated(T#tr.encodings, L, R),
    Layers#{
        id => T#tr.id,
        mid => T#tr.mid,
        kind => T#tr.kind,
        direction => T#tr.current_direction,
        send_codecs => webrtc_jsep_caps:match_remote(RemoteCodecs, T#tr.codecs),
        recv_codecs => LocalCodecs,
        send_extensions => webrtc_jsep_caps:extension_map(webrtc_sdp_media:attrs(extmap, R)),
        recv_extensions => webrtc_jsep_caps:extension_map(webrtc_sdp_media:attrs(extmap, L)),
        ssrc => T#tr.ssrc,
        rtx_ssrc => T#tr.rtx_ssrc,
        cname => undefined,
        remote_ssrcs => remote_ssrcs(R),
        rtcp_rsize => webrtc_sdp_media:attr(rtcp_rsize, R) =:= {ok, true}
    }.

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
