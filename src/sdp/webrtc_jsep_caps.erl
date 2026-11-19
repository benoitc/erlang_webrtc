%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Media capabilities and their negotiation for JSEP (RFC 9429
%% §5.2.1, §5.3.1, RFC 3264 §6.1).
%%
%% A codec is the map used by `webrtc_sdp_media:codecs/1'. Matching
%% follows RFC 3264: same encoding name (case-insensitive), clock rate
%% and channel count, plus the format parameters that identify a
%% distinct codec (H.264 profile and packetization mode, VP9 profile).
%% Retransmission codecs (RFC 4588) follow the codec named by `apt'.
-module(webrtc_jsep_caps).

-export([
    default_codecs/1,
    default_extensions/1,
    answer_codecs/2,
    match_remote/2,
    answer_extensions/2,
    extension_map/1,
    normalize/1,
    to_extmap/1,
    encrypted_ids/1,
    common_extensions/2,
    single_forms/1,
    fmtp/2,
    same_codec/2,
    pause_params/1,
    is_tmmbr/1
]).

-export_type([extension/0]).

-type codec() :: webrtc_sdp_media:codec().
%% `encrypt': sent with RFC 6904 header extension encryption, signaled
%% as `urn:ietf:params:rtp-hdrext:encrypt <uri>'.
-type extension() :: #{id := pos_integer(), uri := binary(), encrypt => boolean()}.
-type kind() :: audio | video.

-define(FB(T), #{type => T, param => undefined}).
-define(FB(T, P), #{type => T, param => P}).

-define(URI_MID, <<"urn:ietf:params:rtp-hdrext:sdes:mid">>).
-define(URI_RID, <<"urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id">>).
-define(URI_RRID, <<"urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id">>).
-define(URI_AUDIO_LEVEL, <<"urn:ietf:params:rtp-hdrext:ssrc-audio-level">>).
-define(URI_ENCRYPT, <<"urn:ietf:params:rtp-hdrext:encrypt">>).
-define(URI_ABS_SEND_TIME, <<"http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time">>).
-define(URI_TWCC, <<"http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01">>).
-define(URI_TOFFSET, <<"urn:ietf:params:rtp-hdrext:toffset">>).
%% RFC 6051 §3.3, recommended by RFC 8834 §5.2.1.
-define(URI_NTP64, <<"urn:ietf:params:rtp-hdrext:ntp-64">>).
-define(URI_NTP56, <<"urn:ietf:params:rtp-hdrext:ntp-56">>).
-define(URI_PLAYOUT_DELAY, <<"http://www.webrtc.org/experiments/rtp-hdrext/playout-delay">>).
-define(URI_ORIENTATION, <<"urn:3gpp:video-orientation">>).

%%====================================================================
%% Defaults
%%====================================================================

%% @doc Codecs we can transport. RFC 7874 requires Opus and G.711
%% (PCMU, PCMA) for audio; RFC 7742 requires VP8 and H.264 constrained
%% baseline for video. The library forwards payloads; encoding and
%% decoding are the application's concern.
-spec default_codecs(kind()) -> [codec()].
default_codecs(audio) ->
    [
        codec(111, <<"opus">>, 48000, 2, [{<<"minptime">>, <<"10">>}, {<<"useinbandfec">>, <<"1">>}], [
            ?FB(<<"transport-cc">>),
            %% RFC 8888 congestion control feedback, for peers without
            %% transport-cc.
            ?FB(<<"ack">>, <<"ccfb">>),
            ?FB(<<"ccm">>, <<"tmmbr">>)
        ]),
        %% RFC 8854 §4.2: redundant audio (RFC 2198), received and
        %% used (§7), sent when a send asks for it.
        codec(63, <<"red">>, 48000, 2, [<<"111/111">>], []),
        codec(0, <<"PCMU">>, 8000, 1, [], [?FB(<<"ccm">>, <<"tmmbr">>)]),
        codec(8, <<"PCMA">>, 8000, 1, [], [?FB(<<"ccm">>, <<"tmmbr">>)]),
        codec(126, <<"telephone-event">>, 8000, 1, [<<"0-15">>], [])
    ];
default_codecs(video) ->
    Fb = [
        ?FB(<<"goog-remb">>),
        ?FB(<<"transport-cc">>),
        ?FB(<<"ack">>, <<"ccfb">>),
        ?FB(<<"ccm">>, <<"fir">>),
        %% RFC 5104 §4.2, required by RFC 8834 §5.1.6.
        ?FB(<<"ccm">>, <<"tmmbr">>),
        ?FB(<<"nack">>),
        ?FB(<<"nack">>, <<"pli">>),
        %% RFC 8834 §5.1.3, §5.1.4: handed to the application or the
        %% codec plugin (webrtc_media_fb).
        ?FB(<<"nack">>, <<"sli">>),
        ?FB(<<"nack">>, <<"rpsi">>),
        %% RFC 7728 pause and resume; point to point, so no hold-off.
        ?FB(<<"ccm">>, <<"pause nowait">>)
    ],
    [
        codec(96, <<"VP8">>, 90000, undefined, [], Fb),
        rtx(97, 96),
        codec(98, <<"VP9">>, 90000, undefined, [{<<"profile-id">>, <<"0">>}], Fb),
        rtx(99, 98),
        codec(
            102,
            <<"H264">>,
            90000,
            undefined,
            [
                {<<"level-asymmetry-allowed">>, <<"1">>},
                {<<"packetization-mode">>, <<"1">>},
                {<<"profile-level-id">>, <<"42e01f">>}
            ],
            Fb
        ),
        rtx(103, 102),
        codec(45, <<"AV1">>, 90000, undefined, [], Fb),
        rtx(46, 45),
        %% RFC 8854 §5.2: ULPFEC (RFC 5109) in RED (RFC 2198), with the
        %% payload types browsers use.
        codec(116, <<"red">>, 90000, undefined, [], []),
        rtx(117, 116),
        codec(118, <<"ulpfec">>, 90000, undefined, [], []),
        %% RFC 8627 FlexFEC on its own SSRC, repair window 200 ms.
        codec(119, <<"flexfec">>, 90000, undefined, [{<<"repair-window">>, <<"200000">>}], [])
    ].

codec(Pt, Name, Rate, Ch, Fmtp, Fb) ->
    #{pt => Pt, name => Name, clock_rate => Rate, channels => Ch, fmtp => Fmtp, rtcp_fb => Fb}.

rtx(Pt, Apt) ->
    codec(Pt, <<"rtx">>, 90000, undefined, [{<<"apt">>, integer_to_binary(Apt)}], []).

-spec default_extensions(kind()) -> [extension()].
default_extensions(audio) ->
    [
        %% RFC 8834 §5.2.2: the audio level can be encrypted (RFC 6904);
        %% both forms are offered, the answer keeps one.
        #{id => 1, uri => ?URI_AUDIO_LEVEL},
        #{id => 5, uri => ?URI_AUDIO_LEVEL, encrypt => true},
        #{id => 2, uri => ?URI_ABS_SEND_TIME},
        #{id => 3, uri => ?URI_TWCC},
        #{id => 4, uri => ?URI_MID},
        #{id => 6, uri => ?URI_NTP64},
        #{id => 7, uri => ?URI_NTP56}
    ];
default_extensions(video) ->
    [
        #{id => 2, uri => ?URI_ABS_SEND_TIME},
        #{id => 3, uri => ?URI_TWCC},
        #{id => 4, uri => ?URI_MID},
        #{id => 10, uri => ?URI_RID},
        #{id => 11, uri => ?URI_RRID},
        #{id => 13, uri => ?URI_ORIENTATION},
        #{id => 14, uri => ?URI_TOFFSET},
        #{id => 12, uri => ?URI_PLAYOUT_DELAY},
        #{id => 6, uri => ?URI_NTP64},
        #{id => 7, uri => ?URI_NTP56}
    ].

%%====================================================================
%% Negotiation
%%====================================================================

%% @doc Codecs for an answer: the offered codecs we support, in the
%% offer's order and with the offer's payload types (RFC 3264 §6.1,
%% RFC 9429 §5.3.1). Feedback is the intersection; our format
%% parameters describe what we receive, except H.264 where the offered
%% profile-level-id is kept.
-spec answer_codecs([codec()], [codec()]) -> [codec()].
answer_codecs(Offered0, Local) ->
    %% RFC 5761 §4: we always multiplex RTP and RTCP, so payload types
    %% 64..95 are never answered.
    Offered = [O || #{pt := Pt} = O <- Offered0, Pt < 64 orelse Pt > 95],
    Primary = [
        answer_codec(O, L)
     || O <- Offered, not is_rtx(O), {ok, L} <- [find_match(O, Local)]
    ],
    %% RED is kept with the offer's fmtp, which names the offer's
    %% payload types, and only when all of those are kept, or without
    %% fmtp.
    Kept0 = [Pt || #{pt := Pt, name := N} <- Primary, string:lowercase(N) =/= <<"red">>],
    Primary1 = [case string:lowercase(N) of <<"red">> -> red_answer(C, Offered, Kept0); _ -> C end
                || #{name := N} = C <- Primary],
    Primary2 = [C || C <- Primary1, C =/= drop, repair_window_ok(C, Offered)],
    Kept = [Pt || #{pt := Pt} <- Primary2],
    Rtx = [
        O#{fmtp => [{<<"apt">>, integer_to_binary(Apt)}]}
     || O <- Offered, is_rtx(O), {ok, Apt} <- [apt(O)], lists:member(Apt, Kept), has_rtx(Local)
    ],
    order_like(Offered, Primary2 ++ Rtx).

%% RFC 8627 §5.2.1: a receiver that cannot keep the source packets of
%% the offered repair window rejects FlexFEC; we keep up to 1 s (and 160
%% packets). The parameter is required.
-define(MAX_REPAIR_WINDOW_US, 1000000).
repair_window_ok(#{name := N, pt := Pt}, Offered) ->
    case string:lowercase(N) of
        <<"flexfec">> ->
            [O] = [O || #{pt := P} = O <- Offered, P =:= Pt],
            case repair_window(maps:get(fmtp, O, [])) of
                {ok, Us} -> Us =< ?MAX_REPAIR_WINDOW_US;
                error -> false
            end;
        _ ->
            true
    end.

%% repair-window=US, or repair-window:US as the second example of RFC
%% 8627 §7.1.2 writes it.
repair_window(Params) ->
    case [V || P <- Params, V <- window_value(P)] of
        [V | _] ->
            try {ok, binary_to_integer(V)} catch error:badarg -> error end;
        [] ->
            error
    end.

window_value({K, V}) ->
    case string:lowercase(K) of <<"repair-window">> -> [V]; _ -> [] end;
window_value(B) when is_binary(B) ->
    case binary:split(B, <<":">>) of
        [K, V] -> window_value({K, V});
        _ -> []
    end.

red_answer(#{pt := Pt} = C, Offered, Kept) ->
    [O] = [O || #{pt := P} = O <- Offered, P =:= Pt],
    Fmtp = maps:get(fmtp, O, []),
    Pts = lists:append([[binary_to_integer(P) || P <- binary:split(F, <<"/">>, [global]), P =/= <<>>]
                        || F <- Fmtp, is_binary(F)]),
    %% RFC 2198 §5: video RED (RFC 8854 §5.2), ours without fmtp, is
    %% offered without one too and names no payload types.
    Video = maps:get(fmtp, C, []) =:= [] andalso Fmtp =:= [],
    case lists:all(fun(P) -> lists:member(P, Kept) end, Pts) andalso (Pts =/= [] orelse Video) of
        true -> C#{fmtp => Fmtp};
        false -> drop
    end.

answer_codec(#{name := N} = O, L) ->
    Fmtp =
        case string:uppercase(N) of
            <<"H264">> ->
                Plid = proplists:get_value(<<"profile-level-id">>, maps:get(fmtp, O), <<"42e01f">>),
                lists:keystore(<<"profile-level-id">>, 1, maps:get(fmtp, L), {<<"profile-level-id">>, Plid});
            _ ->
                maps:get(fmtp, L)
        end,
    LFb = maps:get(rtcp_fb, L),
    OFb = maps:get(rtcp_fb, O),
    Fb = [F || F <- OFb, lists:member(F, LFb), pause_params(F) =:= undefined, not is_tmmbr(F)],
    O#{fmtp => Fmtp, rtcp_fb => Fb ++ answer_tmmbr(OFb, LFb) ++ answer_pause(OFb, LFb)}.

%% @doc True for a `ccm tmmbr' line, with or without `smaxpr' (RFC 5104
%% §7.1).
-spec is_tmmbr(map()) -> boolean().
is_tmmbr(#{type := T, param := P}) when is_binary(P) ->
    string:lowercase(T) =:= <<"ccm">> andalso
        case binary:split(P, <<" ">>, [global, trim_all]) of
            [Tmmbr | _] -> string:lowercase(Tmmbr) =:= <<"tmmbr">>;
            [] -> false
        end;
is_tmmbr(_) ->
    false.

%% TMMBR is answered without smaxpr: we set no packet rate limit.
answer_tmmbr(OFb, LFb) ->
    case lists:any(fun is_tmmbr/1, OFb) andalso lists:any(fun is_tmmbr/1, LFb) of
        true -> [#{type => <<"ccm">>, param => <<"tmmbr">>}];
        false -> []
    end.

%% RFC 7728 §9: we implement every message (config 1, the default) and
%% answer `nowait' only when it was offered.
answer_pause(OFb, LFb) ->
    case {[P || F <- OFb, P <- [pause_params(F)], P =/= undefined],
          [P || F <- LFb, P <- [pause_params(F)], P =/= undefined]} of
        {[Offered | _], [_ | _]} ->
            Param = case lists:member(<<"nowait">>, Offered) of
                        true -> <<"pause nowait">>;
                        false -> <<"pause">>
                    end,
            [#{type => <<"ccm">>, param => Param}];
        _ ->
            []
    end.

%% @doc The attributes of a `ccm pause' feedback line (RFC 7728 §9), or
%% undefined for other feedback.
-spec pause_params(map()) -> undefined | [binary()].
pause_params(#{type := T, param := P}) when is_binary(P) ->
    case {string:lowercase(T), binary:split(P, <<" ">>, [global, trim_all])} of
        {<<"ccm">>, [Pause | Attrs]} ->
            case string:lowercase(Pause) of
                <<"pause">> -> Attrs;
                _ -> undefined
            end;
        _ ->
            undefined
    end;
pause_params(_) ->
    undefined.

%% @doc Codecs of a remote description that we can send, with the
%% remote payload types (the ones the remote expects to receive).
-spec match_remote([codec()], [codec()]) -> [codec()].
match_remote(Remote, Local) ->
    answer_codecs(Remote, Local).

order_like(Ref, Codecs) ->
    Pts = [Pt || #{pt := Pt} <- Ref],
    lists:sort(
        fun(#{pt := A}, #{pt := B}) -> index(A, Pts) =< index(B, Pts) end,
        Codecs
    ).

index(X, L) -> index(X, L, 1).
index(_, [], N) -> N;
index(X, [X | _], N) -> N;
index(X, [_ | T], N) -> index(X, T, N + 1).

find_match(O, Local) ->
    case [L || L <- Local, not is_rtx(L), same_codec(O, L)] of
        [L | _] -> {ok, L};
        [] -> error
    end.

%% @doc Same codec in the RFC 3264 sense (see the module doc).
-spec same_codec(codec(), codec()) -> boolean().
same_codec(#{name := N1, clock_rate := R1} = A, #{name := N2, clock_rate := R2} = B) ->
    string:uppercase(N1) =:= string:uppercase(N2) andalso R1 =:= R2 andalso
        channels(A) =:= channels(B) andalso same_params(string:uppercase(N1), A, B).

channels(#{channels := undefined}) -> 1;
channels(#{channels := C}) -> C;
channels(_) -> 1.

same_params(<<"H264">>, A, B) ->
    profile(fmtp(<<"profile-level-id">>, A)) =:= profile(fmtp(<<"profile-level-id">>, B)) andalso
        default(fmtp(<<"packetization-mode">>, A), <<"0">>) =:=
            default(fmtp(<<"packetization-mode">>, B), <<"0">>);
same_params(<<"VP9">>, A, B) ->
    default(fmtp(<<"profile-id">>, A), <<"0">>) =:= default(fmtp(<<"profile-id">>, B), <<"0">>);
same_params(_, _, _) ->
    true.

%% profile_idc and profile_iop of profile-level-id (RFC 6184 §8.1); the
%% level may differ.
profile(undefined) -> profile(<<"420010">>);
profile(<<P:4/binary, _/binary>>) -> string:lowercase(P);
profile(_) -> undefined.

default(undefined, D) -> D;
default(V, _) -> V.

%% @doc A format parameter of a codec.
-spec fmtp(binary(), codec()) -> binary() | undefined.
fmtp(Key, #{fmtp := Params}) ->
    case lists:keyfind(Key, 1, [P || P <- Params, is_tuple(P)]) of
        {_, V} -> V;
        false -> undefined
    end.

is_rtx(#{name := N}) -> string:lowercase(N) =:= <<"rtx">>.

has_rtx(Local) -> lists:any(fun is_rtx/1, Local).

apt(C) ->
    case fmtp(<<"apt">>, C) of
        undefined -> error;
        V ->
            try binary_to_integer(V) of
                N when N >= 0, N =< 127 -> {ok, N};
                _ -> error
            catch
                error:badarg -> error
            end
    end.

%% @doc Offered header extensions we support, keeping the offered ids
%% (RFC 8285 §5). An extension offered both in clear and encrypted
%% (RFC 6904 §4.1) is answered encrypted when we can, and never in both
%% forms.
-spec answer_extensions([webrtc_sdp_rtp:extmap()], [extension()]) -> [extension()].
answer_extensions(Offered0, Local0) ->
    Offered = [normalize(E) || E <- Offered0],
    Local = [normalize(E) || E <- Local0],
    CanEncrypt = [U || #{uri := U, encrypt := true} <- Local],
    Known = [U || #{uri := U} <- Local],
    Chosen = [
        E
     || U <- lists:usort([U || #{uri := U} <- Offered]),
        lists:member(U, Known),
        E <- choose(U, [X || #{uri := U1} = X <- Offered, U1 =:= U], lists:member(U, CanEncrypt))
    ],
    %% In the offer's order.
    [E || E <- Offered, lists:member(E, Chosen)].

%% The encrypted form when offered and we encrypt it, else the clear one.
choose(_U, Forms, true) ->
    case [E || #{encrypt := true} = E <- Forms] of
        [E | _] -> [E];
        [] -> choose(_U, Forms, false)
    end;
choose(_U, Forms, false) ->
    lists:sublist([E || #{encrypt := false} = E <- Forms], 1).

%% @doc An extension or `a=extmap' value with the encrypted form told
%% apart: `uri' is the extension's own URI and `encrypt' says whether it
%% is sent encrypted (RFC 6904 §4).
-spec normalize(extension() | webrtc_sdp_rtp:extmap()) -> extension().
normalize(#{uri := ?URI_ENCRYPT, attributes := A} = E) when is_binary(A) ->
    [Inner | _] = binary:split(A, <<" ">>),
    #{id => maps:get(id, E), uri => Inner, encrypt => true};
normalize(#{id := Id, uri := U} = E) ->
    #{id => Id, uri => U, encrypt => maps:get(encrypt, E, false) =:= true}.

%% @doc The `a=extmap' value of an extension.
-spec to_extmap(extension()) -> webrtc_sdp_rtp:extmap().
to_extmap(#{id := Id, uri := U} = E) ->
    case maps:get(encrypt, E, false) of
        true -> #{id => Id, direction => undefined, uri => ?URI_ENCRYPT, attributes => U};
        false -> #{id => Id, direction => undefined, uri => U, attributes => undefined}
    end.

%% @doc `#{Uri => Id}' for a list of extensions, by their own URI
%% whether encrypted or not.
-spec extension_map([extension() | webrtc_sdp_rtp:extmap()]) -> #{binary() => pos_integer()}.
extension_map(Exts) ->
    maps:from_list([{U, Id} || E <- Exts, #{id := Id, uri := U} <- [normalize(E)]]).

%% @doc Ids of the encrypted extensions of a list.
-spec encrypted_ids([extension() | webrtc_sdp_rtp:extmap()]) -> [pos_integer()].
encrypted_ids(Exts) ->
    lists:usort([Id || E <- Exts, #{id := Id, encrypt := true} <- [normalize(E)]]).

%% @doc The extensions of `Mine' in the form (clear or encrypted) the
%% other description `Theirs' also has (RFC 8285 §6, RFC 6904 §4.1).
-spec common_extensions([webrtc_sdp_rtp:extmap()], [webrtc_sdp_rtp:extmap()]) -> [extension()].
common_extensions(Mine, Theirs) ->
    Forms = [{U, Enc} || E <- Theirs, #{uri := U, encrypt := Enc} <- [normalize(E)]],
    [N || E <- Mine, #{uri := U, encrypt := Enc} = N <- [normalize(E)], lists:member({U, Enc}, Forms)].

%% @doc True when no extension appears both in clear and encrypted (an
%% answer must not negotiate both, RFC 6904 §4.1).
-spec single_forms([webrtc_sdp_rtp:extmap()]) -> boolean().
single_forms(Exts) ->
    Ns = [normalize(E) || E <- Exts],
    Uris = [U || #{uri := U} <- Ns],
    lists:all(
        fun(U) -> length(lists:usort([Enc || #{uri := U1, encrypt := Enc} <- Ns, U1 =:= U])) =:= 1 end,
        Uris
    ).
