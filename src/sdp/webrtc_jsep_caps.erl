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
    fmtp/2
]).

-export_type([extension/0]).

-type codec() :: webrtc_sdp_media:codec().
-type extension() :: #{id := pos_integer(), uri := binary()}.
-type kind() :: audio | video.

-define(FB(T), #{type => T, param => undefined}).
-define(FB(T, P), #{type => T, param => P}).

-define(URI_MID, <<"urn:ietf:params:rtp-hdrext:sdes:mid">>).
-define(URI_RID, <<"urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id">>).
-define(URI_RRID, <<"urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id">>).
-define(URI_AUDIO_LEVEL, <<"urn:ietf:params:rtp-hdrext:ssrc-audio-level">>).
-define(URI_ABS_SEND_TIME, <<"http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time">>).
-define(URI_TWCC, <<"http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01">>).
-define(URI_TOFFSET, <<"urn:ietf:params:rtp-hdrext:toffset">>).
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
            ?FB(<<"transport-cc">>)
        ]),
        codec(0, <<"PCMU">>, 8000, 1, [], []),
        codec(8, <<"PCMA">>, 8000, 1, [], []),
        codec(126, <<"telephone-event">>, 8000, 1, [<<"0-15">>], [])
    ];
default_codecs(video) ->
    Fb = [
        ?FB(<<"goog-remb">>),
        ?FB(<<"transport-cc">>),
        ?FB(<<"ccm">>, <<"fir">>),
        ?FB(<<"nack">>),
        ?FB(<<"nack">>, <<"pli">>)
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
        rtx(46, 45)
    ].

codec(Pt, Name, Rate, Ch, Fmtp, Fb) ->
    #{pt => Pt, name => Name, clock_rate => Rate, channels => Ch, fmtp => Fmtp, rtcp_fb => Fb}.

rtx(Pt, Apt) ->
    codec(Pt, <<"rtx">>, 90000, undefined, [{<<"apt">>, integer_to_binary(Apt)}], []).

-spec default_extensions(kind()) -> [extension()].
default_extensions(audio) ->
    [
        #{id => 1, uri => ?URI_AUDIO_LEVEL},
        #{id => 2, uri => ?URI_ABS_SEND_TIME},
        #{id => 3, uri => ?URI_TWCC},
        #{id => 4, uri => ?URI_MID}
    ];
default_extensions(video) ->
    [
        #{id => 2, uri => ?URI_ABS_SEND_TIME},
        #{id => 3, uri => ?URI_TWCC},
        #{id => 4, uri => ?URI_MID},
        #{id => 10, uri => ?URI_RID},
        #{id => 11, uri => ?URI_RRID},
        #{id => 13, uri => ?URI_ORIENTATION},
        #{id => 14, uri => ?URI_TOFFSET}
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
answer_codecs(Offered, Local) ->
    Primary = [
        answer_codec(O, L)
     || O <- Offered, not is_rtx(O), {ok, L} <- [find_match(O, Local)]
    ],
    Kept = [Pt || #{pt := Pt} <- Primary],
    Rtx = [
        O#{fmtp => [{<<"apt">>, integer_to_binary(Apt)}]}
     || O <- Offered, is_rtx(O), {ok, Apt} <- [apt(O)], lists:member(Apt, Kept), has_rtx(Local)
    ],
    order_like(Offered, Primary ++ Rtx).

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
    Fb = [F || F <- maps:get(rtcp_fb, O), lists:member(F, LFb)],
    O#{fmtp => Fmtp, rtcp_fb => Fb}.

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
%% (RFC 8285 §5).
-spec answer_extensions([webrtc_sdp_rtp:extmap()], [extension()]) -> [extension()].
answer_extensions(Offered, Local) ->
    Uris = [U || #{uri := U} <- Local],
    [#{id => Id, uri => U} || #{id := Id, uri := U} <- Offered, lists:member(U, Uris)].

%% @doc `#{Uri => Id}' for a list of extensions.
-spec extension_map([extension() | webrtc_sdp_rtp:extmap()]) -> #{binary() => pos_integer()}.
extension_map(Exts) ->
    maps:from_list([{U, Id} || #{id := Id, uri := U} <- Exts]).
