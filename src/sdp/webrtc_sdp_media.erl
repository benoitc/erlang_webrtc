%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Queries and updates on parsed SDP for JSEP.
%%
%% Attribute lookups take the key used in `webrtc_sdp:attribute()' (an
%% atom for typed attributes, a binary for others). Functions taking both
%% a media section and the session apply the session-level fallback rules:
%% `ice-ufrag', `ice-pwd' and `ice-options' (RFC 8839 §5.4, §5.6),
%% `fingerprint' (RFC 8122 §5), `setup' (RFC 4145 §4) and direction
%% (RFC 8866 §6.7).
%%
%% ```
%% [Audio | _] = webrtc_sdp_media:sections(Sdp),
%% {ok, #{ufrag := U, pwd := P}} = webrtc_sdp_media:ice_credentials(Audio, Sdp),
%% [#{name := <<"opus">>} | _] = webrtc_sdp_media:codecs(Audio).
%% '''
-module(webrtc_sdp_media).

-include("webrtc_sdp.hrl").

-export([
    sections/1,
    attr/2,
    attrs/2,
    find_attr/3,
    find_attrs/3,
    put_attr/3,
    add_attr/3,
    delete_attrs/2,
    mid/1,
    direction/2,
    ice_credentials/2,
    ice_options/2,
    ice_pacing/1,
    ice_lite/1,
    fingerprints/2,
    setup/2,
    candidates/1,
    end_of_candidates/1,
    groups/2,
    payload_types/1,
    codecs/1,
    codec_attributes/1,
    set_codecs/2
]).

-export_type([codec/0, key/0]).

-type key() :: atom() | binary().
-type container() :: #sdp{} | #sdp_media{}.
-type codec() :: #{
    pt := 0..127,
    name := binary(),
    clock_rate := pos_integer(),
    channels := pos_integer() | undefined,
    fmtp := [webrtc_sdp_rtp:fmtp_param()],
    rtcp_fb := [#{type := binary(), param := binary() | undefined}]
}.

%% @doc The media sections in order.
-spec sections(#sdp{}) -> [#sdp_media{}].
sections(#sdp{media = M}) -> M.

%% @doc First value of attribute `Key' at this level only.
-spec attr(key(), container()) -> {ok, term()} | error.
attr(Key, C) ->
    case lists:keyfind(Key, 1, attributes(C)) of
        {_, V} -> {ok, V};
        false -> error
    end.

%% @doc All values of attribute `Key' at this level, in order.
-spec attrs(key(), container()) -> [term()].
attrs(Key, C) ->
    [V || {K, V} <- attributes(C), K =:= Key].

%% @doc First value of `Key' in the media section, else at session level.
-spec find_attr(key(), #sdp_media{}, #sdp{}) -> {ok, term()} | error.
find_attr(Key, M, S) ->
    case attr(Key, M) of
        {ok, V} -> {ok, V};
        error -> attr(Key, S)
    end.

%% @doc Values of `Key' in the media section if there is any, else the
%% session-level values. Levels are not merged.
-spec find_attrs(key(), #sdp_media{}, #sdp{}) -> [term()].
find_attrs(Key, M, S) ->
    case attrs(Key, M) of
        [] -> attrs(Key, S);
        Vs -> Vs
    end.

%% @doc Replace the first `Key' attribute (dropping the others), or append.
-spec put_attr(key(), term(), C) -> C when C :: container().
put_attr(Key, V, C) ->
    Attrs = attributes(C),
    New =
        case lists:keymember(Key, 1, Attrs) of
            true ->
                {Before, [_ | After]} = lists:splitwith(fun({K, _}) -> K =/= Key end, Attrs),
                Before ++ [{Key, V} | [A || {K, _} = A <- After, K =/= Key]];
            false ->
                Attrs ++ [{Key, V}]
        end,
    set_attributes(New, C).

%% @doc Append an attribute.
-spec add_attr(key(), term(), C) -> C when C :: container().
add_attr(Key, V, C) ->
    set_attributes(attributes(C) ++ [{Key, V}], C).

-spec delete_attrs(key(), C) -> C when C :: container().
delete_attrs(Key, C) ->
    set_attributes([A || {K, _} = A <- attributes(C), K =/= Key], C).

attributes(#sdp{attributes = A}) -> A;
attributes(#sdp_media{attributes = A}) -> A.

set_attributes(A, #sdp{} = S) -> S#sdp{attributes = A};
set_attributes(A, #sdp_media{} = M) -> M#sdp_media{attributes = A}.

-spec mid(#sdp_media{}) -> binary() | undefined.
mid(M) ->
    case attr(mid, M) of
        {ok, Mid} -> Mid;
        error -> undefined
    end.

%% @doc Media direction; defaults to `sendrecv' (RFC 8866 §6.7).
-spec direction(#sdp_media{}, #sdp{}) -> webrtc_sdp_rtp:direction().
direction(M, S) ->
    case find_attr(direction, M, S) of
        {ok, D} -> D;
        error -> sendrecv
    end.

%% @doc ICE credentials of a media section, each falling back to the
%% session level (RFC 8839 §5.4).
-spec ice_credentials(#sdp_media{}, #sdp{}) ->
    {ok, #{ufrag := binary(), pwd := binary()}} | {error, missing_ice_credentials}.
ice_credentials(M, S) ->
    case {find_attr(ice_ufrag, M, S), find_attr(ice_pwd, M, S)} of
        {{ok, U}, {ok, P}} -> {ok, #{ufrag => U, pwd => P}};
        _ -> {error, missing_ice_credentials}
    end.

-spec ice_options(#sdp_media{}, #sdp{}) -> [binary()].
ice_options(M, S) ->
    case find_attr(ice_options, M, S) of
        {ok, Tags} -> Tags;
        error -> []
    end.

%% @doc The Ta the session asks for (`a=ice-pacing', session level,
%% RFC 8839 §5.5), 50 ms when absent.
-spec ice_pacing(#sdp{}) -> non_neg_integer().
ice_pacing(S) ->
    case attr(ice_pacing, S) of
        {ok, Ta} -> Ta;
        error -> 50
    end.

%% @doc True when the session declares `a=ice-lite' (session level only).
-spec ice_lite(#sdp{}) -> boolean().
ice_lite(S) -> attr(ice_lite, S) =:= {ok, true}.

%% @doc Fingerprints for a media section: the media-level ones if any,
%% else the session-level ones (RFC 8122 §5).
-spec fingerprints(#sdp_media{}, #sdp{}) -> [webrtc_sdp_attr:fingerprint()].
fingerprints(M, S) -> find_attrs(fingerprint, M, S).

%% @doc `a=setup' role, media level first. JSEP (RFC 8842 §5.1) requires
%% the attribute, so an absent one is reported rather than defaulted.
-spec setup(#sdp_media{}, #sdp{}) -> {ok, webrtc_sdp_attr:setup()} | error.
setup(M, S) -> find_attr(setup, M, S).

-spec candidates(#sdp_media{}) -> [#sdp_candidate{}].
candidates(M) -> attrs(candidate, M).

-spec end_of_candidates(#sdp_media{}) -> boolean().
end_of_candidates(M) -> attr(end_of_candidates, M) =:= {ok, true}.

%% @doc Mid lists of the session-level groups with these semantics, for
%% example `groups(<<"BUNDLE">>, Sdp)'.
-spec groups(binary(), #sdp{}) -> [[binary()]].
groups(Semantics, S) ->
    [Mids || #{semantics := Sem, mids := Mids} <- attrs(group, S), Sem =:= Semantics].

%% @doc Payload types of the m= line, for RTP media.
-spec payload_types(#sdp_media{}) -> [0..127].
payload_types(#sdp_media{fmts = Fmts}) ->
    [Pt || F <- Fmts, {ok, Pt} <- [webrtc_sdp_lex:parse_int(F, 0, 127)]].

%% @doc Codecs of an RTP media section in m= line order, merging rtpmap,
%% fmtp and rtcp-fb. Wildcard (`*') feedback is copied into every codec.
%% A payload type without rtpmap uses the RFC 3551 static assignment; one
%% that has neither is skipped.
-spec codecs(#sdp_media{}) -> [codec()].
codecs(M) ->
    Attrs = M#sdp_media.attributes,
    Maps = #{Pt => R || {rtpmap, #{pt := Pt} = R} <- lists:reverse(Attrs)},
    Fmtps = #{Pt => P || {fmtp, #{fmt := Pt, params := P}} <- lists:reverse(Attrs), is_integer(Pt)},
    Fbs = [F || {rtcp_fb, F} <- Attrs],
    lists:filtermap(
        fun(Pt) ->
            case rtpmap(Pt, Maps) of
                undefined ->
                    false;
                #{name := Name, clock_rate := Rate} = R ->
                    {true, #{
                        pt => Pt,
                        name => Name,
                        clock_rate => Rate,
                        channels => maps:get(channels, R, undefined),
                        fmtp => maps:get(Pt, Fmtps, []),
                        rtcp_fb => [
                            #{type => T, param => P}
                         || #{pt := FPt, type := T, param := P} <- Fbs, FPt =:= Pt orelse FPt =:= '*'
                        ]
                    }}
            end
        end,
        payload_types(M)
    ).

rtpmap(Pt, Maps) ->
    case Maps of
        #{Pt := R} -> R;
        _ -> static(Pt)
    end.

%% RFC 3551 §6 static payload types.
static(0) -> #{name => <<"PCMU">>, clock_rate => 8000, channels => 1};
static(3) -> #{name => <<"GSM">>, clock_rate => 8000, channels => 1};
static(4) -> #{name => <<"G723">>, clock_rate => 8000, channels => 1};
static(8) -> #{name => <<"PCMA">>, clock_rate => 8000, channels => 1};
static(9) -> #{name => <<"G722">>, clock_rate => 8000, channels => 1};
static(13) -> #{name => <<"CN">>, clock_rate => 8000, channels => 1};
static(18) -> #{name => <<"G729">>, clock_rate => 8000, channels => 1};
static(_) -> undefined.

%% @doc Attributes describing `Codecs': for each codec its rtpmap, its
%% rtcp-fb lines, then its fmtp when it has parameters (the order used by
%% libwebrtc).
-spec codec_attributes([codec()]) -> [webrtc_sdp:attribute()].
codec_attributes(Codecs) ->
    lists:flatmap(fun codec_attrs/1, Codecs).

codec_attrs(#{pt := Pt, name := Name, clock_rate := Rate} = C) ->
    Map = {rtpmap, #{pt => Pt, name => Name, clock_rate => Rate, channels => maps:get(channels, C, undefined)}},
    Fb = [
        {rtcp_fb, #{pt => Pt, type => T, param => maps:get(param, F, undefined)}}
     || #{type := T} = F <- maps:get(rtcp_fb, C, [])
    ],
    Fmtp =
        case maps:get(fmtp, C, []) of
            [] -> [];
            Params -> [{fmtp, #{fmt => Pt, params => Params}}]
        end,
    [Map | Fb] ++ Fmtp.

%% @doc Replace the codecs of a media section: the m= line payload types
%% and the rtpmap, fmtp and rtcp-fb attributes. The new codec attributes
%% take the place of the first old one; other attributes keep their order.
-spec set_codecs(#sdp_media{}, [codec(), ...]) -> #sdp_media{}.
set_codecs(M, [_ | _] = Codecs) ->
    IsCodec = fun({K, _}) -> K =:= rtpmap orelse K =:= fmtp orelse K =:= rtcp_fb end,
    {Before, After} = lists:splitwith(fun(A) -> not IsCodec(A) end, M#sdp_media.attributes),
    Rest = [A || A <- After, not IsCodec(A)],
    M#sdp_media{
        fmts = [integer_to_binary(Pt) || #{pt := Pt} <- Codecs],
        attributes = Before ++ codec_attributes(Codecs) ++ Rest
    }.
