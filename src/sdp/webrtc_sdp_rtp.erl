%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc RTP related SDP attribute values: rtpmap and fmtp (RFC 8866 §6),
%% rtcp-fb (RFC 4585 §4.2), extmap (RFC 8285 §8), msid (RFC 8830),
%% legacy msid-semantic, ssrc and ssrc-group (RFC 5576). rid and
%% simulcast values are handled by `webrtc_sdp_rid'.
%%
%% `parse/2' takes the attribute key and the text after the colon;
%% `encode/2' returns that text. Used by `webrtc_sdp_attr'.
-module(webrtc_sdp_rtp).

-export([parse/2, encode/2, parse_fmtp_params/1, encode_fmtp_params/1]).

-export_type([
    rtpmap/0,
    fmtp/0,
    fmtp_param/0,
    rtcp_fb/0,
    extmap/0,
    msid/0,
    msid_semantic/0,
    ssrc/0,
    ssrc_group/0,
    direction/0
]).

-type direction() :: sendrecv | sendonly | recvonly | inactive.
-type pt() :: 0..127.
-type rtpmap() :: #{
    pt := pt(), name := binary(), clock_rate := pos_integer(), channels := pos_integer() | undefined
}.
%% A parameter is `Key=Value' or a bare value such as `0-15'.
-type fmtp_param() :: {binary(), binary()} | binary().
%% `raw' holds the parameter text as received when it differs from the
%% canonical `k=v;k=v' form. It is written back while it still parses to
%% `params', so unmodified input round trips byte exact.
-type fmtp() :: #{fmt := pt() | binary(), params := [fmtp_param()], raw => binary()}.
-type rtcp_fb() :: #{pt := pt() | '*', type := binary(), param := binary() | undefined}.
-type extmap() :: #{
    id := 1..255 | 4096..4351,
    direction := direction() | undefined,
    uri := binary(),
    attributes := binary() | undefined
}.
-type msid() :: #{stream := binary(), track := binary() | undefined}.
-type msid_semantic() :: #{semantic := binary(), ids := [binary()], raw => binary()}.
-type ssrc() :: #{ssrc := 0..4294967295, attribute := binary(), value := binary() | undefined}.
-type ssrc_group() :: #{semantics := binary(), ssrcs := [0..4294967295]}.

-define(MAX_SSRC, 4294967295).

-spec parse(atom(), binary()) -> {ok, term()} | error.
parse(rtpmap, V) ->
    maybe
        {ok, [PtB, Enc]} ?= webrtc_sdp_lex:split_sp(V),
        {ok, Pt} ?= pt(PtB),
        {ok, Map} ?= encoding(binary:split(Enc, <<"/">>, [global])),
        {ok, Map#{pt => Pt}}
    else
        _ -> error
    end;
parse(fmtp, V) ->
    case webrtc_sdp_lex:split_first(V, <<" ">>) of
        {FmtB, Raw} when is_binary(Raw), Raw =/= <<>> ->
            maybe
                {ok, Fmt} ?= fmt(FmtB),
                {ok, Params} ?= parse_fmtp_params(Raw),
                {ok, with_raw(#{fmt => Fmt, params => Params}, Raw, fun() -> encode_fmtp_params(Params) end)}
            else
                _ -> error
            end;
        _ ->
            error
    end;
parse(rtcp_fb, V) ->
    case binary:split(V, <<" ">>) of
        [PtB, Rest] ->
            maybe
                {ok, Pt} ?= fb_pt(PtB),
                {Type, Param} = webrtc_sdp_lex:split_first(Rest, <<" ">>),
                true ?= webrtc_sdp_lex:is_token(Type),
                true ?= Param =:= undefined orelse Param =/= <<>>,
                {ok, #{pt => Pt, type => Type, param => Param}}
            else
                _ -> error
            end;
        _ ->
            error
    end;
parse(extmap, V) ->
    maybe
        [Entry, Rest] ?= binary:split(V, <<" ">>),
        {Uri, Attrs} = webrtc_sdp_lex:split_first(Rest, <<" ">>),
        true ?= webrtc_sdp_lex:is_non_ws(Uri),
        true ?= Attrs =:= undefined orelse Attrs =/= <<>>,
        {IdB, DirB} = webrtc_sdp_lex:split_first(Entry, <<"/">>),
        {ok, Id} ?= webrtc_sdp_lex:parse_int(IdB, 1, 4351),
        true ?= Id =< 255 orelse Id >= 4096,
        {ok, Dir} ?= ext_direction(DirB),
        {ok, #{id => Id, direction => Dir, uri => Uri, attributes => Attrs}}
    else
        _ -> error
    end;
parse(msid, V) ->
    case webrtc_sdp_lex:split_sp(V) of
        {ok, [S]} -> msid(S, undefined);
        {ok, [S, T]} -> msid(S, T);
        _ -> error
    end;
parse(msid_semantic, V) ->
    case webrtc_sdp_lex:split_sp(webrtc_sdp_lex:trim_sp(V)) of
        {ok, [Sem | Ids]} ->
            case lists:all(fun webrtc_sdp_lex:is_token/1, [Sem | Ids]) of
                true ->
                    M = #{semantic => Sem, ids => Ids},
                    {ok, with_raw(M, V, fun() -> iolist_to_binary(encode(msid_semantic, M)) end)};
                false -> error
            end;
        error ->
            error
    end;
parse(ssrc, V) ->
    maybe
        [IdB, Attr] ?= binary:split(V, <<" ">>),
        {ok, Id} ?= webrtc_sdp_lex:parse_int(IdB, 0, ?MAX_SSRC),
        {Name, Value} = webrtc_sdp_lex:split_first(Attr, <<":">>),
        true ?= webrtc_sdp_lex:is_token(Name),
        {ok, #{ssrc => Id, attribute => Name, value => Value}}
    else
        _ -> error
    end;
parse(ssrc_group, V) ->
    maybe
        {ok, [Sem | Ids]} ?= webrtc_sdp_lex:split_sp(V),
        true ?= webrtc_sdp_lex:is_token(Sem),
        {ok, Ssrcs} ?= all_ok([webrtc_sdp_lex:parse_int(I, 0, ?MAX_SSRC) || I <- Ids]),
        {ok, #{semantics => Sem, ssrcs => Ssrcs}}
    else
        _ -> error
    end;
parse(Key, V) when Key =:= rid; Key =:= simulcast ->
    webrtc_sdp_rid:parse(Key, V).

%% Encoding name and clock rate, with optional channels.
encoding([Name, Clock | Chans]) when length(Chans) =< 1 ->
    maybe
        true ?= webrtc_sdp_lex:is_token(Name),
        {ok, Rate} ?= webrtc_sdp_lex:parse_int(Clock, 1, infinity),
        {ok, Ch} ?=
            case Chans of
                [] -> {ok, undefined};
                [C] -> webrtc_sdp_lex:parse_int(C, 1, infinity)
            end,
        {ok, #{name => Name, clock_rate => Rate, channels => Ch}}
    end;
encoding(_) ->
    error.

pt(B) -> webrtc_sdp_lex:parse_int(B, 0, 127).

fmt(B) ->
    case webrtc_sdp_lex:is_digits(B) of
        true -> pt(B);
        false when B =/= <<>> -> token_ok(B);
        false -> error
    end.

fb_pt(<<"*">>) -> {ok, '*'};
fb_pt(B) -> pt(B).

token_ok(B) ->
    case webrtc_sdp_lex:is_token(B) of
        true -> {ok, B};
        false -> error
    end.

ext_direction(undefined) -> {ok, undefined};
ext_direction(<<"sendrecv">>) -> {ok, sendrecv};
ext_direction(<<"sendonly">>) -> {ok, sendonly};
ext_direction(<<"recvonly">>) -> {ok, recvonly};
ext_direction(<<"inactive">>) -> {ok, inactive};
ext_direction(_) -> error.

%% Keep the received text only when it differs from the canonical form.
with_raw(M, Raw, Canon) ->
    try Canon() of
        Raw -> M;
        _ -> M#{raw => Raw}
    catch
        error:{invalid_sdp, _} -> M#{raw => Raw}
    end.

msid(S, T) ->
    case msid_id(S) andalso (T =:= undefined orelse msid_id(T)) of
        true -> {ok, #{stream => S, track => T}};
        false -> error
    end.

msid_id(B) -> byte_size(B) =< 64 andalso webrtc_sdp_lex:is_token(B).

%% @doc Parse the parameter text of an fmtp line. Parameters are separated
%% by `;' with optional surrounding spaces; empty parameters are skipped.
-spec parse_fmtp_params(binary()) -> {ok, [fmtp_param()]} | error.
parse_fmtp_params(Raw) ->
    Parts = [webrtc_sdp_lex:trim_sp(P) || P <- binary:split(Raw, <<";">>, [global])],
    all_ok([fmtp_param(P) || P <- Parts, P =/= <<>>]).

fmtp_param(P) ->
    case webrtc_sdp_lex:is_text(P) of
        false ->
            error;
        true ->
            case binary:split(P, <<"=">>) of
                [K, Val] ->
                    case webrtc_sdp_lex:trim_sp(K) of
                        <<>> -> error;
                        Key -> {ok, {Key, webrtc_sdp_lex:trim_sp(Val)}}
                    end;
                [Bare] ->
                    {ok, Bare}
            end
    end.

-spec encode_fmtp_params([fmtp_param()]) -> binary().
encode_fmtp_params(Params) ->
    iolist_to_binary(lists:join($;, [enc_param(P) || P <- Params])).

%% A parameter must parse back to itself, which rules out separators and
%% surrounding spaces inside keys and values.
enc_param(P) ->
    Text =
        case P of
            {K, V} when is_binary(K), is_binary(V) -> <<K/binary, "=", V/binary>>;
            B when is_binary(B) -> B;
            _ -> bad(fmtp_param, P)
        end,
    case parse_fmtp_params(Text) of
        {ok, [P]} -> Text;
        _ -> bad(fmtp_param, P)
    end.

all_ok(L) -> all_ok(L, []).
all_ok([{ok, V} | R], Acc) -> all_ok(R, [V | Acc]);
all_ok([], Acc) -> {ok, lists:reverse(Acc)};
all_ok(_, _) -> error.

%%====================================================================
%% Encoding
%%====================================================================

-spec encode(atom(), term()) -> iodata().
encode(rtpmap, #{pt := Pt, name := Name, clock_rate := Rate} = M) ->
    _ = token(Name),
    Ch =
        case maps:get(channels, M, undefined) of
            undefined -> [];
            C when is_integer(C), C > 0 -> [$/, integer_to_binary(C)]
        end,
    [enc_pt(Pt), $\s, Name, $/, pos(Rate) | Ch];
encode(fmtp, #{fmt := Fmt, params := Params} = M) ->
    Text =
        case M of
            #{raw := Raw} when is_binary(Raw) ->
                case parse_fmtp_params(Raw) of
                    {ok, Params} -> Raw;
                    _ -> encode_fmtp_params(Params)
                end;
            _ ->
                encode_fmtp_params(Params)
        end,
    Text =/= <<>> orelse bad(fmtp, M),
    _ = text(Text),
    [enc_fmt(Fmt), $\s, Text];
encode(rtcp_fb, #{pt := Pt, type := Type} = M) ->
    _ = token(Type),
    P =
        case maps:get(param, M, undefined) of
            undefined -> [];
            Param -> [$\s, nonempty_text(Param)]
        end,
    [
        case Pt of
            '*' -> $*;
            _ -> enc_pt(Pt)
        end,
        $\s,
        Type
        | P
    ];
encode(extmap, #{id := Id, uri := Uri} = M) ->
    (is_integer(Id) andalso (Id >= 1 andalso Id =< 255 orelse Id >= 4096 andalso Id =< 4351)) orelse
        bad(extmap, M),
    _ = non_ws(Uri),
    Dir =
        case maps:get(direction, M, undefined) of
            undefined -> [];
            D -> [$/, enc_dir(D)]
        end,
    Attrs =
        case maps:get(attributes, M, undefined) of
            undefined -> [];
            A -> [$\s, nonempty_text(A)]
        end,
    [integer_to_binary(Id), Dir, $\s, Uri | Attrs];
encode(msid, #{stream := S} = M) ->
    msid_id(S) orelse bad(msid, M),
    case maps:get(track, M, undefined) of
        undefined ->
            S;
        T ->
            msid_id(T) orelse bad(msid, M),
            [S, $\s, T]
    end;
encode(msid_semantic, #{semantic := Sem, ids := Ids} = M) ->
    Canon = lists:join($\s, [token(I) || I <- [Sem | Ids]]),
    case M of
        #{raw := Raw} when is_binary(Raw) ->
            case parse(msid_semantic, Raw) of
                {ok, #{semantic := Sem, ids := Ids}} -> Raw;
                _ -> Canon
            end;
        _ ->
            Canon
    end;
encode(ssrc, #{ssrc := Id, attribute := Name} = M) ->
    _ = token(Name),
    V =
        case maps:get(value, M, undefined) of
            undefined -> [];
            Val -> [$:, text(Val)]
        end,
    [ssrc_id(Id), $\s, Name | V];
encode(ssrc_group, #{semantics := Sem, ssrcs := Ssrcs}) ->
    lists:join($\s, [token(Sem) | [ssrc_id(S) || S <- Ssrcs]]);
encode(Key, V) when Key =:= rid; Key =:= simulcast ->
    webrtc_sdp_rid:encode(Key, V);
encode(Key, V) ->
    bad(Key, V).

enc_dir(D) when D =:= sendrecv; D =:= sendonly; D =:= recvonly; D =:= inactive -> atom_to_binary(D).

enc_pt(Pt) when is_integer(Pt), Pt >= 0, Pt =< 127 -> integer_to_binary(Pt);
enc_pt(Pt) -> bad(payload_type, Pt).

enc_fmt(F) when is_binary(F) -> token(F);
enc_fmt(F) -> enc_pt(F).

ssrc_id(S) when is_integer(S), S >= 0, S =< ?MAX_SSRC -> integer_to_binary(S);
ssrc_id(S) -> bad(ssrc, S).

pos(N) when is_integer(N), N > 0 -> integer_to_binary(N);
pos(N) -> bad(integer, N).

token(B) ->
    is_binary(B) andalso webrtc_sdp_lex:is_token(B) orelse bad(token, B),
    B.

non_ws(B) ->
    is_binary(B) andalso webrtc_sdp_lex:is_non_ws(B) orelse bad(text, B),
    B.

text(B) ->
    webrtc_sdp_lex:check_text(text, B),
    B.

nonempty_text(<<>>) -> bad(text, <<>>);
nonempty_text(B) -> text(B).

-spec bad(term(), term()) -> no_return().
bad(What, V) -> erlang:error({invalid_sdp, {What, V}}).
