%% @doc RTP related SDP attribute values: rtpmap and fmtp (RFC 8866 §6),
%% rtcp-fb (RFC 4585 §4.2), extmap (RFC 8285 §8), msid (RFC 8830),
%% legacy msid-semantic, ssrc and ssrc-group (RFC 5576), rid (RFC 8851)
%% and simulcast (RFC 8853).
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
    rid/0,
    simulcast/0,
    direction/0
]).

-type direction() :: sendrecv | sendonly | recvonly | inactive.
-type pt() :: 0..127.
-type rtpmap() :: #{
    pt := pt(), name := binary(), clock_rate := pos_integer(), channels := pos_integer() | undefined
}.
%% A parameter is `Key=Value' or a bare value such as `0-15'.
-type fmtp_param() :: {binary(), binary()} | binary().
%% `raw' is the parameter text as received. It is written back when it
%% still parses to `params', so unmodified input round trips byte exact.
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
-type rid() :: #{
    id := binary(),
    direction := send | recv,
    pts := [pt()],
    params := [{binary(), binary() | undefined}]
}.
%% Each direction lists simulcast streams; each stream lists alternative
%% rids as `{RidId, Paused}'.
-type simulcast() :: [{send | recv, [[{binary(), boolean()}, ...], ...]}, ...].

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
                {ok, #{fmt => Fmt, params => Params, raw => Raw}}
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
                true -> {ok, #{semantic => Sem, ids => Ids, raw => V}};
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
parse(rid, V) ->
    maybe
        {IdDir, Rest} = split_n(V, 2),
        {ok, [Id, DirB]} ?= webrtc_sdp_lex:split_sp(IdDir),
        true ?= webrtc_sdp_lex:is_rid_id(Id),
        {ok, Dir} ?= rid_dir(DirB),
        {ok, Pts, Params} ?= rid_params(Rest),
        {ok, #{id => Id, direction => Dir, pts => Pts, params => Params}}
    else
        _ -> error
    end;
parse(simulcast, V) ->
    case webrtc_sdp_lex:split_sp(V) of
        {ok, [D1, L1]} ->
            sc([{D1, L1}]);
        {ok, [D1, L1, D2, L2]} when D1 =/= D2 ->
            sc([{D1, L1}, {D2, L2}]);
        _ ->
            error
    end.

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

rid_dir(<<"send">>) -> {ok, send};
rid_dir(<<"recv">>) -> {ok, recv};
rid_dir(_) -> error.

%% Split after the Nth space; the remainder may contain spaces.
split_n(V, 2) ->
    case binary:split(V, <<" ">>) of
        [A, R] ->
            case binary:split(R, <<" ">>) of
                [B, Rest] -> {<<A/binary, " ", B/binary>>, Rest};
                [B] -> {<<A/binary, " ", B/binary>>, undefined}
            end;
        [A] ->
            {A, undefined}
    end.

rid_params(undefined) ->
    {ok, [], []};
rid_params(Rest) ->
    Parts = binary:split(Rest, <<";">>, [global]),
    case Parts of
        [<<"pt=", Fmts/binary>> | Others] ->
            maybe
                {ok, Pts} ?= all_ok([pt(F) || F <- binary:split(Fmts, <<",">>, [global])]),
                {ok, Params} ?= all_ok([rid_param(P) || P <- Others]),
                {ok, Pts, Params}
            end;
        _ ->
            case all_ok([rid_param(P) || P <- Parts]) of
                {ok, Params} -> {ok, [], Params};
                error -> error
            end
    end.

%% rid-param-other = 1*(alpha-numeric / "-") ["=" param-val]
rid_param(P) ->
    {Name, Val} = webrtc_sdp_lex:split_first(P, <<"=">>),
    NameOk = webrtc_sdp_lex:is_rid_id(Name) andalso binary:match(Name, <<"_">>) =:= nomatch,
    ValOk =
        case {Name, Val} of
            {_, undefined} -> Name =/= <<"depend">>;
            {<<"depend">>, _} -> lists:all(fun webrtc_sdp_lex:is_rid_id/1, binary:split(Val, <<",">>, [global]));
            _ -> param_val(Val)
        end,
    case NameOk andalso ValOk of
        true -> {ok, {Name, Val}};
        false -> error
    end.

%% param-val = *(%x20-3A / %x3C-7E)
param_val(<<C, R/binary>>) when C >= 16#20, C =< 16#7E, C =/= $; -> param_val(R);
param_val(<<>>) -> true;
param_val(_) -> false.

sc(Descs) ->
    maybe
        {ok, Parsed} ?= all_ok([sc_desc(D, L) || {D, L} <- Descs]),
        {ok, Parsed}
    end.

sc_desc(DirB, List) ->
    maybe
        {ok, Dir} ?= rid_dir(DirB),
        {ok, Streams} ?= all_ok([sc_stream(S) || S <- binary:split(List, <<";">>, [global])]),
        {ok, {Dir, Streams}}
    end.

sc_stream(S) ->
    all_ok([sc_id(Id) || Id <- binary:split(S, <<",">>, [global])]).

sc_id(<<"~", Id/binary>>) -> sc_rid(Id, true);
sc_id(Id) -> sc_rid(Id, false).

sc_rid(Id, Paused) ->
    case webrtc_sdp_lex:is_rid_id(Id) of
        true -> {ok, {Id, Paused}};
        false -> error
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
    token(Name),
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
    text(Text),
    [enc_fmt(Fmt), $\s, Text];
encode(rtcp_fb, #{pt := Pt, type := Type} = M) ->
    token(Type),
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
    non_ws(Uri),
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
    token(Name),
    V =
        case maps:get(value, M, undefined) of
            undefined -> [];
            Val -> [$:, text(Val)]
        end,
    [ssrc_id(Id), $\s, Name | V];
encode(ssrc_group, #{semantics := Sem, ssrcs := Ssrcs}) ->
    lists:join($\s, [token(Sem) | [ssrc_id(S) || S <- Ssrcs]]);
encode(rid, #{id := Id, direction := Dir} = M) ->
    rid_id(Id),
    Pts =
        case maps:get(pts, M, []) of
            [] -> [];
            L -> [["pt=", lists:join($,, [enc_pt(P) || P <- L])]]
        end,
    Params = [enc_rid_param(P) || P <- maps:get(params, M, [])],
    case Pts ++ Params of
        [] -> [Id, $\s, enc_rid_dir(Dir)];
        Restr -> [Id, $\s, enc_rid_dir(Dir), $\s, lists:join($;, Restr)]
    end;
encode(simulcast, [{D1, _}] = Descs) when D1 =:= send; D1 =:= recv ->
    lists:join($\s, [enc_sc(D, S) || {D, S} <- Descs]);
encode(simulcast, [{D1, _}, {D2, _}] = Descs) when D1 =/= D2 ->
    lists:join($\s, [enc_sc(D, S) || {D, S} <- Descs]);
encode(Key, V) ->
    bad(Key, V).

enc_sc(Dir, [_ | _] = Streams) ->
    [enc_rid_dir(Dir), $\s, lists:join($;, [enc_sc_stream(S) || S <- Streams])];
enc_sc(Dir, Streams) ->
    bad(simulcast, {Dir, Streams}).

enc_sc_stream([_ | _] = Alts) -> lists:join($,, [enc_sc_id(A) || A <- Alts]);
enc_sc_stream(S) -> bad(simulcast, S).

enc_sc_id({Id, true}) -> [$~, rid_id(Id)];
enc_sc_id({Id, false}) -> rid_id(Id).

enc_rid_param({Name, undefined} = P) ->
    case rid_param(Name) of
        {ok, _} -> Name;
        error -> bad(rid, P)
    end;
enc_rid_param({Name, Val} = P) when is_binary(Name), is_binary(Val) ->
    Text = <<Name/binary, "=", Val/binary>>,
    case rid_param(Text) of
        {ok, _} -> Text;
        error -> bad(rid, P)
    end.

enc_rid_dir(send) -> <<"send">>;
enc_rid_dir(recv) -> <<"recv">>.

enc_dir(D) when D =:= sendrecv; D =:= sendonly; D =:= recvonly; D =:= inactive -> atom_to_binary(D).

enc_pt(Pt) when is_integer(Pt), Pt >= 0, Pt =< 127 -> integer_to_binary(Pt);
enc_pt(Pt) -> bad(payload_type, Pt).

enc_fmt(F) when is_binary(F) -> token(F);
enc_fmt(F) -> enc_pt(F).

ssrc_id(S) when is_integer(S), S >= 0, S =< ?MAX_SSRC -> integer_to_binary(S);
ssrc_id(S) -> bad(ssrc, S).

pos(N) when is_integer(N), N > 0 -> integer_to_binary(N);
pos(N) -> bad(integer, N).

rid_id(Id) ->
    is_binary(Id) andalso webrtc_sdp_lex:is_rid_id(Id) orelse bad(rid_id, Id),
    Id.

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
