%% @doc RTP stream identifier (`a=rid', RFC 8851) and simulcast
%% (`a=simulcast', RFC 8853) attribute values, used through
%% `webrtc_sdp_rtp'.
-module(webrtc_sdp_rid).

-export([parse/2, encode/2]).

-export_type([rid/0, simulcast/0]).

%% `pts' is the `pt=' list (empty when absent); `params' are the
%% restrictions in order, such as `{<<"max-width">>, <<"1280">>}'.
-type rid() :: #{
    id := binary(),
    direction := send | recv,
    pts := [0..127],
    params := [{binary(), binary() | undefined}]
}.
%% Each direction lists simulcast streams; each stream lists alternative
%% rids as `{RidId, Paused}' (`~' prefix, RFC 8853 §5.1).
-type simulcast() :: [{send | recv, [[{binary(), boolean()}, ...], ...]}, ...].

-spec parse(rid | simulcast, binary()) -> {ok, rid() | simulcast()} | error.
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

pt(B) -> webrtc_sdp_lex:parse_int(B, 0, 127).

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

-spec encode(rid | simulcast, term()) -> iodata().
encode(rid, #{id := Id, direction := Dir} = M) ->
    _ = rid_id(Id),
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

enc_pt(Pt) when is_integer(Pt), Pt >= 0, Pt =< 127 -> integer_to_binary(Pt);
enc_pt(Pt) -> bad(payload_type, Pt).

rid_id(Id) ->
    is_binary(Id) andalso webrtc_sdp_lex:is_rid_id(Id) orelse bad(rid_id, Id),
    Id.

-spec bad(term(), term()) -> no_return().
bad(What, V) -> erlang:error({invalid_sdp, {What, V}}).
