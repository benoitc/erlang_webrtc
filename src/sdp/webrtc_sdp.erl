%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc SDP codec (RFC 8866) with the attributes used by WebRTC.
%%
%% `parse/1' turns a session description into an `#sdp{}' record (see
%% `webrtc_sdp.hrl'); `encode/1' turns the record back into text. JSEP
%% code works on these records only, never on the text.
%%
%% ```
%% {ok, Sdp} = webrtc_sdp:parse(Offer),
%% [Audio | _] = Sdp#sdp.media,
%% Codecs = webrtc_sdp_media:codecs(Audio),
%% Answer = webrtc_sdp:encode(Sdp#sdp{media = [...]}).
%% '''
%%
%% Parsing:
%% <ul>
%% <li>Lines may end with CRLF or LF (RFC 8866 §5 allows a lenient
%% parser); the last line may lack its terminator.</li>
%% <li>Field order and cardinality follow the RFC 8866 §9 grammar. A `z='
%% line attaches to the preceding `t=' (accepting both RFC 4566 and RFC
%% 8866 placement).</li>
%% <li>Errors are `{error, {Line, Reason}}' with a 1-based line number.</li>
%% <li>Attributes listed in `webrtc_sdp_attr' are parsed into typed
%% terms, the rest are kept as `{Name, Value}' binaries in order. A
%% malformed known attribute is an error.</li>
%% </ul>
%%
%% Encoding always writes CRLF and the RFC 8866 field order. Values that
%% cannot be written (for example text containing CR or LF) raise
%% `error({invalid_sdp, Detail})'. `encode(parse(X))' reproduces `X' byte
%% for byte when `X' uses CRLF and the canonical spelling of typed
%% attributes (single spaces, upper-case fingerprint hex, lowercase hash
%% names, no leading zeros), which is what browsers emit. `fmtp' and
%% `msid-semantic' keep their raw text so they round trip as received.
-module(webrtc_sdp).

-include("webrtc_sdp.hrl").

-export([parse/1, encode/1]).

-export_type([sdp/0, media/0, attribute/0, error_reason/0]).

-type sdp() :: #sdp{}.
-type media() :: #sdp_media{}.
-type error_reason() :: atom() | {atom(), term()}.

-type attribute() :: webrtc_sdp_attr:attribute().

-type line() :: {pos_integer(), char(), binary()}.

%%====================================================================
%% Parsing
%%====================================================================

%% @doc Parse a session description.
-spec parse(binary()) -> {ok, sdp()} | {error, {pos_integer(), error_reason()}}.
parse(Bin) when is_binary(Bin) ->
    try
        Lines = lines(Bin),
        {ok, session(Lines, length(Lines) + 1)}
    catch
        throw:{sdp_error, Line, Reason} -> {error, {Line, Reason}}
    end.

lines(Bin) ->
    Raw = binary:split(Bin, <<"\n">>, [global]),
    Trimmed =
        case lists:last(Raw) of
            <<>> -> lists:droplast(Raw);
            _ -> Raw
        end,
    number(Trimmed, 1).

number([L | Rest], N) ->
    [line(N, strip_cr(L)) | number(Rest, N + 1)];
number([], _) ->
    [].

strip_cr(L) ->
    case byte_size(L) of
        0 -> L;
        S when binary_part(L, S - 1, 1) =:= <<"\r">> -> binary_part(L, 0, S - 1);
        _ -> L
    end.

-spec line(pos_integer(), binary()) -> line().
line(N, <<>>) ->
    fail(N, empty_line);
line(N, <<T, $=, V/binary>>) when T >= $a, T =< $z ->
    case lists:member(T, "vosiuepcbtrzkam") of
        false -> fail(N, {unknown_field, <<T>>});
        true ->
            case webrtc_sdp_lex:is_text(V) of
                true -> {N, T, V};
                false -> fail(N, bad_character)
            end
    end;
line(N, _) ->
    fail(N, bad_line).

-spec fail(pos_integer(), error_reason()) -> no_return().
fail(N, Reason) -> throw({sdp_error, N, Reason}).

session([{N, $v, V} | R0], End) ->
    V =:= <<"0">> orelse fail(N, bad_version),
    {Origin, R1} = required($o, R0, End, missing_origin, fun origin/2),
    {Name, R2} = required($s, R1, End, missing_session_name, fun(_, T) -> T end),
    {Info, R3} = optional($i, R2, fun(_, T) -> T end),
    {Uri, R4} = optional($u, R3, fun uri/2),
    {Emails, R5} = many($e, R4, fun nonempty/2),
    {Phones, R6} = many($p, R5, fun nonempty/2),
    {Conn, R7} = optional($c, R6, fun connection/2),
    {Bws, R8} = many($b, R7, fun bandwidth/2),
    {Times, R9} = times(R8, End),
    {Key, R10} = optional($k, R9, fun key/2),
    {Attrs, R11} = many($a, R10, fun attribute/2),
    Media = media(R11),
    #sdp{
        version = 0,
        origin = Origin,
        session_name = Name,
        information = Info,
        uri = Uri,
        emails = Emails,
        phones = Phones,
        connection = Conn,
        bandwidths = Bws,
        times = Times,
        key = Key,
        attributes = Attrs,
        media = Media
    };
session([{N, _, _} | _], _) ->
    fail(N, missing_version);
session([], _) ->
    fail(1, missing_version).

required(T, [{N, T, V} | Rest], _End, _Missing, F) -> {F(N, V), Rest};
required(_, [{N, _, _} | _], _End, Missing, _) -> fail(N, Missing);
required(_, [], End, Missing, _) -> fail(End, Missing).

optional(T, [{N, T, V} | Rest], F) -> {F(N, V), Rest};
optional(_, Rest, _) -> {undefined, Rest}.

many(T, Lines, F) -> many(T, Lines, F, []).

many(T, [{N, T, V} | Rest], F, Acc) -> many(T, Rest, F, [F(N, V) | Acc]);
many(_, Rest, _, Acc) -> {lists:reverse(Acc), Rest}.

nonempty(N, <<>>) -> fail(N, empty_value);
nonempty(_, V) -> V.

origin(N, V) ->
    case webrtc_sdp_lex:split_sp(V) of
        {ok, [User, Id, Ver, Net, Type, Addr]} ->
            ok(N, bad_origin, webrtc_sdp_lex:is_non_ws(User)),
            ok(N, bad_origin, webrtc_sdp_lex:is_token(Net) andalso webrtc_sdp_lex:is_token(Type)),
            ok(N, bad_origin, webrtc_sdp_lex:is_non_ws(Addr)),
            #sdp_origin{
                username = User,
                sess_id = int(N, bad_origin, Id),
                sess_version = int(N, bad_origin, Ver),
                nettype = Net,
                addrtype = Type,
                address = Addr
            };
        _ ->
            fail(N, bad_origin)
    end.

uri(N, V) ->
    ok(N, bad_uri, webrtc_sdp_lex:is_non_ws(V)),
    V.

connection(N, V) ->
    case webrtc_sdp_lex:split_sp(V) of
        {ok, [Net, Type, Addr]} ->
            ok(N, bad_connection, webrtc_sdp_lex:is_token(Net) andalso webrtc_sdp_lex:is_token(Type)),
            ok(N, bad_connection, webrtc_sdp_lex:is_non_ws(Addr)),
            #sdp_connection{nettype = Net, addrtype = Type, address = Addr};
        _ ->
            fail(N, bad_connection)
    end.

bandwidth(N, V) ->
    case binary:split(V, <<":">>) of
        [Type, Bw] ->
            ok(N, bad_bandwidth, webrtc_sdp_lex:is_token(Type)),
            {Type, int(N, bad_bandwidth, Bw)};
        _ ->
            fail(N, bad_bandwidth)
    end.

%% 1*( t= *r= [z=] )
times([{N, $t, V} | Rest], End) ->
    {Repeats, R1} = many($r, Rest, fun repeat/2),
    {Zones, R2} = optional($z, R1, fun zone/2),
    T0 = time(N, V),
    T = T0#sdp_time{
        repeats = Repeats,
        zones =
            case Zones of
                undefined -> [];
                Z -> Z
            end
    },
    case R2 of
        [{_, $t, _} | _] ->
            {More, R3} = times(R2, End),
            {[T | More], R3};
        _ ->
            {[T], R2}
    end;
times([{N, _, _} | _], _) ->
    fail(N, missing_time);
times([], End) ->
    fail(End, missing_time).

time(N, V) ->
    case webrtc_sdp_lex:split_sp(V) of
        {ok, [S, E]} ->
            ok(N, bad_time, is_time(S) andalso is_time(E)),
            #sdp_time{start = binary_to_integer(S), stop = binary_to_integer(E)};
        _ ->
            fail(N, bad_time)
    end.

%% time = POS-DIGIT 9*DIGIT, or "0"
is_time(<<"0">>) -> true;
is_time(<<C, _/binary>> = B) when C =/= $0 -> byte_size(B) >= 10 andalso webrtc_sdp_lex:parse_int(B) =/= error;
is_time(_) -> false.

repeat(N, V) ->
    case webrtc_sdp_lex:split_sp(V) of
        {ok, [Interval, _, _ | _] = Fields} ->
            ok(N, bad_repeat, typed_time(Interval, false) andalso binary_part(Interval, 0, 1) =/= <<"0">>),
            ok(N, bad_repeat, lists:all(fun(F) -> typed_time(F, false) end, tl(Fields))),
            Fields;
        _ ->
            fail(N, bad_repeat)
    end.

zone(N, V) ->
    case webrtc_sdp_lex:split_sp(V) of
        {ok, Fields} when length(Fields) rem 2 =:= 0 -> zone_pairs(N, Fields);
        _ -> fail(N, bad_zone)
    end.

zone_pairs(N, [T, Off | Rest]) ->
    ok(N, bad_zone, is_time(T) andalso typed_time(Off, true)),
    [{binary_to_integer(T), Off} | zone_pairs(N, Rest)];
zone_pairs(_, []) ->
    [].

%% typed-time = 1*DIGIT [fixed-len-time-unit], with an optional "-" in z=
typed_time(<<"-", T/binary>>, true) ->
    typed_time(T, false);
typed_time(T, _) when byte_size(T) > 0 ->
    {Digits, Unit} =
        case binary:last(T) of
            U when U =:= $d; U =:= $h; U =:= $m; U =:= $s -> {binary_part(T, 0, byte_size(T) - 1), U};
            _ -> {T, none}
        end,
    _ = Unit,
    webrtc_sdp_lex:parse_int(Digits) =/= error;
typed_time(_, _) ->
    false.

%% key-type (RFC 8866 §5.12, obsolete but still part of the grammar)
key(_, <<"prompt">> = K) -> K;
key(_, <<"clear:", _/binary>> = K) -> K;
key(N, <<"base64:", B/binary>> = K) ->
    ok(N, bad_key, is_base64(B)),
    K;
key(N, <<"uri:", U/binary>> = K) ->
    ok(N, bad_key, webrtc_sdp_lex:is_non_ws(U)),
    K;
key(N, _) ->
    fail(N, bad_key).

is_base64(B) ->
    byte_size(B) rem 4 =:= 0 andalso
        try base64:decode(B) of
            _ -> true
        catch
            error:_ -> false
        end.

attribute(N, V) ->
    {Name, Value} = webrtc_sdp_lex:split_first(V, <<":">>),
    case webrtc_sdp_attr:parse(Name, Value) of
        {ok, A} -> A;
        error -> fail(N, {bad_attribute, Name})
    end.

media([{N, $m, V} | R0]) ->
    M0 = media_line(N, V),
    {Info, R1} = optional($i, R0, fun(_, T) -> T end),
    {Conns, R2} = many($c, R1, fun connection/2),
    {Bws, R3} = many($b, R2, fun bandwidth/2),
    {Key, R4} = optional($k, R3, fun key/2),
    {Attrs, R5} = many($a, R4, fun attribute/2),
    M = M0#sdp_media{
        information = Info,
        connections = Conns,
        bandwidths = Bws,
        key = Key,
        attributes = Attrs
    },
    [M | media(R5)];
media([{N, T, _} | _]) ->
    fail(N, {unexpected_field, <<T>>});
media([]) ->
    [].

%% m=<media> <port>[/<number of ports>] <proto> <fmt> ...
media_line(N, V) ->
    case webrtc_sdp_lex:split_sp(V) of
        {ok, [Media, PortB, Proto | [_ | _] = Fmts]} ->
            ok(N, bad_media, webrtc_sdp_lex:is_token(Media)),
            ok(N, bad_proto, is_proto(Proto)),
            ok(N, bad_fmt, lists:all(fun webrtc_sdp_lex:is_token/1, Fmts)),
            {Port, Count} =
                case binary:split(PortB, <<"/">>) of
                    [P] -> {port(N, P), undefined};
                    [P, C] -> {port(N, P), count(N, C)}
                end,
            #sdp_media{media = Media, port = Port, port_count = Count, proto = Proto, fmts = Fmts};
        _ ->
            fail(N, bad_media)
    end.

port(N, P) ->
    case webrtc_sdp_lex:parse_int(P, 0, 65535) of
        {ok, Port} -> Port;
        error -> fail(N, bad_port)
    end.

count(N, C) ->
    case webrtc_sdp_lex:parse_int(C, 1, 65535) of
        {ok, Count} -> Count;
        error -> fail(N, bad_port)
    end.

%% proto = token *("/" token)
is_proto(P) ->
    lists:all(fun webrtc_sdp_lex:is_token/1, binary:split(P, <<"/">>, [global])).

int(N, Reason, B) ->
    case webrtc_sdp_lex:parse_int(B) of
        {ok, I} -> I;
        error -> fail(N, Reason)
    end.

ok(_, _, true) -> ok;
ok(N, Reason, false) -> fail(N, Reason).

%%====================================================================
%% Encoding
%%====================================================================

%% @doc Encode a session description with CRLF line endings.
-spec encode(sdp()) -> binary().
encode(#sdp{} = S) ->
    #sdp{origin = O, times = [_ | _] = Times} = S,
    S#sdp.version =:= 0 orelse bad(version, S#sdp.version),
    iolist_to_binary([
        <<"v=0\r\n">>,
        out($o, origin(O)),
        out($s, text(session_name, S#sdp.session_name)),
        opt($i, S#sdp.information),
        case S#sdp.uri of
            undefined -> [];
            U -> out($u, non_ws(uri, U))
        end,
        [out($e, nonempty_text(email, E)) || E <- S#sdp.emails],
        [out($p, nonempty_text(phone, P)) || P <- S#sdp.phones],
        case S#sdp.connection of
            undefined -> [];
            C -> out($c, conn(C))
        end,
        [out($b, bw(B)) || B <- S#sdp.bandwidths],
        [enc_time(T) || T <- Times],
        enc_key(S#sdp.key),
        [out($a, webrtc_sdp_attr:encode(A)) || A <- S#sdp.attributes],
        [enc_media(M) || M <- S#sdp.media]
    ]).

out(T, V) -> [T, $=, V, <<"\r\n">>].

opt(_, undefined) -> [];
opt(T, V) -> out(T, text(T, V)).

origin(#sdp_origin{} = O) ->
    #sdp_origin{
        username = U, sess_id = Id, sess_version = Ver, nettype = N, addrtype = T, address = A
    } = O,
    lists:join($\s, [
        non_ws(username, U),
        webrtc_sdp_lex:int(Id),
        webrtc_sdp_lex:int(Ver),
        token(nettype, N),
        token(addrtype, T),
        non_ws(address, A)
    ]).

conn(#sdp_connection{nettype = N, addrtype = T, address = A}) ->
    [token(nettype, N), $\s, token(addrtype, T), $\s, non_ws(address, A)].

bw({Type, V}) -> [token(bwtype, Type), $:, webrtc_sdp_lex:int(V)].

enc_time(#sdp_time{start = S, stop = E, repeats = Rs, zones = Zs}) ->
    [
        out($t, [webrtc_sdp_lex:int(S), $\s, webrtc_sdp_lex:int(E)]),
        [out($r, enc_repeat(R)) || R <- Rs],
        case Zs of
            [] -> [];
            _ -> out($z, lists:join($\s, [enc_zone(Z) || Z <- Zs]))
        end
    ].

enc_repeat(R) ->
    Text = lists:join($\s, R),
    try repeat(0, iolist_to_binary(Text)) of
        _ -> Text
    catch
        throw:{sdp_error, _, _} -> bad(repeat, R);
        error:_ -> bad(repeat, R)
    end.

enc_zone({T, Off} = Z) ->
    Text = [webrtc_sdp_lex:int(T), $\s, non_ws(zone, Off)],
    try zone(0, iolist_to_binary(Text)) of
        _ -> Text
    catch
        throw:{sdp_error, _, _} -> bad(zone, Z)
    end.

enc_key(undefined) ->
    [];
enc_key(K) ->
    try key(0, text(key, K)) of
        _ -> out($k, K)
    catch
        throw:{sdp_error, _, _} -> bad(key, K)
    end.

enc_media(#sdp_media{} = M) ->
    #sdp_media{media = Media, port = Port, port_count = Count, proto = Proto, fmts = Fmts} = M,
    is_integer(Port) andalso Port >= 0 andalso Port =< 65535 orelse bad(port, Port),
    Fmts =/= [] orelse bad(fmts, Fmts),
    PortText =
        case Count of
            undefined -> integer_to_binary(Port);
            _ when is_integer(Count), Count >= 1 -> [integer_to_binary(Port), $/, integer_to_binary(Count)]
        end,
    is_binary(Proto) andalso is_proto(Proto) orelse bad(proto, Proto),
    [
        out($m, lists:join($\s, [token(media, Media), PortText, Proto | [token(fmt, F) || F <- Fmts]])),
        opt($i, M#sdp_media.information),
        [out($c, conn(C)) || C <- M#sdp_media.connections],
        [out($b, bw(B)) || B <- M#sdp_media.bandwidths],
        enc_key(M#sdp_media.key),
        [out($a, webrtc_sdp_attr:encode(A)) || A <- M#sdp_media.attributes]
    ].

text(What, V) ->
    webrtc_sdp_lex:check_text(What, V),
    V.

nonempty_text(What, <<>>) -> bad(What, <<>>);
nonempty_text(What, V) -> text(What, V).

token(What, V) ->
    is_binary(V) andalso webrtc_sdp_lex:is_token(V) orelse bad(What, V),
    V.

non_ws(What, V) ->
    is_binary(V) andalso webrtc_sdp_lex:is_non_ws(V) orelse bad(What, V),
    V.

-spec bad(atom(), term()) -> no_return().
bad(What, V) -> erlang:error({invalid_sdp, {What, V}}).
