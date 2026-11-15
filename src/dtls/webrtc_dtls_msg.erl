%% @doc DTLS 1.2 handshake message codec (RFC 6347 §4.2.2, RFC 5246 §7.4)
%% with the extensions WebRTC needs: supported_groups and
%% ec_point_formats (RFC 8422), signature_algorithms, use_srtp
%% (RFC 5764 §4.1.1), extended_master_secret (RFC 7627) and
%% renegotiation_info (RFC 5746).
%%
%% Messages are maps. `decode_body/2' never raises; malformed input
%% gives `{error, decode_error}' which maps to the decode_error alert.
-module(webrtc_dtls_msg).

-export([
    decode_fragment/1,
    encode_body/2,
    decode_body/2,
    full/3,
    fragments/4,
    type_code/1,
    type_name/1,
    encode_extensions/1,
    decode_extensions/1
]).

-export_type([msg_type/0, fragment/0]).

-type msg_type() ::
    hello_request
    | client_hello
    | server_hello
    | hello_verify_request
    | certificate
    | server_key_exchange
    | certificate_request
    | server_hello_done
    | certificate_verify
    | client_key_exchange
    | finished
    | new_session_ticket
    | encrypted_extensions
    | key_update
    | request_connection_id
    | new_connection_id
    | message_hash
    | 0..255.
-type fragment() :: #{
    type := msg_type(),
    length := non_neg_integer(),
    seq := 0..16#FFFF,
    offset := non_neg_integer(),
    data := binary()
}.

-define(EXT_SUPPORTED_GROUPS, 10).
-define(EXT_EC_POINT_FORMATS, 11).
-define(EXT_SIGNATURE_ALGORITHMS, 13).
-define(EXT_USE_SRTP, 14).
-define(EXT_EXTENDED_MASTER_SECRET, 23).
-define(EXT_RENEGOTIATION_INFO, 16#FF01).

-spec type_code(msg_type()) -> 0..255.
type_code(hello_request) -> 0;
type_code(client_hello) -> 1;
type_code(server_hello) -> 2;
type_code(hello_verify_request) -> 3;
type_code(certificate) -> 11;
type_code(server_key_exchange) -> 12;
type_code(certificate_request) -> 13;
type_code(server_hello_done) -> 14;
type_code(certificate_verify) -> 15;
type_code(client_key_exchange) -> 16;
type_code(finished) -> 20;
type_code(new_session_ticket) -> 4;
type_code(encrypted_extensions) -> 8;
type_code(key_update) -> 24;
type_code(request_connection_id) -> 9;
type_code(new_connection_id) -> 10;
type_code(message_hash) -> 254;
type_code(N) when is_integer(N) -> N.

-spec type_name(0..255) -> msg_type().
type_name(0) -> hello_request;
type_name(1) -> client_hello;
type_name(2) -> server_hello;
type_name(3) -> hello_verify_request;
type_name(11) -> certificate;
type_name(12) -> server_key_exchange;
type_name(13) -> certificate_request;
type_name(14) -> server_hello_done;
type_name(15) -> certificate_verify;
type_name(16) -> client_key_exchange;
type_name(20) -> finished;
type_name(4) -> new_session_ticket;
type_name(8) -> encrypted_extensions;
type_name(24) -> key_update;
type_name(9) -> request_connection_id;
type_name(10) -> new_connection_id;
type_name(N) -> N.

%%====================================================================
%% Handshake fragments
%%====================================================================

%% @doc Split the payload of a handshake record into fragments.
-spec decode_fragment(binary()) -> {ok, [fragment()]} | {error, decode_error}.
decode_fragment(Bin) ->
    decode_fragment(Bin, []).

decode_fragment(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
decode_fragment(
    <<Type, Len:24, Seq:16, Off:24, FLen:24, Rest/binary>>, Acc
) when byte_size(Rest) >= FLen, Off + FLen =< Len ->
    <<Data:FLen/binary, Tail/binary>> = Rest,
    F = #{type => type_name(Type), length => Len, seq => Seq, offset => Off, data => Data},
    decode_fragment(Tail, [F | Acc]);
decode_fragment(_, _) ->
    {error, decode_error}.

%% @doc A complete message with its 12-byte header, as it enters the
%% handshake transcript (§4.2.6: offset 0, fragment length = length).
-spec full(msg_type(), 0..16#FFFF, binary()) -> binary().
full(Type, Seq, Body) ->
    Len = byte_size(Body),
    <<(type_code(Type)), Len:24, Seq:16, 0:24, Len:24, Body/binary>>.

%% @doc Fragment a message so each fragment (header included) fits in
%% `Max' bytes (§4.2.3).
-spec fragments(msg_type(), 0..16#FFFF, binary(), pos_integer()) -> [binary()].
fragments(Type, Seq, Body, Max) when Max > 12 ->
    Len = byte_size(Body),
    Chunk = Max - 12,
    case Len =< Chunk of
        true -> [full(Type, Seq, Body)];
        false -> frag(type_code(Type), Seq, Len, Body, 0, Chunk, [])
    end.

frag(_T, _Seq, _Len, <<>>, _Off, _Chunk, Acc) ->
    lists:reverse(Acc);
frag(T, Seq, Len, Body, Off, Chunk, Acc) ->
    N = min(Chunk, byte_size(Body)),
    <<Part:N/binary, Rest/binary>> = Body,
    frag(T, Seq, Len, Rest, Off + N, Chunk, [<<T, Len:24, Seq:16, Off:24, N:24, Part/binary>> | Acc]).

%%====================================================================
%% Message bodies
%%====================================================================

-spec encode_body(msg_type(), map() | [binary()] | binary()) -> binary().
encode_body(client_hello, #{
    version := V, random := R, session_id := Sid, cookie := C, suites := Suites, extensions := Exts
}) ->
    SuitesBin = <<<<S:16>> || S <- Suites>>,
    iolist_to_binary([
        <<V:16>>,
        R,
        vec8(Sid),
        vec8(C),
        vec16(SuitesBin),
        vec8(<<0>>),
        encode_extensions(Exts)
    ]);
encode_body(server_hello, #{
    version := V, random := R, session_id := Sid, suite := Suite, extensions := Exts
}) ->
    iolist_to_binary([<<V:16>>, R, vec8(Sid), <<Suite:16, 0>>, encode_extensions(Exts)]);
encode_body(hello_verify_request, #{version := V, cookie := C}) ->
    iolist_to_binary([<<V:16>>, vec8(C)]);
encode_body(certificate, Certs) when is_list(Certs) ->
    vec24(iolist_to_binary([vec24(C) || C <- Certs]));
encode_body(server_key_exchange, #{params := Params, scheme := Scheme, signature := Sig}) ->
    iolist_to_binary([Params, <<Scheme:16>>, vec16(Sig)]);
encode_body(certificate_request, #{cert_types := Types, schemes := Schemes}) ->
    iolist_to_binary([
        vec8(list_to_binary(Types)), vec16(<<<<S:16>> || S <- Schemes>>), vec16(<<>>)
    ]);
encode_body(server_hello_done, _) ->
    <<>>;
encode_body(client_key_exchange, #{public := Pub}) ->
    vec8(Pub);
encode_body(certificate_verify, #{scheme := Scheme, signature := Sig}) ->
    iolist_to_binary([<<Scheme:16>>, vec16(Sig)]);
encode_body(finished, VerifyData) when is_binary(VerifyData) ->
    VerifyData.

%% @doc ServerKeyExchange params for a named curve (RFC 8422 §5.4).
-spec decode_body(msg_type(), binary()) -> {ok, term()} | {error, decode_error}.
decode_body(Type, Bin) ->
    try body(Type, Bin) of
        Msg -> {ok, Msg}
    catch
        _:_ -> {error, decode_error}
    end.

body(client_hello, <<V:16, R:32/binary, Rest0/binary>>) ->
    {Sid, Rest1} = take8(Rest0),
    true = byte_size(Sid) =< 32,
    {Cookie, Rest2} = take8(Rest1),
    true = byte_size(Cookie) =< 255,
    {SuitesBin, Rest3} = take16(Rest2),
    0 = byte_size(SuitesBin) rem 2,
    {Comp, Rest4} = take8(Rest3),
    true = byte_size(Comp) >= 1,
    #{
        version => V,
        random => R,
        session_id => Sid,
        cookie => Cookie,
        suites => [S || <<S:16>> <= SuitesBin],
        compression => binary_to_list(Comp),
        extensions => extensions(Rest4)
    };
body(server_hello, <<V:16, R:32/binary, Rest0/binary>>) ->
    {Sid, <<Suite:16, Comp, Rest1/binary>>} = take8(Rest0),
    true = byte_size(Sid) =< 32,
    #{
        version => V,
        random => R,
        session_id => Sid,
        suite => Suite,
        compression => Comp,
        extensions => extensions(Rest1)
    };
body(hello_verify_request, <<V:16, Rest/binary>>) ->
    {Cookie, <<>>} = take8(Rest),
    #{version => V, cookie => Cookie};
body(certificate, Bin) ->
    {List, <<>>} = take24(Bin),
    certs(List, []);
body(server_key_exchange, <<3, Curve:16, PLen, Pub:PLen/binary, Scheme:16, Rest/binary>> = Bin) ->
    {Sig, <<>>} = take16(Rest),
    <<Params:(4 + PLen)/binary, _/binary>> = Bin,
    #{curve => Curve, public => Pub, params => Params, scheme => Scheme, signature => Sig};
body(certificate_request, Bin) ->
    {Types, Rest0} = take8(Bin),
    {Schemes, Rest1} = take16(Rest0),
    0 = byte_size(Schemes) rem 2,
    {_CAs, <<>>} = take16(Rest1),
    #{cert_types => binary_to_list(Types), schemes => [S || <<S:16>> <= Schemes]};
body(server_hello_done, <<>>) ->
    #{};
body(client_key_exchange, Bin) ->
    {Pub, <<>>} = take8(Bin),
    #{public => Pub};
body(certificate_verify, <<Scheme:16, Rest/binary>>) ->
    {Sig, <<>>} = take16(Rest),
    #{scheme => Scheme, signature => Sig};
body(finished, <<VD:12/binary>>) ->
    VD;
body(hello_request, <<>>) ->
    #{}.

certs(<<>>, Acc) ->
    lists:reverse(Acc);
certs(Bin, Acc) ->
    {C, Rest} = take24(Bin),
    true = byte_size(C) > 0,
    certs(Rest, [C | Acc]).

%%====================================================================
%% Extensions
%%====================================================================

-spec encode_extensions([{atom() | non_neg_integer(), term()}]) -> binary().
encode_extensions([]) ->
    <<>>;
encode_extensions(Exts) ->
    vec16(iolist_to_binary([encode_ext(E) || E <- Exts])).

encode_ext({supported_groups, Groups}) ->
    ext(?EXT_SUPPORTED_GROUPS, vec16(<<<<G:16>> || G <- Groups>>));
encode_ext({ec_point_formats, Formats}) ->
    ext(?EXT_EC_POINT_FORMATS, vec8(list_to_binary(Formats)));
encode_ext({signature_algorithms, Schemes}) ->
    ext(?EXT_SIGNATURE_ALGORITHMS, vec16(<<<<S:16>> || S <- Schemes>>));
encode_ext({use_srtp, {Profiles, MKI}}) ->
    ext(?EXT_USE_SRTP, <<(vec16(<<<<P:16>> || P <- Profiles>>))/binary, (vec8(MKI))/binary>>);
encode_ext({extended_master_secret, _}) ->
    ext(?EXT_EXTENDED_MASTER_SECRET, <<>>);
encode_ext({renegotiation_info, Info}) ->
    ext(?EXT_RENEGOTIATION_INFO, vec8(Info));
encode_ext({Type, Data}) when is_integer(Type), is_binary(Data) ->
    ext(Type, Data).

ext(Type, Data) ->
    [<<Type:16>>, vec16(Data)].

%% @doc Decode an extension block (with its length). Raises on
%% malformed input; callers run it under `decode_body/2' style guards.
-spec decode_extensions(binary()) -> [{atom() | non_neg_integer(), term()}].
decode_extensions(Bin) ->
    extensions(Bin).

%% Absent extension block is allowed (RFC 5246 §7.4.1.2).
extensions(<<>>) ->
    [];
extensions(Bin) ->
    {Block, <<>>} = take16(Bin),
    exts(Block, []).

exts(<<>>, Acc) ->
    Acc1 = lists:reverse(Acc),
    %% RFC 5246 §7.4.1.4: at most one extension of each type.
    Types = [T || {T, _} <- Acc1],
    true = length(Types) =:= length(lists:usort(Types)),
    Acc1;
exts(<<Type:16, Rest0/binary>>, Acc) ->
    {Data, Rest} = take16(Rest0),
    exts(Rest, [decode_ext(Type, Data) | Acc]).

decode_ext(?EXT_SUPPORTED_GROUPS, Data) ->
    {L, <<>>} = take16(Data),
    0 = byte_size(L) rem 2,
    {supported_groups, [G || <<G:16>> <= L]};
decode_ext(?EXT_EC_POINT_FORMATS, Data) ->
    {L, <<>>} = take8(Data),
    {ec_point_formats, binary_to_list(L)};
decode_ext(?EXT_SIGNATURE_ALGORITHMS, Data) ->
    {L, <<>>} = take16(Data),
    0 = byte_size(L) rem 2,
    {signature_algorithms, [S || <<S:16>> <= L]};
decode_ext(?EXT_USE_SRTP, Data) ->
    {L, Rest} = take16(Data),
    0 = byte_size(L) rem 2,
    true = byte_size(L) > 0,
    {MKI, <<>>} = take8(Rest),
    {use_srtp, {[P || <<P:16>> <= L], MKI}};
decode_ext(?EXT_EXTENDED_MASTER_SECRET, <<>>) ->
    {extended_master_secret, true};
decode_ext(?EXT_RENEGOTIATION_INFO, Data) ->
    {Info, <<>>} = take8(Data),
    {renegotiation_info, Info};
decode_ext(Type, Data) ->
    {Type, Data}.

%%====================================================================
%% Vectors
%%====================================================================

vec8(B) -> <<(byte_size(B)), B/binary>>.
vec16(B) -> <<(byte_size(B)):16, B/binary>>.
vec24(B) -> <<(byte_size(B)):24, B/binary>>.

take8(<<L, B:L/binary, R/binary>>) -> {B, R}.
take16(<<L:16, B:L/binary, R/binary>>) -> {B, R}.
take24(<<L:24, B:L/binary, R/binary>>) -> {B, R}.
