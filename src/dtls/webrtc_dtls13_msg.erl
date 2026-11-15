%% @doc DTLS 1.3 handshake message and extension codec (RFC 8446 §4,
%% RFC 9147 §5). ClientHello and ServerHello share the DTLS 1.2 layout
%% and are handled by `webrtc_dtls_msg'; this module covers the
%% messages and extensions that only exist in (D)TLS 1.3.
%%
%% `decode/2' and `ext/3' never raise: malformed input gives
%% `{error, decode_error}'.
-module(webrtc_dtls13_msg).

-export([
    encode/2,
    decode/2,
    known/1,
    ext/3,
    supported_versions_ext/1,
    key_share_ext/1,
    cookie_ext/1,
    connection_id_ext/1,
    psk_modes_ext/0,
    early_data_ext/0,
    client_psk_ext/3,
    server_psk_ext/1,
    selected_version_ext/0,
    server_share_ext/2,
    hrr_group_ext/1,
    transcript_msg/2,
    message_hash/1
]).

-define(EXT_SUPPORTED_VERSIONS, 43).
-define(EXT_COOKIE, 44).
-define(EXT_KEY_SHARE, 51).
-define(EXT_CONNECTION_ID, 54).
-define(EXT_PRE_SHARED_KEY, 41).
-define(EXT_EARLY_DATA, 42).
-define(EXT_PSK_MODES, 45).
-define(MESSAGE_HASH, 254).

%%====================================================================
%% Extensions (RFC 8446 §4.2)
%%====================================================================

-spec supported_versions_ext([0..16#FFFF]) -> {43, binary()}.
supported_versions_ext(Versions) ->
    V = <<<<X:16>> || X <- Versions>>,
    {?EXT_SUPPORTED_VERSIONS, <<(byte_size(V)), V/binary>>}.

-spec selected_version_ext() -> {43, binary()}.
selected_version_ext() ->
    {?EXT_SUPPORTED_VERSIONS, <<16#FEFC:16>>}.

-spec key_share_ext([{0..16#FFFF, binary()}]) -> {51, binary()}.
key_share_ext(Shares) ->
    L = iolist_to_binary([<<G:16, (byte_size(K)):16, K/binary>> || {G, K} <- Shares]),
    {?EXT_KEY_SHARE, <<(byte_size(L)):16, L/binary>>}.

-spec server_share_ext(0..16#FFFF, binary()) -> {51, binary()}.
server_share_ext(Group, Key) ->
    {?EXT_KEY_SHARE, <<Group:16, (byte_size(Key)):16, Key/binary>>}.

-spec hrr_group_ext(0..16#FFFF) -> {51, binary()}.
hrr_group_ext(Group) ->
    {?EXT_KEY_SHARE, <<Group:16>>}.

%% @doc The connection ID we want to receive (RFC 9146 §3).
-spec connection_id_ext(binary()) -> {54, binary()}.
connection_id_ext(Cid) ->
    {?EXT_CONNECTION_ID, <<(byte_size(Cid)), Cid/binary>>}.

%% @doc psk_key_exchange_modes with psk_dhe_ke only: resumption keeps
%% (EC)DHE and forward secrecy (RFC 8446 §4.2.9).
-spec psk_modes_ext() -> {45, binary()}.
psk_modes_ext() ->
    {?EXT_PSK_MODES, <<1, 1>>}.

%% @doc early_data, empty in ClientHello and EncryptedExtensions
%% (RFC 8446 §4.2.10).
-spec early_data_ext() -> {42, binary()}.
early_data_ext() ->
    {?EXT_EARLY_DATA, <<>>}.

%% @doc The ClientHello pre_shared_key extension with one identity and
%% a binder of `BinderLen' zero octets, filled by the caller (it must
%% be the last extension, RFC 8446 §4.2.11).
-spec client_psk_ext(binary(), 0..16#FFFFFFFF, pos_integer()) -> {41, binary()}.
client_psk_ext(Ticket, ObfuscatedAge, BinderLen) ->
    Ids = <<(byte_size(Ticket)):16, Ticket/binary, ObfuscatedAge:32>>,
    Binders = <<BinderLen, 0:(BinderLen * 8)>>,
    {?EXT_PRE_SHARED_KEY, <<(byte_size(Ids)):16, Ids/binary, (byte_size(Binders)):16, Binders/binary>>}.

%% @doc The ServerHello pre_shared_key extension.
-spec server_psk_ext(0..16#FFFF) -> {41, binary()}.
server_psk_ext(Index) ->
    {?EXT_PRE_SHARED_KEY, <<Index:16>>}.

-spec cookie_ext(binary()) -> {44, binary()}.
cookie_ext(Cookie) ->
    {?EXT_COOKIE, <<(byte_size(Cookie)):16, Cookie/binary>>}.

%% @doc Decode a 1.3 extension carried as `{Type, Data}' by the hello
%% codec, in the context of the message that carried it.
-spec ext(client_hello | server_hello | hello_retry_request, atom(), [{term(), term()}]) ->
    undefined | {ok, term()} | {error, decode_error}.
ext(Ctx, Name, Exts) ->
    Type =
        case Name of
            supported_versions -> ?EXT_SUPPORTED_VERSIONS;
            key_share -> ?EXT_KEY_SHARE;
            cookie -> ?EXT_COOKIE;
            connection_id -> ?EXT_CONNECTION_ID;
            pre_shared_key -> ?EXT_PRE_SHARED_KEY;
            early_data -> ?EXT_EARLY_DATA;
            psk_key_exchange_modes -> ?EXT_PSK_MODES
        end,
    case lists:keyfind(Type, 1, Exts) of
        false ->
            undefined;
        {_, Data} ->
            try ext_body(Ctx, Name, Data) of
                V -> {ok, V}
            catch
                _:_ -> {error, decode_error}
            end
    end.

ext_body(client_hello, supported_versions, <<L, V:L/binary>>) when L >= 2, L rem 2 =:= 0 ->
    [X || <<X:16>> <= V];
ext_body(_, supported_versions, <<V:16>>) ->
    V;
ext_body(client_hello, key_share, <<L:16, Body:L/binary>>) ->
    shares(Body, []);
ext_body(server_hello, key_share, <<G:16, L:16, K:L/binary>>) when L > 0 ->
    {G, K};
ext_body(hello_retry_request, key_share, <<G:16>>) ->
    G;
ext_body(_, cookie, <<L:16, C:L/binary>>) when L > 0 ->
    C;
ext_body(_, connection_id, <<L, C:L/binary>>) ->
    C;
%% {[{Identity, ObfuscatedAge}], [Binder], BindersLength}.
ext_body(client_hello, pre_shared_key, <<IL:16, Ids:IL/binary, BL:16, Bs:BL/binary>>) when IL > 0, BL > 0 ->
    {identities(Ids), binders(Bs), BL};
ext_body(server_hello, pre_shared_key, <<Index:16>>) ->
    Index;
ext_body(_, early_data, <<>>) ->
    true;
ext_body(client_hello, psk_key_exchange_modes, <<L, Modes:L/binary>>) when L > 0 ->
    binary_to_list(Modes).

cids(<<>>) -> [];
cids(<<L, C:L/binary, Rest/binary>>) -> [C | cids(Rest)].

identities(<<>>) -> [];
identities(<<L:16, I:L/binary, Age:32, Rest/binary>>) when L > 0 -> [{I, Age} | identities(Rest)].

binders(<<>>) -> [];
binders(<<L, B:L/binary, Rest/binary>>) when L >= 32 -> [B | binders(Rest)].

shares(<<>>, Acc) ->
    Groups = [G || {G, _} <- Acc],
    %% RFC 8446 §4.2.8: at most one share per group.
    true = length(Groups) =:= length(lists:usort(Groups)),
    lists:reverse(Acc);
shares(<<G:16, L:16, K:L/binary, Rest/binary>>, Acc) when L > 0 ->
    shares(Rest, [{G, K} | Acc]).

%%====================================================================
%% Messages (RFC 8446 §4.3 to §4.6)
%%====================================================================

-spec encode(atom(), term()) -> binary().
encode(encrypted_extensions, Exts) ->
    exts_block(Exts);
encode(certificate_request, #{context := Ctx, extensions := Exts}) ->
    <<(vec8(Ctx))/binary, (exts_block(Exts))/binary>>;
encode(certificate, #{context := Ctx, certs := Certs}) ->
    List = iolist_to_binary([[vec24(C), <<0:16>>] || C <- Certs]),
    <<(vec8(Ctx))/binary, (vec24(List))/binary>>;
encode(certificate_verify, #{scheme := S, signature := Sig}) ->
    <<S:16, (byte_size(Sig)):16, Sig/binary>>;
encode(finished, VD) ->
    VD;
encode(new_session_ticket, #{lifetime := L, age_add := A, nonce := N, ticket := T, max_early_data := M}) ->
    Exts = [{?EXT_EARLY_DATA, <<M:32>>} || M > 0],
    <<L:32, A:32, (byte_size(N)), N/binary, (byte_size(T)):16, T/binary, (exts_block(Exts))/binary>>;
encode(new_connection_id, {Cids, Usage}) ->
    List = iolist_to_binary([vec8(C) || C <- Cids]),
    <<(byte_size(List)):16, List/binary, (case Usage of immediate -> 0; spare -> 1 end)>>;
encode(request_connection_id, N) when N > 0, N =< 255 ->
    <<N>>;
encode(key_update, update_requested) ->
    <<1>>;
encode(key_update, update_not_requested) ->
    <<0>>.

%% @doc True for the message types `decode/2' handles.
-spec known(term()) -> boolean().
known(Type) ->
    lists:member(Type, [
        encrypted_extensions, certificate_request, certificate, certificate_verify, finished, key_update, new_session_ticket,
        request_connection_id, new_connection_id
    ]).

-spec decode(atom() | 0..255, binary()) -> {ok, term()} | {error, decode_error}.
decode(Type, Bin) ->
    try body(Type, Bin) of
        M -> {ok, M}
    catch
        _:_ -> {error, decode_error}
    end.

body(encrypted_extensions, Bin) ->
    {Block, <<>>} = take16(Bin),
    exts(Block);
body(certificate_request, Bin) ->
    {Ctx, Rest} = take8(Bin),
    {Block, <<>>} = take16(Rest),
    #{context => Ctx, extensions => exts(Block)};
body(certificate, Bin) ->
    {Ctx, Rest} = take8(Bin),
    {List, <<>>} = take24(Rest),
    #{context => Ctx, certs => entries(List, [])};
body(certificate_verify, <<S:16, L:16, Sig:L/binary>>) ->
    #{scheme => S, signature => Sig};
body(finished, VD) when byte_size(VD) =:= 32; byte_size(VD) =:= 48 ->
    VD;
%% RFC 9147 §9: ConnectionId cids<0..2^16-1> (each opaque<0..2^8-1>)
%% and the usage; and the number of CIDs asked for.
body(new_connection_id, <<L:16, Cids:L/binary, Usage>>) when Usage =:= 0; Usage =:= 1 ->
    {cids(Cids), case Usage of 0 -> immediate; 1 -> spare end};
body(request_connection_id, <<N>>) ->
    N;
body(key_update, <<0>>) ->
    update_not_requested;
body(key_update, <<1>>) ->
    update_requested;
body(new_session_ticket, <<Lifetime:32, AgeAdd:32, Rest0/binary>>) ->
    {Nonce, Rest1} = take8(Rest0),
    {Ticket, Rest2} = take16(Rest1),
    true = byte_size(Ticket) > 0,
    {Block, <<>>} = take16(Rest2),
    Exts = exts(Block),
    MaxEarly =
        case lists:keyfind(?EXT_EARLY_DATA, 1, Exts) of
            {_, <<M:32>>} -> M;
            false -> 0
        end,
    #{lifetime => Lifetime, age_add => AgeAdd, nonce => Nonce, ticket => Ticket, max_early_data => MaxEarly}.

entries(<<>>, Acc) ->
    lists:reverse(Acc);
entries(Bin, Acc) ->
    {C, Rest0} = take24(Bin),
    true = byte_size(C) > 0,
    {_Exts, Rest} = take16(Rest0),
    entries(Rest, [C | Acc]).

exts(<<>>) ->
    [];
exts(Block) ->
    webrtc_dtls_msg:decode_extensions(<<(byte_size(Block)):16, Block/binary>>).

exts_block(Exts) ->
    case webrtc_dtls_msg:encode_extensions(Exts) of
        <<>> -> <<0:16>>;
        B -> B
    end.

%% @doc A handshake message as it enters the DTLS 1.3 transcript: the
%% TLS 1.3 header without message_seq and fragment fields (RFC 9147
%% §5.2).
-spec transcript_msg(webrtc_dtls_msg:msg_type(), binary()) -> binary().
transcript_msg(Type, Body) ->
    <<(webrtc_dtls_msg:type_code(Type)), (byte_size(Body)):24, Body/binary>>.

%% @doc The synthetic message_hash message replacing ClientHello1 in
%% the transcript after a HelloRetryRequest (RFC 8446 §4.4.1).
-spec message_hash(binary()) -> binary().
message_hash(Hash) ->
    <<?MESSAGE_HASH, 0, 0, (byte_size(Hash)), Hash/binary>>.

vec8(B) -> <<(byte_size(B)), B/binary>>.
vec24(B) -> <<(byte_size(B)):24, B/binary>>.

take8(<<L, B:L/binary, R/binary>>) -> {B, R}.
take16(<<L:16, B:L/binary, R/binary>>) -> {B, R}.
take24(<<L:24, B:L/binary, R/binary>>) -> {B, R}.
