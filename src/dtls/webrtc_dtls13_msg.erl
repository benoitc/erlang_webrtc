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
    ext/3,
    supported_versions_ext/1,
    key_share_ext/1,
    cookie_ext/1,
    selected_version_ext/0,
    server_share_ext/2,
    hrr_group_ext/1,
    transcript_msg/2,
    message_hash/1
]).

-define(EXT_SUPPORTED_VERSIONS, 43).
-define(EXT_COOKIE, 44).
-define(EXT_KEY_SHARE, 51).
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
            cookie -> ?EXT_COOKIE
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
    C.

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
encode(key_update, update_requested) ->
    <<1>>;
encode(key_update, update_not_requested) ->
    <<0>>.

-spec decode(atom(), binary()) -> {ok, term()} | {error, decode_error}.
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
body(key_update, <<0>>) ->
    update_not_requested;
body(key_update, <<1>>) ->
    update_requested;
body(new_session_ticket, <<_Lifetime:32, _AgeAdd:32, Rest0/binary>>) ->
    {_Nonce, Rest1} = take8(Rest0),
    {Ticket, Rest2} = take16(Rest1),
    true = byte_size(Ticket) > 0,
    {Block, <<>>} = take16(Rest2),
    _ = exts(Block),
    #{}.

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
