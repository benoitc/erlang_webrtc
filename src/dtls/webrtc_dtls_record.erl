%% @doc DTLS 1.2 record layer (RFC 6347 §4.1): record framing, AEAD
%% protection and the anti-replay window (§4.1.2.6).
-module(webrtc_dtls_record).

-export([
    decode/1,
    encode/5,
    new_cipher/3,
    protect/6,
    unprotect/2,
    replay_new/0,
    replay_check/2,
    replay_update/2,
    type_code/1,
    type_name/1
]).

-export_type([dtls_record/0, cipher/0, replay/0, content_type/0]).

-define(DTLS12, 16#FEFD).
-define(MAX_PLAINTEXT, 16384).
-define(MAX_CIPHERTEXT, (16384 + 2048)).
-define(WINDOW, 64).

-type content_type() ::
    change_cipher_spec | alert | handshake | application_data | heartbeat | ack | 0..255.
-type dtls_record() :: #{
    type := content_type(),
    version := 0..16#FFFF,
    epoch := 0..16#FFFF,
    seq := 0..16#FFFFFFFFFFFF,
    fragment := binary()
}.
-type cipher() :: #{
    cipher := aes_128_gcm | aes_256_gcm | chacha20_poly1305,
    key := binary(),
    iv := binary(),
    explicit_nonce := 0 | 8
}.
-type replay() :: {Max :: integer(), Bitmap :: non_neg_integer()}.

-spec type_code(content_type()) -> 0..255.
type_code(change_cipher_spec) -> 20;
type_code(alert) -> 21;
type_code(handshake) -> 22;
type_code(application_data) -> 23;
type_code(heartbeat) -> 24;
type_code(ack) -> 26;
type_code(N) when is_integer(N) -> N.

-spec type_name(0..255) -> content_type().
type_name(20) -> change_cipher_spec;
type_name(21) -> alert;
type_name(22) -> handshake;
type_name(23) -> application_data;
type_name(24) -> heartbeat;
type_name(26) -> ack;
type_name(N) -> N.

%% @doc Split a datagram into records. A datagram may carry several
%% records (§4.1.1). Parsing stops at the first malformed record; the
%% records before it are returned, as invalid records are discarded
%% (§4.1.2.7) without affecting valid ones.
-spec decode(binary()) -> [dtls_record()].
decode(Bin) ->
    decode(Bin, []).

decode(<<Type, Version:16, Epoch:16, Seq:48, Len:16, Rest/binary>>, Acc) when
    Len =< ?MAX_CIPHERTEXT, byte_size(Rest) >= Len, Version >= 16#FEFD, Version =< 16#FEFF
->
    <<Frag:Len/binary, Tail/binary>> = Rest,
    R = #{type => type_name(Type), version => Version, epoch => Epoch, seq => Seq, fragment => Frag},
    decode(Tail, [R | Acc]);
decode(_, Acc) ->
    lists:reverse(Acc).

-spec encode(content_type(), 0..16#FFFF, 0..16#FFFF, 0..16#FFFFFFFFFFFF, iodata()) -> binary().
encode(Type, Version, Epoch, Seq, Fragment) ->
    Frag = iolist_to_binary(Fragment),
    <<(type_code(Type)), Version:16, Epoch:16, Seq:48, (byte_size(Frag)):16, Frag/binary>>.

-spec new_cipher(webrtc_dtls_crypto:suite(), binary(), binary()) -> cipher().
new_cipher(#{cipher := C, explicit_nonce := E}, Key, IV) ->
    #{cipher => C, key => Key, iv => IV, explicit_nonce => E}.

%% @doc Encrypt and frame one record (RFC 5246 §6.2.3.3, RFC 5288 §3,
%% RFC 7905 §2). The 64-bit DTLS sequence (epoch || seq) is the
%% explicit nonce for GCM and is XORed into the IV for ChaCha20-Poly1305.
-spec protect(content_type(), 0..16#FFFF, 0..16#FFFF, 0..16#FFFFFFFFFFFF, iodata(), cipher()) ->
    binary().
protect(Type, Version, Epoch, Seq, Plain0, #{cipher := C, key := K, iv := IV, explicit_nonce := E}) ->
    Plain = iolist_to_binary(Plain0),
    TypeCode = type_code(Type),
    SeqNum = <<Epoch:16, Seq:48>>,
    AAD = <<SeqNum/binary, TypeCode, Version:16, (byte_size(Plain)):16>>,
    {Nonce, Explicit} = nonce(E, IV, SeqNum),
    {Ct, Tag} = crypto:crypto_one_time_aead(C, K, Nonce, Plain, AAD, 16, true),
    Body = <<Explicit/binary, Ct/binary, Tag/binary>>,
    <<TypeCode, Version:16, Epoch:16, Seq:48, (byte_size(Body)):16, Body/binary>>.

%% @doc Decrypt a protected record.
-spec unprotect(dtls_record(), cipher()) -> {ok, binary()} | {error, bad_record_mac}.
unprotect(
    #{type := Type, version := Version, epoch := Epoch, seq := Seq, fragment := Frag},
    #{cipher := C, key := K, iv := IV, explicit_nonce := E}
) ->
    SeqNum = <<Epoch:16, Seq:48>>,
    case Frag of
        <<Explicit:E/binary, Rest/binary>> when byte_size(Rest) >= 16 ->
            CtLen = byte_size(Rest) - 16,
            <<Ct:CtLen/binary, Tag:16/binary>> = Rest,
            Nonce =
                case E of
                    8 -> <<IV/binary, Explicit/binary>>;
                    0 -> xor_iv(IV, SeqNum)
                end,
            AAD = <<SeqNum/binary, (type_code(Type)), Version:16, CtLen:16>>,
            case crypto:crypto_one_time_aead(C, K, Nonce, Ct, AAD, Tag, false) of
                Plain when is_binary(Plain), byte_size(Plain) =< ?MAX_PLAINTEXT -> {ok, Plain};
                _ -> {error, bad_record_mac}
            end;
        _ ->
            {error, bad_record_mac}
    end.

nonce(8, IV, SeqNum) -> {<<IV/binary, SeqNum/binary>>, SeqNum};
nonce(0, IV, SeqNum) -> {xor_iv(IV, SeqNum), <<>>}.

xor_iv(<<IV:96>>, <<S:64>>) -> <<(IV bxor S):96>>.

%%====================================================================
%% Anti-replay window (RFC 6347 §4.1.2.6, RFC 4303 §3.4.3)
%%====================================================================

-spec replay_new() -> replay().
replay_new() ->
    {-1, 0}.

-spec replay_check(non_neg_integer(), replay()) -> ok | replay.
replay_check(Seq, {Max, _}) when Seq > Max ->
    ok;
replay_check(Seq, {Max, _}) when Max - Seq >= ?WINDOW ->
    replay;
replay_check(Seq, {Max, Bits}) ->
    case Bits band (1 bsl (Max - Seq)) of
        0 -> ok;
        _ -> replay
    end.

%% @doc Mark `Seq' as received. Only call after the record authenticated.
-spec replay_update(non_neg_integer(), replay()) -> replay().
replay_update(Seq, {Max, _Bits}) when Seq - Max >= ?WINDOW ->
    %% A jump beyond the window leaves only the new record in it.
    {Seq, 1};
replay_update(Seq, {Max, Bits}) when Seq > Max ->
    Shift = Seq - Max,
    Mask = (1 bsl ?WINDOW) - 1,
    {Seq, ((Bits bsl Shift) bor 1) band Mask};
replay_update(Seq, {Max, Bits}) ->
    {Max, Bits bor (1 bsl (Max - Seq))}.
