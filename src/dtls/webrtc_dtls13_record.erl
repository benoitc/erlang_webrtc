%% @doc DTLS 1.3 record layer (RFC 9147 §4): demultiplexing of
%% DTLSPlaintext and DTLSCiphertext records (§4.1), the unified header,
%% AEAD protection with the TLS 1.3 nonce and inner plaintext
%% (RFC 8446 §5.2, §5.3), record number encryption (§4.2.3), record
%% number reconstruction (§4.2.2) and the ACK message (§7).
%%
%% Nothing here raises on peer input: malformed records are skipped
%% (§4.5.2).
-module(webrtc_dtls13_record).

-export([
    overhead/1,
    split/1,
    split/2,
    protect/5,
    protect/6,
    open/3,
    reconstruct/3,
    select_epoch/2,
    encode_ack/1,
    decode_ack/1,
    overhead/0
]).

-export_type([rec/0]).

-define(MAX_PLAINTEXT, 16384).
-define(MAX_CIPHERTEXT, (16384 + 256)).
-define(TAG, 16).
%% 0 0 1 C S L E E with C = 0, S = 1 (16-bit sequence), L = 1.
-define(HDR_BITS, 2#00101100).

-type rec() ::
    #{
        format := plain,
        type := webrtc_dtls_record:content_type(),
        version := 0..16#FFFF,
        epoch := 0..16#FFFF,
        seq := 0..16#FFFFFFFFFFFF,
        fragment := binary()
    }
    | #{
        format := unified,
        epoch_bits := 0..3,
        cid => binary(),
        seq_len := 1 | 2,
        enc_seq := non_neg_integer(),
        first := byte(),
        length := undefined | non_neg_integer(),
        body := binary()
    }.

%% @doc Bytes added to a protected record: 5 byte header, content type
%% and the 16 byte AEAD tag.
-spec overhead() -> pos_integer().
overhead() -> 5 + 1 + ?TAG.

%% @doc The same with the peer's connection ID in the header.
-spec overhead(undefined | binary()) -> pos_integer().
overhead(undefined) -> overhead();
overhead(Cid) -> overhead() + byte_size(Cid).

%%====================================================================
%% Demultiplexing (RFC 9147 §4.1)
%%====================================================================

%% @doc Split a datagram into records. Parsing stops at a record whose
%% boundary cannot be found; records with a connection ID (not
%% negotiated) stop parsing too, as the CID length is unknown.
-spec split(binary()) -> [rec()].
split(Bin) ->
    split(Bin, undefined).

%% @doc The same, with records carrying a connection ID of `CidLen'
%% bytes (the one we offered, RFC 9147 §9); `undefined' when we offered
%% none, and a record with a CID then ends parsing (§9: rejected).
-spec split(binary(), undefined | pos_integer()) -> [rec()].
split(Bin, CidLen) ->
    split(Bin, CidLen, []).

split(<<T, V:16, E:16, S:48, L:16, Rest/binary>>, CidLen, Acc) when
    T >= 20, T =< 26, V >= 16#FEFD, V =< 16#FEFF, L =< ?MAX_CIPHERTEXT, byte_size(Rest) >= L
->
    <<Frag:L/binary, Tail/binary>> = Rest,
    R = #{
        format => plain,
        type => webrtc_dtls_record:type_name(T),
        version => V,
        epoch => E,
        seq => S,
        fragment => Frag
    },
    split(Tail, CidLen, [R | Acc]);
split(<<H, Rest00/binary>>, CidLen, Acc) when
    H band 16#E0 =:= 16#20, (H band 16#10 =:= 0 orelse is_integer(CidLen))
->
    SeqLen =
        case H band 16#08 of
            0 -> 1;
            _ -> 2
        end,
    {Cid, Rest0} =
        case {H band 16#10, Rest00} of
            {0, _} -> {<<>>, Rest00};
            {_, <<C:CidLen/binary, R0/binary>>} -> {C, R0};
            {_, _} -> {<<>>, <<>>}
        end,
    case Rest0 of
        <<Seq:SeqLen/unit:8, Rest1/binary>> ->
            case H band 16#04 of
                0 ->
                    lists:reverse(maybe_add(unified(H, Cid, SeqLen, Seq, undefined, Rest1), Acc));
                _ ->
                    case Rest1 of
                        <<L:16, Body:L/binary, Tail/binary>> when L =< ?MAX_CIPHERTEXT ->
                            split(Tail, CidLen, maybe_add(unified(H, Cid, SeqLen, Seq, L, Body), Acc));
                        _ ->
                            lists:reverse(Acc)
                    end
            end;
        _ ->
            lists:reverse(Acc)
    end;
split(_, _CidLen, Acc) ->
    lists:reverse(Acc).

unified(H, Cid, SeqLen, Seq, L, Body) ->
    #{
        format => unified,
        epoch_bits => H band 3,
        cid => Cid,
        seq_len => SeqLen,
        enc_seq => Seq,
        first => H,
        length => L,
        body => Body
    }.

%% §4.2.3: ciphertexts shorter than 16 bytes are rejected as if they
%% failed deprotection.
maybe_add(#{body := B}, Acc) when byte_size(B) < 16; byte_size(B) > ?MAX_CIPHERTEXT ->
    Acc;
maybe_add(R, Acc) ->
    [R | Acc].

%%====================================================================
%% Protection
%%====================================================================

%% @doc Protect one record with the full header (16-bit sequence
%% number and length), encrypting the sequence number.
-spec protect(webrtc_dtls_record:content_type(), non_neg_integer(), non_neg_integer(), iodata(),
    webrtc_dtls13_keys:keys()) -> binary().
protect(Type, Epoch, Seq, Plain, Keys) ->
    protect(Type, Epoch, Seq, Plain, Keys, undefined).

%% @doc The same with the peer's connection ID in the header (C bit,
%% RFC 9147 §4, §9), part of the AEAD additional data. No CID for
%% `undefined' or an empty one.
-spec protect(webrtc_dtls_record:content_type(), non_neg_integer(), non_neg_integer(), iodata(),
    webrtc_dtls13_keys:keys(), undefined | binary()) -> binary().
protect(Type, Epoch, Seq, Plain, #{cipher := C, key := K} = Keys, Cid0) ->
    Cid = case Cid0 of undefined -> <<>>; _ -> Cid0 end,
    Inner = <<(iolist_to_binary(Plain))/binary, (webrtc_dtls_record:type_code(Type))>>,
    Len = byte_size(Inner) + ?TAG,
    CBit = case Cid of <<>> -> 0; _ -> 16#10 end,
    First = ?HDR_BITS bor CBit bor (Epoch band 3),
    Low = Seq band 16#FFFF,
    AAD = <<First, Cid/binary, Low:16, Len:16>>,
    {Ct, Tag} = crypto:crypto_one_time_aead(C, K, nonce(Keys, Seq), Inner, AAD, ?TAG, true),
    Body = <<Ct/binary, Tag/binary>>,
    <<M:16, _/binary>> = mask(Keys, Body),
    <<First, Cid/binary, (Low bxor M):16, Len:16, Body/binary>>.

%% @doc Decrypt the record number, reconstruct it from `Next' (one
%% plus the highest sequence number deprotected in the epoch) and open
%% the record. Returns the full sequence number, the inner content type
%% and the content.
-spec open(rec(), webrtc_dtls13_keys:keys(), non_neg_integer()) ->
    {ok, non_neg_integer(), webrtc_dtls_record:content_type(), binary()} | error.
open(#{format := unified, seq_len := SL, enc_seq := Enc, first := First, length := L, body := Body} = R, Keys, Next) ->
    Bits = SL * 8,
    <<M:Bits, _/binary>> = mask(Keys, Body),
    Low = Enc bxor M,
    Seq = reconstruct(Low, Bits, Next),
    Cid = maps:get(cid, R, <<>>),
    AAD =
        case L of
            undefined -> <<First, Cid/binary, Low:Bits>>;
            _ -> <<First, Cid/binary, Low:Bits, L:16>>
        end,
    CtLen = byte_size(Body) - ?TAG,
    <<Ct:CtLen/binary, Tag:?TAG/binary>> = Body,
    #{cipher := C, key := K} = Keys,
    case crypto:crypto_one_time_aead(C, K, nonce(Keys, Seq), Ct, AAD, Tag, false) of
        Inner when is_binary(Inner), byte_size(Inner) =< ?MAX_PLAINTEXT + 1 ->
            case inner(Inner) of
                {ok, Type, Content} -> {ok, Seq, Type, Content};
                error -> error
            end;
        _ ->
            error
    end;
open(_, _, _) ->
    error.

%% RFC 8446 §5.4: the content type is the last non-zero byte.
inner(Inner) ->
    case strip_zeros(Inner, byte_size(Inner)) of
        0 ->
            error;
        N ->
            Len = N - 1,
            <<Content:Len/binary, Type, _/binary>> = Inner,
            {ok, webrtc_dtls_record:type_name(Type), Content}
    end.

strip_zeros(_Bin, 0) ->
    0;
strip_zeros(Bin, N) ->
    case binary:at(Bin, N - 1) of
        0 -> strip_zeros(Bin, N - 1);
        _ -> N
    end.

%% RFC 8446 §5.3: the 64-bit record sequence number (RFC 9147 §4: the
%% epoch is not included) left-padded to the IV length, XORed with it.
nonce(#{iv := <<IV:96>>}, Seq) ->
    <<(IV bxor Seq):96>>.

%% RFC 9147 §4.2.3.
mask(#{cipher := aes_128_gcm, sn_key := K}, <<Sample:16/binary, _/binary>>) ->
    crypto:crypto_one_time(aes_128_ecb, K, Sample, true);
mask(#{cipher := aes_256_gcm, sn_key := K}, <<Sample:16/binary, _/binary>>) ->
    crypto:crypto_one_time(aes_256_ecb, K, Sample, true);
mask(#{cipher := chacha20_poly1305, sn_key := K}, <<Sample:16/binary, _/binary>>) ->
    %% OTP's chacha20 IV is the 32-bit little-endian block counter
    %% followed by the 96-bit nonce, which is exactly the sample layout.
    crypto:crypto_one_time(chacha20, K, Sample, <<0:128>>, true).

%%====================================================================
%% Record number reconstruction (RFC 9147 §4.2.2)
%%====================================================================

%% @doc The sequence number closest to `Next' whose low `Bits' bits are
%% `Low'.
-spec reconstruct(non_neg_integer(), 8 | 16, non_neg_integer()) -> non_neg_integer().
reconstruct(Low, Bits, Next) ->
    Win = 1 bsl Bits,
    Cand = (Next band bnot (Win - 1)) bor Low,
    Options = [C || C <- [Cand - Win, Cand, Cand + Win], C >= 0],
    {_, Best} = lists:min([{abs(C - Next), C} || C <- Options]),
    Best.

%% @doc The most recent epoch among `Epochs' whose low two bits are
%% `Bits'.
-spec select_epoch(0..3, [non_neg_integer()]) -> {ok, non_neg_integer()} | error.
select_epoch(Bits, Epochs) ->
    case [E || E <- Epochs, E > 0, E band 3 =:= Bits] of
        [] -> error;
        Es -> {ok, lists:max(Es)}
    end.

%%====================================================================
%% ACK (RFC 9147 §7)
%%====================================================================

-spec encode_ack([{non_neg_integer(), non_neg_integer()}]) -> binary().
encode_ack(Records) ->
    Body = <<<<E:64, S:64>> || {E, S} <- lists:usort(Records)>>,
    <<(byte_size(Body)):16, Body/binary>>.

-spec decode_ack(binary()) -> {ok, [{non_neg_integer(), non_neg_integer()}]} | error.
decode_ack(<<L:16, Body:L/binary>>) when L rem 16 =:= 0 ->
    {ok, [{E, S} || <<E:64, S:64>> <= Body]};
decode_ack(_) ->
    error.
