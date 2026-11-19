%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc SRTP and SRTCP packet transforms: AES-CM with HMAC-SHA1
%% (RFC 3711 §4.1.1, §4.2.1) and AES-GCM (RFC 7714 §8, §9).
%%
%% This module holds no per-stream state. The caller (`webrtc_srtp')
%% parses the packet, determines the index, runs the replay check and
%% passes everything here. Unprotect functions verify the authentication
%% tag before any decryption and compare tags in constant time.
%%
%% Packet layouts produced and consumed:
%%
%% <pre>
%% SRTP  AES-CM:  header | E(payload)             | tag (10 or 4)
%% SRTP  GCM:     header | E(payload) | GCM tag (16)
%% SRTCP AES-CM:  8 octets | E(rest) | E-flag,index | tag (10)
%% SRTCP GCM E=1: 8 octets | E(rest) | GCM tag | E-flag,index
%% SRTCP GCM E=0: whole packet | GCM tag | E-flag,index
%% </pre>
-module(webrtc_srtp_cipher).

-include("webrtc_srtp.hrl").

-export([
    keys/5,
    rtp_protect/5,
    rtp_unprotect/5,
    rtp_protect_cryptex/4,
    rtp_unprotect_cryptex/5,
    header_keystream/5,
    rtcp_protect/5,
    rtcp_unprotect/4
]).

%% Largest AES-CM keystream for one IV: 2^16 blocks (RFC 3711 §4.1.1).
-define(CM_MAX_BYTES, (1 bsl 20)).

%% @doc Build the transform state for one of SRTP or SRTCP from session
%% keys. `Salt' is the session salt (14 octets for AES-CM, 12 for GCM).
-spec keys(cm | gcm, binary(), binary(), binary(), pos_integer()) -> #srtp_keys{}.
keys(cm, EncKey, <<Salt:112>>, AuthKey, TagLen) when
    byte_size(EncKey) =:= 16, byte_size(AuthKey) =:= 20, TagLen >= 4, TagLen =< 20
->
    #srtp_keys{
        transform = cm,
        cipher = aes_128_ctr,
        enc_key = EncKey,
        salt = Salt bsl 16,
        auth_key = AuthKey,
        tag_len = TagLen
    };
keys(gcm, EncKey, <<Salt:96>>, _AuthKey, 16) when
    byte_size(EncKey) =:= 16; byte_size(EncKey) =:= 32
->
    Cipher =
        case byte_size(EncKey) of
            16 -> aes_128_gcm;
            32 -> aes_256_gcm
        end,
    #srtp_keys{
        transform = gcm,
        cipher = Cipher,
        enc_key = EncKey,
        salt = Salt,
        tag_len = 16,
        enc_state = crypto:crypto_one_time_aead_init(Cipher, EncKey, 16, true),
        dec_state = crypto:crypto_one_time_aead_init(Cipher, EncKey, 16, false)
    };
keys(Transform, EncKey, Salt, AuthKey, TagLen) ->
    erlang:error(badarg, [Transform, EncKey, Salt, AuthKey, TagLen]).

%%====================================================================
%% SRTP
%%====================================================================

%% @doc Protect an RTP packet split as `Header' and `Payload' with the
%% 48-bit packet index `Index'.
-spec rtp_protect(#srtp_keys{}, 0..16#FFFFFFFF, non_neg_integer(), binary(), binary()) ->
    {ok, binary()} | {error, malformed}.
rtp_protect(#srtp_keys{transform = cm}, _SSRC, _Index, _Hdr, Payload) when
    byte_size(Payload) > ?CM_MAX_BYTES
->
    {error, malformed};
rtp_protect(#srtp_keys{transform = cm} = K, SSRC, Index, Hdr, Payload) ->
    #srtp_keys{enc_key = EK, auth_key = AK, tag_len = TL} = K,
    Enc = crypto:crypto_one_time(aes_128_ctr, EK, cm_iv(K, SSRC, Index), Payload, true),
    Out = <<Hdr/binary, Enc/binary>>,
    Tag = crypto:macN(hmac, sha, AK, [Out, <<(Index bsr 16):32>>], TL),
    {ok, <<Out/binary, Tag/binary>>};
rtp_protect(#srtp_keys{transform = gcm, enc_state = S} = K, SSRC, Index, Hdr, Payload) ->
    CT = crypto:crypto_one_time_aead(S, gcm_iv(K, SSRC, Index), Payload, Hdr),
    {ok, <<Hdr/binary, CT/binary>>}.

%% @doc Verify and decrypt an SRTP packet whose RTP header is `HdrLen'
%% octets long. The caller guarantees the packet holds at least the
%% header and the tag.
-spec rtp_unprotect(#srtp_keys{}, 0..16#FFFFFFFF, non_neg_integer(), binary(), non_neg_integer()) ->
    {ok, binary()} | {error, auth_failed | malformed}.
rtp_unprotect(#srtp_keys{transform = cm} = K, SSRC, Index, Bin, HdrLen) ->
    #srtp_keys{enc_key = EK, auth_key = AK, tag_len = TL} = K,
    AuthLen = byte_size(Bin) - TL,
    <<Auth:AuthLen/binary, Tag:TL/binary>> = Bin,
    Expected = crypto:macN(hmac, sha, AK, [Auth, <<(Index bsr 16):32>>], TL),
    case crypto:hash_equals(Expected, Tag) of
        true when AuthLen - HdrLen > ?CM_MAX_BYTES ->
            {error, malformed};
        true ->
            <<Hdr:HdrLen/binary, Enc/binary>> = Auth,
            Plain = crypto:crypto_one_time(aes_128_ctr, EK, cm_iv(K, SSRC, Index), Enc, false),
            {ok, <<Hdr/binary, Plain/binary>>};
        false ->
            {error, auth_failed}
    end;
rtp_unprotect(#srtp_keys{transform = gcm, dec_state = S} = K, SSRC, Index, Bin, HdrLen) ->
    <<Hdr:HdrLen/binary, CT/binary>> = Bin,
    case crypto:crypto_one_time_aead(S, gcm_iv(K, SSRC, Index), CT, Hdr) of
        Plain when is_binary(Plain) -> {ok, <<Hdr/binary, Plain/binary>>};
        error -> {error, auth_failed}
    end.

%%====================================================================
%% Cryptex (RFC 9335)
%%====================================================================

%% @doc Protect an RTP packet with its CSRC list and header extension
%% encrypted (RFC 9335 §5.1). `Parts' is the fixed header (X set), the
%% CSRC list, the extension header (0xC0DE or 0xC2DE), the extension
%% data and the payload. The encrypted portion is CSRCs, extension data
%% and payload as one keystream; for GCM the fixed header and extension
%% header are the associated data (§5.2).
-spec rtp_protect_cryptex(#srtp_keys{}, 0..16#FFFFFFFF, non_neg_integer(),
                          {binary(), binary(), binary(), binary(), binary()}) ->
    {ok, binary()} | {error, malformed}.
rtp_protect_cryptex(#srtp_keys{transform = cm}, _SSRC, _Index, {_, C, _, E, P}) when
    byte_size(C) + byte_size(E) + byte_size(P) > ?CM_MAX_BYTES
->
    {error, malformed};
rtp_protect_cryptex(#srtp_keys{transform = cm} = K, SSRC, Index, {Fixed, C, ExtHdr, E, P}) ->
    #srtp_keys{enc_key = EK, auth_key = AK, tag_len = TL} = K,
    Enc = crypto:crypto_one_time(aes_128_ctr, EK, cm_iv(K, SSRC, Index), [C, E, P], true),
    Out = assemble(Fixed, byte_size(C), ExtHdr, Enc),
    Tag = crypto:macN(hmac, sha, AK, [Out, <<(Index bsr 16):32>>], TL),
    {ok, <<Out/binary, Tag/binary>>};
rtp_protect_cryptex(#srtp_keys{transform = gcm, enc_state = S} = K, SSRC, Index, {Fixed, C, ExtHdr, E, P}) ->
    CT = crypto:crypto_one_time_aead(S, gcm_iv(K, SSRC, Index), [C, E, P], [Fixed, ExtHdr]),
    {ok, assemble(Fixed, byte_size(C), ExtHdr, CT)}.

%% @doc Verify and decrypt a cryptex packet with `CC' CSRCs. The
%% extension header comes back with its usual profile value.
-spec rtp_unprotect_cryptex(#srtp_keys{}, 0..16#FFFFFFFF, non_neg_integer(), binary(), 0..15) ->
    {ok, binary()} | {error, auth_failed | malformed}.
rtp_unprotect_cryptex(#srtp_keys{transform = cm} = K, SSRC, Index, Bin, CC) ->
    #srtp_keys{enc_key = EK, auth_key = AK, tag_len = TL} = K,
    AuthLen = byte_size(Bin) - TL,
    <<Auth:AuthLen/binary, Tag:TL/binary>> = Bin,
    Expected = crypto:macN(hmac, sha, AK, [Auth, <<(Index bsr 16):32>>], TL),
    case crypto:hash_equals(Expected, Tag) of
        true when AuthLen > ?CM_MAX_BYTES ->
            {error, malformed};
        true ->
            {Fixed, EncC, ExtHdr, Rest} = split_cryptex(Auth, CC),
            Plain = crypto:crypto_one_time(aes_128_ctr, EK, cm_iv(K, SSRC, Index), [EncC, Rest], false),
            {ok, assemble(Fixed, CC * 4, restore(ExtHdr), Plain)};
        false ->
            {error, auth_failed}
    end;
rtp_unprotect_cryptex(#srtp_keys{transform = gcm, dec_state = S} = K, SSRC, Index, Bin, CC) ->
    {Fixed, EncC, ExtHdr, Rest} = split_cryptex(Bin, CC),
    case crypto:crypto_one_time_aead(S, gcm_iv(K, SSRC, Index), <<EncC/binary, Rest/binary>>, [Fixed, ExtHdr]) of
        Plain when is_binary(Plain) -> {ok, assemble(Fixed, CC * 4, restore(ExtHdr), Plain)};
        error -> {error, auth_failed}
    end.

split_cryptex(Bin, CC) ->
    CL = CC * 4,
    <<Fixed:12/binary, EncC:CL/binary, ExtHdr:4/binary, Rest/binary>> = Bin,
    {Fixed, EncC, ExtHdr, Rest}.

%% Fixed header, the first CL bytes of Enc (the CSRCs), the extension
%% header, then the rest of Enc (extension data, payload, GCM tag).
assemble(Fixed, CL, ExtHdr, Enc) ->
    <<C:CL/binary, Rest/binary>> = iolist_to_binary(Enc),
    <<Fixed/binary, C/binary, ExtHdr/binary, Rest/binary>>.

restore(<<16#C0DE:16, Len:16>>) -> <<16#BEDE:16, Len:16>>;
restore(<<16#C2DE:16, Len:16>>) -> <<16#1000:16, Len:16>>.

%%====================================================================
%% SRTCP
%%====================================================================

%% @doc Protect an RTCP compound packet with the 31-bit SRTCP `Index'.
%% `Encrypt' sets the E flag. The packet must be at least 8 octets.
-spec rtcp_protect(#srtp_keys{}, 0..16#FFFFFFFF, 0..16#7FFFFFFF, boolean(), binary()) ->
    {ok, binary()} | {error, malformed}.
rtcp_protect(#srtp_keys{transform = cm} = K, SSRC, Index, Encrypt, Bin) ->
    #srtp_keys{enc_key = EK, auth_key = AK, tag_len = TL} = K,
    <<Hdr:8/binary, Body/binary>> = Bin,
    if
        byte_size(Body) > ?CM_MAX_BYTES ->
            {error, malformed};
        true ->
            {E, Body1} =
                case Encrypt of
                    true ->
                        IV = cm_iv(K, SSRC, Index),
                        {1, crypto:crypto_one_time(aes_128_ctr, EK, IV, Body, true)};
                    false ->
                        {0, Body}
                end,
            Out = <<Hdr/binary, Body1/binary, E:1, Index:31>>,
            Tag = crypto:macN(hmac, sha, AK, Out, TL),
            {ok, <<Out/binary, Tag/binary>>}
    end;
rtcp_protect(#srtp_keys{transform = gcm, enc_state = S} = K, SSRC, Index, true, Bin) ->
    <<Hdr:8/binary, Body/binary>> = Bin,
    Word = <<1:1, Index:31>>,
    CT = crypto:crypto_one_time_aead(S, gcm_iv(K, SSRC, Index), Body, [Hdr, Word]),
    {ok, <<Hdr/binary, CT/binary, Word/binary>>};
rtcp_protect(#srtp_keys{transform = gcm, enc_state = S} = K, SSRC, Index, false, Bin) ->
    Word = <<0:1, Index:31>>,
    Tag = crypto:crypto_one_time_aead(S, gcm_iv(K, SSRC, Index), <<>>, [Bin, Word]),
    {ok, <<Bin/binary, Tag/binary, Word/binary>>}.

%% @doc Verify and, when the E flag is set, decrypt an SRTCP packet.
%% Returns the RTCP compound packet and the SRTCP index. The caller has
%% read `Index' and `E' from the packet to run the replay check and
%% guarantees the minimum length (8 + 4 + tag).
-spec rtcp_unprotect(#srtp_keys{}, 0..16#FFFFFFFF, 0..16#7FFFFFFF, binary()) ->
    {ok, binary()} | {error, auth_failed | malformed}.
rtcp_unprotect(#srtp_keys{transform = cm} = K, SSRC, Index, Bin) ->
    #srtp_keys{enc_key = EK, auth_key = AK, tag_len = TL} = K,
    AuthLen = byte_size(Bin) - TL,
    <<Auth:AuthLen/binary, Tag:TL/binary>> = Bin,
    Expected = crypto:macN(hmac, sha, AK, Auth, TL),
    case crypto:hash_equals(Expected, Tag) of
        true ->
            BodyLen = AuthLen - 12,
            <<Hdr:8/binary, Body:BodyLen/binary, E:1, _:31>> = Auth,
            if
                E =:= 0 ->
                    {ok, <<Hdr/binary, Body/binary>>};
                BodyLen > ?CM_MAX_BYTES ->
                    {error, malformed};
                true ->
                    IV = cm_iv(K, SSRC, Index),
                    Plain = crypto:crypto_one_time(aes_128_ctr, EK, IV, Body, false),
                    {ok, <<Hdr/binary, Plain/binary>>}
            end;
        false ->
            {error, auth_failed}
    end;
rtcp_unprotect(#srtp_keys{transform = gcm, dec_state = S} = K, SSRC, Index, Bin) ->
    HeadLen = byte_size(Bin) - 4,
    <<Head:HeadLen/binary, Word:4/binary>> = Bin,
    IV = gcm_iv(K, SSRC, Index),
    case Word of
        <<1:1, _:31>> ->
            <<Hdr:8/binary, CT/binary>> = Head,
            case crypto:crypto_one_time_aead(S, IV, CT, [Hdr, Word]) of
                Plain when is_binary(Plain) -> {ok, <<Hdr/binary, Plain/binary>>};
                error -> {error, auth_failed}
            end;
        <<0:1, _:31>> ->
            ClearLen = HeadLen - 16,
            <<Clear:ClearLen/binary, Tag:16/binary>> = Head,
            case crypto:crypto_one_time_aead(S, IV, Tag, [Clear, Word]) of
                <<>> -> {ok, Clear};
                error -> {error, auth_failed}
            end
    end.

%%====================================================================
%% Header extension keystream (RFC 6904 §4)
%%====================================================================

%% @doc `Len' octets of the header extension keystream of a packet: the
%% AES-CM transform and IV of the payload (RFC 3711 §4.1.1) with the
%% header key and salt in place of the session key and salt. AES-CM is
%% also the transform for the AES-GCM profiles (RFC 7714 §8.3).
-spec header_keystream(binary(), <<_:112>>, 0..16#FFFFFFFF, non_neg_integer(), non_neg_integer()) -> binary().
header_keystream(Key, <<Salt:112>>, SSRC, Index, Len) ->
    Cipher = case byte_size(Key) of 16 -> aes_128_ctr; 24 -> aes_192_ctr; 32 -> aes_256_ctr end,
    IV = <<((Salt bsl 16) bxor (SSRC bsl 64) bxor (Index bsl 16)):128>>,
    crypto:crypto_one_time(Cipher, Key, IV, <<0:(Len * 8)>>, true).

%%====================================================================
%% IV formation
%%====================================================================

%% RFC 3711 §4.1.1: IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16).
%% The salt is stored already shifted.
cm_iv(#srtp_keys{salt = Salt}, SSRC, Index) ->
    <<(Salt bxor (SSRC bsl 64) bxor (Index bsl 16)):128>>.

%% RFC 7714 §8.1 (SRTP): 00 00 | SSRC | ROC | SEQ, XOR salt.
%% RFC 7714 §9.1 (SRTCP): 00 00 | SSRC | 00 00 | 0 | index, XOR salt.
%% In both cases the low 48 bits are the index and SSRC sits above them.
gcm_iv(#srtp_keys{salt = Salt}, SSRC, Index) ->
    <<(Salt bxor ((SSRC bsl 48) bor Index)):96>>.
