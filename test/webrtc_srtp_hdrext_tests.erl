%% RFC 6904: encrypted RTP header extension elements.
-module(webrtc_srtp_hdrext_tests).
-include_lib("eunit/include/eunit.hrl").

-import(webrtc_test_hex, [b/1]).

-define(HK, b("549752054D6FB708622C4A2E596A1B93")).
-define(HS, b("AB01818174C40D39A3781F7C2D27")).
%% A.2: elements 1, 3 and 4 encrypted, 2 clear, one padding octet.
-define(PLAIN, b("17 414273A475262748 22 0000C8 30 8E 46 55996386B395FB 00")).
-define(CIPHER, b("17588A9270F4E15E1C220000C8309546A994F0BC54789700")).

%% A context with the A.2 header key and salt (the other session keys do
%% not matter for the header extension).
ctx(Profile, Ids) ->
    KL = case Profile of srtp_aead_aes_256_gcm -> 32; _ -> 16 end,
    SL = case Profile of srtp_aes128_cm_hmac_sha1_80 -> 14; srtp_aes128_cm_hmac_sha1_32 -> 14; _ -> 12 end,
    Keys = (webrtc_srtp_kdf:session_keys(Profile, <<1:(KL * 8)>>, <<2:(SL * 8)>>))#{
        rtp_hdr_key => ?HK, rtp_hdr_salt => ?HS
    },
    webrtc_srtp:from_session_keys(Profile, Keys, #{encrypted_extensions => Ids}).

%% SSRC CAFEBABE, sequence 1234, the A.2 extension block, a payload.
packet(Ext) ->
    Words = byte_size(Ext) div 4,
    <<16#90, 96, 16#1234:16, 0:32, 16#CAFEBABE:32, 16#BEDE:16, Words:16, Ext/binary, "payload">>.

ext_of(<<_:12/binary, 16#BEDE:16, W:16, Ext:W/binary-unit:32, _/binary>>) -> Ext.

keystream_test() ->
    Ks = webrtc_srtp_cipher:header_keystream(?HK, ?HS, 16#CAFEBABE, 16#1234, 24),
    ?assertEqual(b("1E19C8E1D481C779549ED1617AAA1B7AFC0D933AE7ED6CC8"), Ks).

%% Appendix A.2 on a whole packet: the extension block on the wire is
%% the RFC's ciphertext, and it comes back as the plaintext.
rfc6904_a2_test_() ->
    [?_test(a2(P)) || P <- [srtp_aes128_cm_hmac_sha1_80, srtp_aead_aes_128_gcm]].

a2(Profile) ->
    Tx = ctx(Profile, [1, 3, 4]),
    Rx = ctx(Profile, [1, 3, 4]),
    {ok, Srtp, _} = webrtc_srtp:protect_rtp(packet(?PLAIN), Tx),
    ?assertEqual(?CIPHER, ext_of(Srtp)),
    ?assertEqual({ok, packet(?PLAIN)}, unprotect(Srtp, Rx)).

unprotect(Srtp, Rx) ->
    {ok, P, _} = webrtc_srtp:unprotect_rtp(Srtp, Rx),
    {ok, P}.

%% The tag covers the encrypted elements: changing one fails.
tampered_test_() ->
    [?_test(tampered(P)) || P <- [srtp_aes128_cm_hmac_sha1_80, srtp_aead_aes_128_gcm]].

tampered(Profile) ->
    {ok, <<H:17/binary, X, T/binary>>, _} = webrtc_srtp:protect_rtp(packet(?PLAIN), ctx(Profile, [1])),
    ?assertEqual({error, auth_failed}, webrtc_srtp:unprotect_rtp(<<H/binary, (X bxor 1), T/binary>>, ctx(Profile, [1]))).

%% Without encrypted ids nothing changes in the header.
clear_test() ->
    {ok, Srtp, _} = webrtc_srtp:protect_rtp(packet(?PLAIN), ctx(srtp_aes128_cm_hmac_sha1_80, [])),
    ?assertEqual(?PLAIN, ext_of(Srtp)).

%% Mixed: element 2 encrypted, the others clear; ids not in the packet
%% change nothing.
mixed_test() ->
    {ok, Srtp, _} = webrtc_srtp:protect_rtp(packet(?PLAIN), ctx(srtp_aes128_cm_hmac_sha1_80, [2, 9])),
    <<A:10/binary, Two:3/binary, B/binary>> = ext_of(Srtp),
    <<A:10/binary, Clear:3/binary, B/binary>> = ?PLAIN,
    ?assertNotEqual(Clear, Two),
    ?assertMatch({ok, _}, unprotect(Srtp, ctx(srtp_aes128_cm_hmac_sha1_80, [2, 9]))).

%% Two-byte form (RFC 8285 §4.3): id, length, data.
two_byte_test() ->
    Ext = <<5, 3, 1, 2, 3, 6, 0, 7, 1, 9, 0, 0>>,
    Pkt = <<16#90, 96, 1:16, 0:32, 16#CAFEBABE:32, 16#1000:16, 3:16, Ext/binary, "p">>,
    Tx = ctx(srtp_aes128_cm_hmac_sha1_80, [5, 7]),
    {ok, Srtp, _} = webrtc_srtp:protect_rtp(Pkt, Tx),
    <<_:12/binary, 16#1000:16, 3:16, 5, 3, E5:3/binary, 6, 0, 7, 1, E7, 0, 0, _/binary>> = Srtp,
    ?assertNotEqual(<<1, 2, 3>>, E5),
    ?assertNotEqual(9, E7),
    {ok, Pkt, _} = webrtc_srtp:unprotect_rtp(Srtp, ctx(srtp_aes128_cm_hmac_sha1_80, [5, 7])).

%% A block that does not parse is left as it is.
malformed_block_test() ->
    Ext = <<16#1F, 1, 2, 3>>,
    {ok, Srtp, _} = webrtc_srtp:protect_rtp(packet(Ext), ctx(srtp_aes128_cm_hmac_sha1_80, [1])),
    ?assertEqual(Ext, ext_of(Srtp)).

%% With cryptex on, a packet is cryptex only: decrypting it does not
%% unmask on top (RFC 9335 and RFC 6904 independent).
with_cryptex_test() ->
    Tx = webrtc_srtp:set_cryptex(true, ctx(srtp_aes128_cm_hmac_sha1_80, [1, 3, 4])),
    {ok, Srtp, _} = webrtc_srtp:protect_rtp(packet(?PLAIN), Tx),
    ?assertMatch(<<_:12/binary, 16#C0DE:16, _/binary>>, Srtp),
    {ok, Back, _} = webrtc_srtp:unprotect_rtp(Srtp, ctx(srtp_aes128_cm_hmac_sha1_80, [1, 3, 4])),
    ?assertEqual(packet(?PLAIN), Back).
