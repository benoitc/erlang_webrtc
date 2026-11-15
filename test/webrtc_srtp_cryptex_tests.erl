% RFC 9335 Appendix A: cryptex test vectors, ROC 0.
-module(webrtc_srtp_cryptex_tests).
-include_lib("eunit/include/eunit.hrl").

h(Hex) -> binary:decode_hex(list_to_binary(Hex)).

cm() ->
    [
        {"A.1.1", "900f1235decafbadcafebabebede000151000200abababababababababababababababab",
         "900f1235decafbadcafebabec0de0001eb92365251c3e036f8de27e9c27ee3e0b4651d9fbc4218a70244522f34a5"},
        {"A.1.2", "900f1236decafbadcafebabe1000000105020002abababababababababababababababab",
         "900f1236decafbadcafebabec2de00014ed9cc4e6a712b3096c5ca77339d4204ce0d77396cab69585fbce38194a5"},
        {"A.1.3", "920f1238decafbadcafebabe0001e2400000b26ebede000151000200abababababababababababababababab",
         "920f1238decafbadcafebabe8bb6e12b5cff16ddc0de000192838c8c09e58393e1de3a9a74734d6745671338c3acf11da2df8423bee0"},
        {"A.1.4", "920f1239decafbadcafebabe0001e2400000b26e1000000105020002abababababababababababababababab",
         "920f1239decafbadcafebabef70e513eb90b9b25c2de0001bbed4848faa644665f3d7f34125914e9f4d0ae923c6f479b95a0f7b53133"},
        {"A.1.5", "920f123adecafbadcafebabe0001e2400000b26ebede0000abababababababababababababababab",
         "920f123adecafbadcafebabe7130b6abfe2ab0e3c0de0000e3d9f64b25c9e74cb4cf8e43fb92e3781c2c0ceab6b3a499a14c"},
        {"A.1.6", "920f123bdecafbadcafebabe0001e2400000b26e10000000abababababababababababababababab",
         "920f123bdecafbadcafebabecbf24c124330e1c8c2de0000599dd45bc9d687b603e8b59d771fd38e88b170e0cd31e125eabe"}
    ].

gcm() ->
    [
        {"A.2.1", "900f1235decafbadcafebabebede000151000200abababababababababababababababab",
         "900f1235decafbadcafebabec0de000139972dc9572c4d99e8fc355de743fb2e94f9d8ff54e72f4193bbc5c74ffab0fa9fa0fbeb"},
        {"A.2.2", "900f1236decafbadcafebabe1000000105020002abababababababababababababababab",
         "900f1236decafbadcafebabec2de0001bb75a4c545cd1f413bdb7daa2b1e3263de313667c963249081b35a65f5cb6c88b394235f"},
        {"A.2.3", "920f1238decafbadcafebabe0001e2400000b26ebede000151000200abababababababababababababababab",
         "920f1238decafbadcafebabe63bbccc4a7f695c4c0de00018ad7c71fac70a80c92866b4c6ba98546ef913586e95ffaaffe956885bb0647a8bc094ac8"},
        {"A.2.4", "920f1239decafbadcafebabe0001e2400000b26e1000000105020002abababababababababababababababab",
         "920f1239decafbadcafebabe3680524f8d312b00c2de0001c78d120038422bc111a7187a18246f980c059cc6bc9df8b626394eca344e4b05d80fea83"},
        {"A.2.5", "920f123adecafbadcafebabe0001e2400000b26ebede0000abababababababababababababababab",
         "920f123adecafbadcafebabe15b6bb4337906fffc0de0000b7b964537a2b03ab7ba5389ce93317126b5d974df30c6884dcb651c5e120c1da"},
        {"A.2.6", "920f123bdecafbadcafebabe0001e2400000b26e10000000abababababababababababababababab",
         "920f123bdecafbadcafebabedcb38c9e48bf95f4c2de000061ee432cf920317076613258d3ce4236c06ac429681ad08413512dc98b5207d8"}
    ].

contexts(cm) ->
    {webrtc_srtp:new(srtp_aes128_cm_hmac_sha1_80, h("e1f97a0d3e018be0d64fa32c06de4139"), h("0ec675ad498afeebb6960b3aabe6"), #{cryptex => true}),
     webrtc_srtp:new(srtp_aes128_cm_hmac_sha1_80, h("e1f97a0d3e018be0d64fa32c06de4139"), h("0ec675ad498afeebb6960b3aabe6"), #{})};
contexts(gcm) ->
    {webrtc_srtp:new(srtp_aead_aes_128_gcm, h("000102030405060708090a0b0c0d0e0f"), h("a0a1a2a3a4a5a6a7a8a9aaab"), #{cryptex => true}),
     webrtc_srtp:new(srtp_aead_aes_128_gcm, h("000102030405060708090a0b0c0d0e0f"), h("a0a1a2a3a4a5a6a7a8a9aaab"), #{})}.

vectors_test_() ->
    [{Name, ?_test(check(T, Plain, Cipher))} || {T, Vs} <- [{cm, cm()}, {gcm, gcm()}], {Name, Plain, Cipher} <- Vs].

check(T, Plain, Cipher) ->
    {Tx, Rx} = contexts(T),
    ?assertMatch({ok, _, _}, webrtc_srtp:protect_rtp(h(Plain), Tx)),
    {ok, Out, _} = webrtc_srtp:protect_rtp(h(Plain), Tx),
    ?assertEqual(h(Cipher), Out),
    % The receiver needs no option to recognise cryptex.
    ?assertMatch({ok, _, _}, webrtc_srtp:unprotect_rtp(h(Cipher), Rx)),
    {ok, Back, _} = webrtc_srtp:unprotect_rtp(h(Cipher), Rx),
    ?assertEqual(h(Plain), Back).

% A tampered extension header fails authentication.
tampered_test() ->
    {_, Rx} = contexts(gcm),
    [{_, _, Cipher} | _] = gcm(),
    <<Head:12/binary, _:16, Rest/binary>> = h(Cipher),
    ?assertMatch({error, _}, webrtc_srtp:unprotect_rtp(<<Head/binary, 16#C2DE:16, Rest/binary>>, Rx)).

% Without CSRCs or extensions the packet is plain SRTP.
plain_packet_test() ->
    {Tx, Rx} = contexts(cm),
    Pkt = <<16#80, 15, 0, 1, 0:32, 1:32, "payload">>,
    {ok, Out, _} = webrtc_srtp:protect_rtp(Pkt, Tx),
    {ok, Pkt, _} = webrtc_srtp:unprotect_rtp(Out, Rx),
    {ok, Out, _} = webrtc_srtp:protect_rtp(Pkt, webrtc_srtp:set_cryptex(false, Tx)).

%% A plain packet with a profile reserved for cryptex would be misread
%% by the receiver: refused.
reserved_profile_test() ->
    {_, Tx} = contexts(cm),
    Pkt = <<16#90, 15, 0, 1, 0:32, 1:32, 16#C0DE:16, 0:16, "payload">>,
    ?assertEqual({error, malformed}, webrtc_srtp:protect_rtp(Pkt, Tx)).
