%% @private DTLS 1.2 handshake logic for both roles (RFC 6347 §4.2,
%% RFC 5246 §7.4), full handshake only: WebRTC endpoints do not resume
%% sessions, and renegotiation is refused.
%%
%% This module also owns the hello exchange that chooses the version
%% (RFC 8446 §4.2.1, RFC 9147 §5.3): the ClientHello offers DTLS 1.3
%% and DTLS 1.2, the server picks DTLS 1.3 when offered, and a client
%% that offered DTLS 1.3 checks the downgrade sentinel (RFC 8446
%% §4.1.3) when DTLS 1.2 is selected. DTLS 1.3 continues in
%% `webrtc_dtls13_hs' and `webrtc_dtls13_server'.
%%
%% Flights (RFC 6347 §4.2.4):
%% ```
%% client                                   server
%% ClientHello                 -------->                         F1
%%                             <-------- HelloVerifyRequest      F2
%% ClientHello (cookie)        -------->                         F3
%%                                       ServerHello             F4
%%                                       Certificate
%%                                       ServerKeyExchange
%%                                       CertificateRequest
%%                             <-------- ServerHelloDone
%% Certificate                                                   F5
%% ClientKeyExchange
%% CertificateVerify
%% [ChangeCipherSpec]
%% Finished                    -------->
%%                                       [ChangeCipherSpec]      F6
%%                             <-------- Finished
%% '''
-module(webrtc_dtls_hs).

-include("webrtc_dtls.hrl").

%% connection_id (RFC 9146 §3).
-define(EXT_CID, 54).

-export([start_client/1, handle/5, maybe_verify/1, check_fingerprint/1, client_hello_body/1]).

-define(SCSV_RENEGOTIATION, 16#00FF).
-define(MAX_HVR, 3).
-define(CERT_TYPE_RSA_SIGN, 1).
-define(CERT_TYPE_ECDSA_SIGN, 64).

-import(webrtc_dtls, [fail/3, queue_handshake/4, queue_ccs/1, emit/2]).

%%====================================================================
%% Client
%%====================================================================

start_client(St) ->
    St1 = St#dtls{client_random = crypto:strong_rand_bytes(32)},
    %% One key share, for our preferred group (RFC 8446 §4.2.8).
    St2 =
        case webrtc_dtls13_hs:offers13(St1) of
            true ->
                [G | _] = St1#dtls.groups,
                {Pub, Priv} = webrtc_dtls_crypto:generate_ecdhe(G),
                webrtc_dtls13_hs:take_ticket(St1#dtls{kx = {G, Pub, Priv}});
            false ->
                St1#dtls{versions = St1#dtls.versions -- [dtls13]}
        end,
    send_client_hello(St2#dtls{state = wait_server_hello}).

send_client_hello(St) ->
    {_, St1} = queue_handshake(client_hello, client_hello_body(St), true, St),
    webrtc_dtls13_hs:client_early_keys(St1).

%% @doc The ClientHello for the versions we offer. A second ClientHello
%% (after HelloVerifyRequest or HelloRetryRequest) only differs by the
%% cookie and, after HelloRetryRequest, the key share.
-spec client_hello_body(#dtls{}) -> binary().
client_hello_body(St) ->
    Offer12 = lists:member(dtls12, St#dtls.versions),
    {Suites13, Exts13} = webrtc_dtls13_hs:client_hello_parts(St),
    Exts =
        [
            {supported_groups, [webrtc_dtls_crypto:group_id(G) || G <- St#dtls.groups]},
            {signature_algorithms, [
                webrtc_dtls_crypto:sig_scheme_id(S)
             || S <- webrtc_dtls_crypto:signature_schemes()
            ]}
        ] ++
            [{ec_point_formats, [0]} || Offer12] ++
            [{extended_master_secret, true} || Offer12] ++
            [{renegotiation_info, <<>>} || Offer12] ++
            srtp_ext(St#dtls.srtp_profiles) ++ Exts13 ++
            %% RFC 9146 §3: with DTLS 1.3 offered the extension is already
            %% among Exts13 (same encoding).
            [webrtc_dtls13_msg:connection_id_ext(St#dtls.cid)
             || is_binary(St#dtls.cid), not lists:member(dtls13, St#dtls.versions)],
    Body = webrtc_dtls_msg:encode_body(client_hello, #{
        version => ?DTLS12,
        random => St#dtls.client_random,
        session_id => <<>>,
        cookie => St#dtls.cookie,
        suites => Suites13 ++ [S || Offer12, S <- St#dtls.suites],
        extensions => Exts
    }),
    webrtc_dtls13_hs:bind_psk(Body, St).

srtp_ext([]) -> [];
srtp_ext(Profiles) -> [{use_srtp, {Profiles, <<>>}}].

%%====================================================================
%% Dispatch
%%====================================================================

handle(Type, Body, Full, Now, St) ->
    case webrtc_dtls_msg:decode_body(Type, Body) of
        {ok, Msg} -> msg(St#dtls.role, St#dtls.state, Type, Msg, Full, Now, St);
        {error, _} -> fail(?ALERT_DECODE_ERROR, {decode_error, Type}, St)
    end.

%% Client side.
msg(client, wait_server_hello, hello_verify_request, #{cookie := C}, _Full, _Now, St) when
    St#dtls.hvr_count < ?MAX_HVR, St#dtls.hrr =:= false
->
    %% RFC 6347 §4.2.1: the first ClientHello and the HelloVerifyRequest
    %% are not part of the transcript.
    send_client_hello(St#dtls{cookie = C, transcript = [], hvr_count = St#dtls.hvr_count + 1});
msg(client, wait_server_hello, server_hello, #{extensions := Exts} = M, Full, _Now, St) ->
    case lists:keymember(43, 1, Exts) of
        true ->
            %% supported_versions: DTLS 1.3 (RFC 8446 §4.2.1).
            lists:member(dtls13, St#dtls.versions) orelse
                fail(?ALERT_UNSUPPORTED_EXTENSION, {unsolicited_extension, 43}, St),
            <<_:12/binary, Body/binary>> = Full,
            webrtc_dtls13_hs:client_server_hello(M, Body, St);
        false ->
            lists:member(dtls12, St#dtls.versions) orelse
                fail(?ALERT_PROTOCOL_VERSION, dtls12_not_enabled, St),
            client_server_hello(M, add(Full, St#dtls{version = dtls12}))
    end;
msg(client, wait_server_hello_done, certificate, Certs, Full, _Now, #dtls{peer_cert = undefined} = St) ->
    peer_certificate(Certs, add(Full, St));
msg(client, wait_server_hello_done, server_key_exchange, M, Full, _Now, St) when
    St#dtls.peer_key =/= undefined, St#dtls.peer_ecdh =:= undefined
->
    server_key_exchange(M, add(Full, St));
msg(client, wait_server_hello_done, certificate_request, M, Full, _Now, St) when
    St#dtls.peer_ecdh =/= undefined, not St#dtls.cert_requested
->
    #{cert_types := _, schemes := Schemes} = M,
    add(Full, St#dtls{cert_requested = true, peer_schemes = Schemes});
msg(client, wait_server_hello_done, server_hello_done, _M, Full, _Now, St) when
    St#dtls.peer_ecdh =/= undefined
->
    client_flight(add(Full, St));
msg(client, wait_server_finished, finished, VD, Full, _Now, St) ->
    check_finished(server, VD, St),
    St1 = add(Full, St),
    maybe_verify(St1#dtls{handshake_done = true, state = connected, rtx_at = infinity});
%% Server side.
msg(server, wait_client_hello, client_hello, M, Full, Now, St) ->
    server_client_hello(M, Full, Now, St);
msg(server, wait_client_finished, certificate, Certs, Full, _Now, St) when
    St#dtls.peer_cert =:= undefined, St#dtls.master =:= undefined
->
    peer_certificate(Certs, add(Full, St));
msg(server, wait_client_finished, client_key_exchange, #{public := Pub}, Full, _Now, St) when
    St#dtls.peer_cert =/= undefined, St#dtls.master =:= undefined
->
    St1 = add(Full, St),
    derive_keys(Pub, St1);
msg(server, wait_client_finished, certificate_verify, M, Full, _Now, St) when
    St#dtls.master =/= undefined, not St#dtls.cv_ok
->
    verify_certificate_verify(M, St),
    add(Full, St#dtls{cv_ok = true});
msg(server, wait_client_finished, finished, VD, Full, _Now, St) when St#dtls.cv_ok ->
    check_finished(client, VD, St),
    St1 = queue_ccs(add(Full, St)),
    #{prf := H} = St1#dtls.suite,
    MyVD = webrtc_dtls_crypto:finished(H, server, St1#dtls.master, transcript_hash(St1)),
    {_, St2} = queue_handshake(finished, webrtc_dtls_msg:encode_body(finished, MyVD), true, St1),
    maybe_verify(St2#dtls{handshake_done = true, state = connected});
%% Renegotiation is not supported (RFC 5746 is only used to signal it).
msg(_, connected, Type, _M, _Full, _Now, St) when Type =:= client_hello; Type =:= hello_request ->
    St;
msg(_Role, _State, Type, _M, _Full, _Now, St) ->
    fail(?ALERT_UNEXPECTED_MESSAGE, {unexpected_message, Type}, St).

add(Full, #dtls{transcript = T} = St) ->
    St#dtls{transcript = [Full | T]}.

transcript(#dtls{transcript = T}) ->
    lists:reverse(T).

transcript_hash(#dtls{suite = #{prf := H}} = St) ->
    crypto:hash(H, transcript(St)).

%%====================================================================
%% Client steps
%%====================================================================

client_server_hello(M, St) ->
    #{version := V, random := SR, suite := SuiteId, compression := Comp, extensions := Exts} = M,
    V =:= ?DTLS12 orelse fail(?ALERT_PROTOCOL_VERSION, {bad_version, V}, St),
    Comp =:= 0 orelse fail(?ALERT_ILLEGAL_PARAMETER, bad_compression, St),
    %% RFC 8446 §4.1.3: a DTLS 1.3 server selecting DTLS 1.2 marks its
    %% random; when we offered DTLS 1.3 this means a downgrade.
    Sentinel = binary:part(SR, 24, 8),
    lists:member(dtls13, St#dtls.versions) andalso
        (crypto:hash_equals(Sentinel, webrtc_dtls13_keys:downgrade12()) orelse
            crypto:hash_equals(Sentinel, webrtc_dtls13_keys:downgrade10())) andalso
        fail(?ALERT_ILLEGAL_PARAMETER, downgrade_detected, St),
    lists:member(SuiteId, St#dtls.suites) orelse fail(?ALERT_ILLEGAL_PARAMETER, bad_suite, St),
    {ok, Suite} = webrtc_dtls_crypto:suite(SuiteId),
    Ems = proplists:get_value(extended_master_secret, Exts, false),
    Ems orelse not St#dtls.require_ems orelse
        fail(?ALERT_HANDSHAKE_FAILURE, extended_master_secret_required, St),
    case proplists:get_value(renegotiation_info, Exts, <<>>) of
        <<>> -> ok;
        _ -> fail(?ALERT_HANDSHAKE_FAILURE, bad_renegotiation_info, St)
    end,
    Profile =
        case proplists:get_value(use_srtp, Exts) of
            undefined ->
                undefined;
            {[P], _MKI} ->
                %% RFC 5764 §4.1.1: exactly one profile, one we offered.
                lists:member(P, St#dtls.srtp_profiles) orelse
                    fail(?ALERT_ILLEGAL_PARAMETER, bad_srtp_profile, St),
                P;
            _ ->
                fail(?ALERT_ILLEGAL_PARAMETER, bad_use_srtp, St)
        end,
    %% RFC 9146 §3: the server's CID, for our records to it.
    PeerCid =
        case proplists:get_value(?EXT_CID, Exts) of
            undefined -> undefined;
            <<L, C:L/binary>> when is_binary(St#dtls.cid) -> C;
            _ when is_binary(St#dtls.cid) -> fail(?ALERT_DECODE_ERROR, bad_connection_id, St);
            _ -> fail(?ALERT_ILLEGAL_PARAMETER, {unsolicited_extension, ?EXT_CID}, St)
        end,
    Known = [supported_groups, ec_point_formats, extended_master_secret, renegotiation_info, use_srtp, ?EXT_CID],
    %% RFC 5246 §7.4.1.4: the server must not send extensions we did not
    %% offer (supported_groups is not sent by servers but tolerated).
    [fail(?ALERT_ILLEGAL_PARAMETER, {unsolicited_extension, T}, St) || {T, _} <- Exts, not lists:member(T, Known)],
    St#dtls{
        peer_cid = PeerCid,
        server_random = SR,
        suite = Suite,
        ems = Ems,
        srtp_profile = Profile,
        state = wait_server_hello_done
    }.

server_key_exchange(#{curve := C, public := Pub, params := Params, scheme := S, signature := Sig}, St) ->
    Group = webrtc_dtls_crypto:group_name(C),
    lists:member(Group, St#dtls.groups) orelse fail(?ALERT_ILLEGAL_PARAMETER, bad_group, St),
    Scheme = offered_scheme(S, St),
    Signed = [St#dtls.client_random, St#dtls.server_random, Params],
    webrtc_dtls_crypto:verify(Scheme, Signed, Sig, St#dtls.peer_key) orelse
        fail(?ALERT_DECRYPT_ERROR, bad_server_key_exchange_signature, St),
    St#dtls{group = Group, peer_ecdh = Pub}.

client_flight(St0) ->
    St1 =
        case St0#dtls.cert_requested of
            true ->
                Body = webrtc_dtls_msg:encode_body(certificate, [St0#dtls.cert_der]),
                element(2, queue_handshake(certificate, Body, true, St0));
            false ->
                St0
        end,
    {Pub, Priv} = webrtc_dtls_crypto:generate_ecdhe(St1#dtls.group),
    CKE = webrtc_dtls_msg:encode_body(client_key_exchange, #{public => Pub}),
    {_, St2} = queue_handshake(client_key_exchange, CKE, true, St1#dtls{ecdh_priv = Priv}),
    St3 = derive_keys(St2#dtls.peer_ecdh, St2),
    St4 =
        case St3#dtls.cert_requested of
            true ->
                Scheme = choose_scheme(St3#dtls.peer_schemes, St3),
                Sig = webrtc_dtls_crypto:sign(Scheme, transcript(St3), St3#dtls.key),
                CV = webrtc_dtls_msg:encode_body(certificate_verify, #{
                    scheme => webrtc_dtls_crypto:sig_scheme_id(Scheme), signature => Sig
                }),
                element(2, queue_handshake(certificate_verify, CV, true, St3));
            false ->
                St3
        end,
    St5 = queue_ccs(St4),
    #{prf := H} = St5#dtls.suite,
    VD = webrtc_dtls_crypto:finished(H, client, St5#dtls.master, transcript_hash(St5)),
    {_, St6} = queue_handshake(finished, webrtc_dtls_msg:encode_body(finished, VD), true, St5),
    St6#dtls{state = wait_server_finished}.

%%====================================================================
%% Server steps
%%====================================================================

server_client_hello(#{extensions := Exts} = M, Full, Now, St) ->
    Offered =
        case webrtc_dtls13_msg:ext(client_hello, supported_versions, Exts) of
            undefined -> legacy;
            {ok, Vs} -> Vs;
            {error, _} -> fail(?ALERT_DECODE_ERROR, bad_supported_versions, St)
        end,
    Mine = St#dtls.versions,
    if
        Offered =/= legacy ->
            %% RFC 8446 §4.2.1: the version comes from supported_versions.
            case lists:member(?DTLS13, Offered) andalso lists:member(dtls13, Mine) of
                true ->
                    <<_:12/binary, Body/binary>> = Full,
                    webrtc_dtls13_server:client_hello(M, Body, Now, St);
                false ->
                    (lists:member(?DTLS12, Offered) andalso lists:member(dtls12, Mine)) orelse
                        fail(?ALERT_PROTOCOL_VERSION, no_common_version, St),
                    server_client_hello12(M, Full, St)
            end;
        true ->
            lists:member(dtls12, Mine) orelse fail(?ALERT_PROTOCOL_VERSION, no_common_version, St),
            server_client_hello12(M, Full, St)
    end.

server_client_hello12(M, Full, St) ->
    #{version := V, random := CR, session_id := Sid, cookie := Cookie, suites := Suites} = M,
    %% DTLS versions count down: 0xFEFD (1.2) < 0xFEFF (1.0).
    V =< ?DTLS12 orelse fail(?ALERT_PROTOCOL_VERSION, {unsupported_version, V}, St),
    Expected = cookie(CR, Sid, Suites, St),
    case St#dtls.use_cookie andalso not crypto:hash_equals(pad32(Cookie), Expected) of
        true ->
            send_hello_verify(Expected, St);
        false ->
            %% A cookie that matches validates the client's address.
            negotiate(M, St#dtls{
                client_random = CR,
                transcript = [Full],
                send_msg_seq = St#dtls.recv_msg_seq - 1,
                addr_valid = St#dtls.addr_valid orelse St#dtls.use_cookie
            })
    end.

pad32(C) when byte_size(C) =:= 32 -> C;
pad32(_) -> <<0:256>>.

cookie(CR, Sid, Suites, #dtls{cookie_secret = K}) ->
    crypto:mac(hmac, sha256, K, [CR, Sid, <<<<S:16>> || S <- Suites>>]).

%% Stateless reply; HelloVerifyRequest always has message_seq 0 and is
%% not part of the transcript.
send_hello_verify(Cookie, St) ->
    Body = webrtc_dtls_msg:encode_body(hello_verify_request, #{version => ?DTLS12, cookie => Cookie}),
    {_, St1} = queue_handshake(hello_verify_request, Body, false, St#dtls{send_msg_seq = 0}),
    St1#dtls{send_msg_seq = 0}.

negotiate(#{suites := Suites, compression := Comp, extensions := Exts}, St) ->
    lists:member(0, Comp) orelse fail(?ALERT_ILLEGAL_PARAMETER, no_null_compression, St),
    SuiteId =
        case [S || S <- St#dtls.suites, lists:member(S, Suites)] of
            [S0 | _] -> S0;
            [] -> fail(?ALERT_HANDSHAKE_FAILURE, no_common_suite, St)
        end,
    {ok, Suite} = webrtc_dtls_crypto:suite(SuiteId),
    ClientSchemes = proplists:get_value(signature_algorithms, Exts, []),
    Scheme = choose_scheme(ClientSchemes, St),
    ClientGroups = [
        webrtc_dtls_crypto:group_name(G)
     || G <- proplists:get_value(supported_groups, Exts, [23])
    ],
    Group =
        case [G || G <- St#dtls.groups, lists:member(G, ClientGroups)] of
            [G0 | _] -> G0;
            [] -> fail(?ALERT_HANDSHAKE_FAILURE, no_common_group, St)
        end,
    case proplists:get_value(ec_point_formats, Exts) of
        undefined -> ok;
        Fmts -> lists:member(0, Fmts) orelse fail(?ALERT_ILLEGAL_PARAMETER, no_uncompressed_point, St)
    end,
    Ems = proplists:get_value(extended_master_secret, Exts, false),
    Ems orelse not St#dtls.require_ems orelse
        fail(?ALERT_HANDSHAKE_FAILURE, extended_master_secret_required, St),
    Secure =
        case proplists:get_value(renegotiation_info, Exts) of
            undefined -> lists:member(?SCSV_RENEGOTIATION, Suites);
            <<>> -> true;
            _ -> fail(?ALERT_HANDSHAKE_FAILURE, bad_renegotiation_info, St)
        end,
    {Profile, SrtpExt} =
        case proplists:get_value(use_srtp, Exts) of
            {Offered, MKI} ->
                case [P || P <- St#dtls.srtp_profiles, lists:member(P, Offered)] of
                    [P0 | _] -> {P0, [{use_srtp, {[P0], MKI}}]};
                    [] -> {undefined, []}
                end;
            undefined ->
                {undefined, []}
        end,
    SR =
        case lists:member(dtls13, St#dtls.versions) of
            %% RFC 8446 §4.1.3 downgrade sentinel.
            true -> <<(crypto:strong_rand_bytes(24))/binary, (webrtc_dtls13_keys:downgrade12())/binary>>;
            false -> crypto:strong_rand_bytes(32)
        end,
    %% RFC 9146 §3: when both want connection IDs, ours goes in the
    %% ServerHello and the client's in our records.
    PeerCid =
        case {St#dtls.cid, proplists:get_value(?EXT_CID, Exts)} of
            {Ours, <<L, C:L/binary>>} when is_binary(Ours) -> C;
            {Ours, Bad} when is_binary(Ours), Bad =/= undefined -> fail(?ALERT_DECODE_ERROR, bad_connection_id, St);
            _ -> undefined
        end,
    Exts1 =
        [{renegotiation_info, <<>>} || Secure] ++
            [{extended_master_secret, true} || Ems] ++
            [{ec_point_formats, [0]} || proplists:is_defined(ec_point_formats, Exts)] ++
            SrtpExt ++
            [webrtc_dtls13_msg:connection_id_ext(St#dtls.cid) || PeerCid =/= undefined],
    SH = webrtc_dtls_msg:encode_body(server_hello, #{
        version => ?DTLS12, random => SR, session_id => <<>>, suite => SuiteId, extensions => Exts1
    }),
    St1 = St#dtls{
        version = dtls12, server_random = SR, suite = Suite, group = Group, ems = Ems, srtp_profile = Profile,
        peer_cid = PeerCid
    },
    {_, St2} = queue_handshake(server_hello, SH, true, St1),
    Cert = webrtc_dtls_msg:encode_body(certificate, [St#dtls.cert_der]),
    {_, St3} = queue_handshake(certificate, Cert, true, St2),
    {Pub, Priv} = webrtc_dtls_crypto:generate_ecdhe(Group),
    Params = <<3, (webrtc_dtls_crypto:group_id(Group)):16, (byte_size(Pub)), Pub/binary>>,
    Sig = webrtc_dtls_crypto:sign(Scheme, [St3#dtls.client_random, SR, Params], St#dtls.key),
    SKE = webrtc_dtls_msg:encode_body(server_key_exchange, #{
        params => Params, scheme => webrtc_dtls_crypto:sig_scheme_id(Scheme), signature => Sig
    }),
    {_, St4} = queue_handshake(server_key_exchange, SKE, true, St3#dtls{ecdh_priv = Priv}),
    %% RFC 8827 §6.5: both sides authenticate with certificates.
    CR = webrtc_dtls_msg:encode_body(certificate_request, #{
        cert_types => [?CERT_TYPE_ECDSA_SIGN, ?CERT_TYPE_RSA_SIGN],
        schemes => [webrtc_dtls_crypto:sig_scheme_id(S) || S <- webrtc_dtls_crypto:signature_schemes()]
    }),
    {_, St5} = queue_handshake(certificate_request, CR, true, St4),
    {_, St6} = queue_handshake(server_hello_done, <<>>, true, St5),
    St6#dtls{state = wait_client_finished, cert_requested = true}.

verify_certificate_verify(#{scheme := S, signature := Sig}, St) ->
    Scheme = offered_scheme(S, St),
    webrtc_dtls_crypto:verify(Scheme, transcript(St), Sig, St#dtls.peer_key) orelse
        fail(?ALERT_DECRYPT_ERROR, bad_certificate_verify, St),
    ok.

%%====================================================================
%% Shared steps
%%====================================================================

peer_certificate([], St) ->
    %% WebRTC requires mutual authentication (RFC 8827 §6.5).
    fail(?ALERT_HANDSHAKE_FAILURE, certificate_required, St);
peer_certificate([Der | _], St) ->
    case webrtc_dtls_cert:public_key(Der) of
        {ok, {Type, _} = Key} ->
            case St#dtls.role of
                client ->
                    #{auth := Auth} = St#dtls.suite,
                    (Auth =:= rsa andalso Type =:= rsa) orelse
                        (Auth =:= ecdsa andalso (Type =:= ecdsa orelse Type =:= eddsa)) orelse
                        fail(?ALERT_UNSUPPORTED_CERTIFICATE, certificate_suite_mismatch, St);
                server ->
                    ok
            end,
            check_fingerprint(St#dtls{peer_cert = Der, peer_key = Key});
        {error, Reason} ->
            fail(?ALERT_BAD_CERTIFICATE, Reason, St)
    end.

%% @doc Check the peer certificate against the remote fingerprints, if
%% known (RFC 8122 §5).
-spec check_fingerprint(#dtls{}) -> #dtls{}.
check_fingerprint(#dtls{remote_fps = undefined} = St) ->
    St;
check_fingerprint(#dtls{remote_fps = FPs, peer_cert = Der} = St) ->
    case webrtc_dtls_cert:matches(Der, FPs) of
        true -> St#dtls{verified = true};
        false -> fail(?ALERT_BAD_CERTIFICATE, fingerprint_mismatch, St)
    end.

%% ECDHE shared secret, master secret (RFC 7627 when negotiated), keys.
derive_keys(PeerPub, St) ->
    PreMaster =
        case webrtc_dtls_crypto:ecdhe_shared(St#dtls.group, PeerPub, St#dtls.ecdh_priv) of
            {ok, S} -> S;
            {error, _} -> fail(?ALERT_ILLEGAL_PARAMETER, bad_ecdhe_point, St)
        end,
    #{prf := H} = Suite = St#dtls.suite,
    Master =
        case St#dtls.ems of
            true ->
                webrtc_dtls_crypto:extended_master_secret(H, PreMaster, transcript_hash(St));
            false ->
                webrtc_dtls_crypto:master_secret(
                    H, PreMaster, St#dtls.client_random, St#dtls.server_random
                )
        end,
    Keys = webrtc_dtls_crypto:key_block(Suite, Master, St#dtls.client_random, St#dtls.server_random),
    webrtc_dtls:install_write(Suite, St#dtls{master = Master, keys = Keys, ecdh_priv = undefined}).

check_finished(PeerRole, VD, #dtls{read_epoch = RE} = St) ->
    RE >= 1 orelse fail(?ALERT_UNEXPECTED_MESSAGE, finished_before_ccs, St),
    #{prf := H} = St#dtls.suite,
    Expected = webrtc_dtls_crypto:finished(H, PeerRole, St#dtls.master, transcript_hash(St)),
    crypto:hash_equals(Expected, VD) orelse fail(?ALERT_DECRYPT_ERROR, bad_finished, St),
    ok.

%% A scheme the peer used must be one we offered, and one we can verify.
offered_scheme(Id, St) ->
    case webrtc_dtls_crypto:sig_scheme_name(Id) of
        unknown -> fail(?ALERT_ILLEGAL_PARAMETER, {bad_signature_scheme, Id}, St);
        S -> S
    end.

%% Pick a scheme for our key among those the peer accepts.
choose_scheme(PeerIds, St) ->
    Mine = webrtc_dtls_crypto:scheme_for_key(St#dtls.key),
    case [S || S <- Mine, lists:member(webrtc_dtls_crypto:sig_scheme_id(S), PeerIds)] of
        [S | _] -> S;
        [] -> fail(?ALERT_HANDSHAKE_FAILURE, no_common_signature_scheme, St)
    end.

%% @doc Announce the connection once the handshake is done and the peer
%% certificate matched the SDP fingerprint; release held data.
maybe_verify(#dtls{peer_cert = undefined} = St) ->
    St;
maybe_verify(#dtls{verified = false, remote_fps = undefined} = St) ->
    St;
maybe_verify(#dtls{verified = false} = St) ->
    maybe_verify(check_fingerprint(St));
maybe_verify(#dtls{verified = true, handshake_done = true, announced = false} = St) ->
    Info = (webrtc_dtls:info(St))#{peer_certificate => St#dtls.peer_cert},
    St1 = emit({connected, Info}, St#dtls{announced = true}),
    Held = lists:reverse(St1#dtls.held),
    lists:foldl(fun(D, S) -> emit({data, D}, S) end, St1#dtls{held = []}, Held);
maybe_verify(St) ->
    St.
