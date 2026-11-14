%% @private DTLS 1.3 handshake (RFC 9147 §5, RFC 8446 §4), client side
%% and the helpers shared with `webrtc_dtls13_server'. Full handshake
%% with (EC)DHE and certificates only: no PSK, no resumption, no 0-RTT.
%%
%% ```
%% client                                         server
%% ClientHello (+key_share, supported_versions) -->
%%                                  <--  HelloRetryRequest (+cookie)
%% ClientHello (+cookie)                        -->
%%                                               ServerHello
%%                                               {EncryptedExtensions}
%%                                               {CertificateRequest}
%%                                               {Certificate}
%%                                               {CertificateVerify}
%%                                  <--          {Finished}
%% {Certificate} {CertificateVerify} {Finished} -->
%%                                  <--          [ACK]
%% '''
%%
%% The transcript holds TLS 1.3 style messages, without the DTLS
%% message_seq and fragment fields (RFC 9147 §5.2).
-module(webrtc_dtls13_hs).

-include("webrtc_dtls.hrl").

-export([
    offers13/1,
    client_hello_parts/1,
    client_server_hello/3,
    handle/5,
    final_flight_acked/1
]).

%% Shared with webrtc_dtls13_server.
-export([
    add/2,
    transcript_hash/1,
    prefix_hash/1,
    install_handshake_keys/2,
    derive_application/1,
    queue/3,
    certificate_body/2,
    certificate_verify_body/3,
    finished_body/2,
    verify_finished/3,
    verify_certificate_verify/3,
    peer_certificate/2,
    choose_scheme/2,
    offered_schemes/0
]).

-import(webrtc_dtls, [fail/3]).

-define(EXT_SUPPORTED_GROUPS, supported_groups).
-define(EXT_USE_SRTP, use_srtp).

%%====================================================================
%% ClientHello
%%====================================================================

%% @doc True when the client offers DTLS 1.3.
-spec offers13(#dtls{}) -> boolean().
offers13(#dtls{versions = Vs, suites13 = S13}) ->
    lists:member(dtls13, Vs) andalso S13 =/= [].

%% @doc Suites and extensions the ClientHello adds for DTLS 1.3, given
%% the key share stored in the state.
-spec client_hello_parts(#dtls{}) -> {[0..16#FFFF], [{non_neg_integer(), binary()}]}.
client_hello_parts(#dtls{kx = {Group, Pub, _}, versions = Vs, suites13 = S13, cookie13 = Cookie}) ->
    Versions = [?DTLS13 || lists:member(dtls13, Vs)] ++ [?DTLS12 || lists:member(dtls12, Vs)],
    Exts =
        [
            webrtc_dtls13_msg:supported_versions_ext(Versions),
            webrtc_dtls13_msg:key_share_ext([{webrtc_dtls_crypto:group_id(Group), Pub}])
        ] ++ [webrtc_dtls13_msg:cookie_ext(Cookie) || Cookie =/= undefined],
    {S13, Exts};
client_hello_parts(_) ->
    {[], []}.

%%====================================================================
%% ServerHello and HelloRetryRequest
%%====================================================================

%% @doc A ServerHello selecting DTLS 1.3 (or a HelloRetryRequest).
%% `SHBody' is the message body as received.
-spec client_server_hello(map(), binary(), #dtls{}) -> #dtls{}.
client_server_hello(M, SHBody, St) ->
    #{version := V, random := SR, session_id := Sid, suite := SuiteId, compression := Comp, extensions := Exts} = M,
    V =:= ?DTLS12 orelse fail(?ALERT_PROTOCOL_VERSION, {bad_legacy_version, V}, St),
    Comp =:= 0 orelse fail(?ALERT_ILLEGAL_PARAMETER, bad_compression, St),
    %% RFC 9147 §5 and erratum 8066: legacy_session_id_echo is empty.
    Sid =:= <<>> orelse fail(?ALERT_ILLEGAL_PARAMETER, bad_session_id_echo, St),
    lists:member(SuiteId, St#dtls.suites13) orelse fail(?ALERT_ILLEGAL_PARAMETER, bad_suite, St),
    case webrtc_dtls13_msg:ext(server_hello, supported_versions, Exts) of
        {ok, ?DTLS13} -> ok;
        _ -> fail(?ALERT_ILLEGAL_PARAMETER, bad_supported_versions, St)
    end,
    {ok, Suite} = webrtc_dtls13_keys:suite(SuiteId),
    case SR =:= webrtc_dtls13_keys:hrr_random() of
        true -> hello_retry(Suite, Exts, SHBody, St);
        false -> server_hello(Suite, SR, Exts, SHBody, St)
    end.

hello_retry(_Suite, _Exts, _Body, #dtls{hrr = true} = St) ->
    %% RFC 8446 §4.1.4.
    fail(?ALERT_UNEXPECTED_MESSAGE, second_hello_retry_request, St);
hello_retry(#{hash := H} = Suite, Exts, Body, St) ->
    only_extensions([43, 44, 51], Exts, St),
    Cookie =
        case webrtc_dtls13_msg:ext(hello_retry_request, cookie, Exts) of
            undefined -> undefined;
            {ok, C} -> C;
            {error, _} -> fail(?ALERT_DECODE_ERROR, bad_cookie, St)
        end,
    {Group0, _, _} = St#dtls.kx,
    Kx =
        case webrtc_dtls13_msg:ext(hello_retry_request, key_share, Exts) of
            undefined ->
                St#dtls.kx;
            {ok, Id} ->
                G = webrtc_dtls_crypto:group_name(Id),
                %% The group must be one we offered and not the one we
                %% already sent a share for.
                (lists:member(G, St#dtls.groups) andalso G =/= Group0) orelse
                    fail(?ALERT_ILLEGAL_PARAMETER, bad_hrr_group, St),
                {Pub, Priv} = webrtc_dtls_crypto:generate_ecdhe(G),
                {G, Pub, Priv};
            {error, _} ->
                fail(?ALERT_DECODE_ERROR, bad_key_share, St)
        end,
    (Cookie =/= undefined orelse Kx =/= St#dtls.kx) orelse
        fail(?ALERT_ILLEGAL_PARAMETER, hrr_without_change, St),
    CH1 = client_hello_msg(St),
    Transcript = [webrtc_dtls13_msg:transcript_msg(server_hello, Body), webrtc_dtls13_msg:message_hash(crypto:hash(H, CH1))],
    St1 = webrtc_dtls13:implicit_ack(St#dtls{
        version = dtls13,
        hrr = true,
        suite13 = Suite,
        cookie13 = Cookie,
        kx = Kx,
        transcript = Transcript
    }),
    send_client_hello2(St1).

%% The ClientHello in the transcript, as a TLS 1.3 style message.
client_hello_msg(#dtls{transcript = T}) ->
    <<_:12/binary, Body/binary>> = lists:last(T),
    webrtc_dtls13_msg:transcript_msg(client_hello, Body).

send_client_hello2(St) ->
    Body = webrtc_dtls_hs:client_hello_body(St),
    queue(client_hello, Body, St).

server_hello(#{hash := H} = Suite, SR, Exts, Body, St) ->
    case St#dtls.suite13 of
        undefined -> ok;
        Suite -> ok;
        _ -> fail(?ALERT_ILLEGAL_PARAMETER, suite_changed_after_hrr, St)
    end,
    only_extensions([43, 51], Exts, St),
    {Group, _, Priv} = St#dtls.kx,
    PeerPub =
        case webrtc_dtls13_msg:ext(server_hello, key_share, Exts) of
            {ok, {Id, K}} ->
                Id =:= webrtc_dtls_crypto:group_id(Group) orelse fail(?ALERT_ILLEGAL_PARAMETER, bad_key_share_group, St),
                K;
            undefined ->
                fail(?ALERT_MISSING_EXTENSION, missing_key_share, St);
            {error, _} ->
                fail(?ALERT_DECODE_ERROR, bad_key_share, St)
        end,
    Shared =
        case webrtc_dtls_crypto:ecdhe_shared(Group, PeerPub, Priv) of
            {ok, S} -> S;
            {error, _} -> fail(?ALERT_ILLEGAL_PARAMETER, bad_ecdhe_point, St)
        end,
    T0 =
        case St#dtls.hrr of
            true -> St#dtls.transcript;
            false -> [client_hello_msg(St)]
        end,
    St1 = add(webrtc_dtls13_msg:transcript_msg(server_hello, Body), St#dtls{
        version = dtls13,
        suite13 = Suite,
        group = Group,
        server_random = SR,
        kx = undefined,
        transcript = T0
    }),
    HS = webrtc_dtls13_keys:handshake_secret(webrtc_dtls13_keys:prefix(), H, Shared),
    St2 = install_handshake_keys(HS, St1),
    webrtc_dtls13:implicit_ack(St2#dtls{state = wait_ee}).

only_extensions(Allowed, Exts, St) ->
    [fail(?ALERT_UNSUPPORTED_EXTENSION, {unsolicited_extension, T}, St) || {T, _} <- Exts, not lists:member(T, Allowed)],
    ok.

%%====================================================================
%% Encrypted handshake messages
%%====================================================================

%% @doc A complete DTLS 1.3 handshake message received in `Epoch'.
-spec handle(webrtc_dtls_msg:msg_type(), binary(), non_neg_integer(), integer(), #dtls{}) -> #dtls{}.
handle(server_hello, Body, 0, _Now, #dtls{role = client, state = wait_server_hello} = St) ->
    case webrtc_dtls_msg:decode_body(server_hello, Body) of
        {ok, M} -> client_server_hello(M, Body, St);
        {error, _} -> fail(?ALERT_DECODE_ERROR, {decode_error, server_hello}, St)
    end;
handle(Type, Body, Epoch, Now, St) ->
    case webrtc_dtls13_msg:decode(Type, Body) of
        {ok, Msg0} ->
            check_epoch(Epoch, St),
            %% A KeyUpdate is tied to the epoch it was received in.
            Msg =
                case Type of
                    key_update -> {Msg0, Epoch};
                    _ -> Msg0
                end,
            Full = webrtc_dtls13_msg:transcript_msg(Type, Body),
            case St#dtls.role of
                client -> client(St#dtls.state, Type, Msg, Full, Now, St);
                server -> webrtc_dtls13_server:handle(St#dtls.state, Type, Msg, Full, Now, St)
            end;
        {error, _} ->
            %% A message type without a place in DTLS 1.3 here (a late
            %% ClientHello, an unknown type) is unexpected.
            case webrtc_dtls13_msg:known(Type) of
                true -> fail(?ALERT_DECODE_ERROR, {decode_error, Type}, St);
                false -> fail(?ALERT_UNEXPECTED_MESSAGE, {unexpected_message, Type}, St)
            end
    end.

%% Handshake messages use epoch 2, post-handshake messages epoch 3 or
%% later (RFC 9147 §6.1).
check_epoch(Epoch, #dtls{state = S} = St) ->
    Post = S =:= connected orelse S =:= wait_ack,
    ok =
        case {Post, Epoch} of
            {false, 2} -> ok;
            {true, E} when E >= 3 -> ok;
            _ -> fail(?ALERT_UNEXPECTED_MESSAGE, {wrong_epoch, Epoch}, St)
        end.

client(wait_ee, encrypted_extensions, Exts, Full, _Now, St) ->
    only_extensions([?EXT_SUPPORTED_GROUPS, ?EXT_USE_SRTP], Exts, St),
    Profile =
        case proplists:get_value(use_srtp, Exts) of
            undefined ->
                undefined;
            {[P], _MKI} ->
                %% RFC 5764 §4.1.1: exactly one profile, one we offered.
                lists:member(P, St#dtls.srtp_profiles) orelse fail(?ALERT_ILLEGAL_PARAMETER, bad_srtp_profile, St),
                P;
            _ ->
                fail(?ALERT_ILLEGAL_PARAMETER, bad_use_srtp, St)
        end,
    add(Full, St#dtls{srtp_profile = Profile, state = wait_cert_cr});
client(wait_cert_cr, certificate_request, #{context := Ctx, extensions := Exts}, Full, _Now, St) ->
    Schemes =
        case proplists:get_value(signature_algorithms, Exts) of
            undefined -> fail(?ALERT_MISSING_EXTENSION, missing_signature_algorithms, St);
            L -> L
        end,
    add(Full, St#dtls{cert_requested = true, cr_context = Ctx, peer_schemes = Schemes, state = wait_cert});
client(S, certificate, #{context := Ctx, certs := Certs}, Full, _Now, St) when S =:= wait_cert_cr; S =:= wait_cert ->
    Ctx =:= <<>> orelse fail(?ALERT_ILLEGAL_PARAMETER, bad_certificate_context, St),
    Certs =/= [] orelse fail(?ALERT_DECODE_ERROR, empty_server_certificate, St),
    add(Full, (peer_certificate(Certs, St))#dtls{state = wait_cv});
client(wait_cv, certificate_verify, CV, Full, _Now, St) ->
    verify_certificate_verify(server, CV, St),
    add(Full, St#dtls{cv_ok = true, state = wait_finished});
client(wait_finished, finished, VD, Full, _Now, St) ->
    #{shs := SHS} = St#dtls.secrets,
    verify_finished(SHS, VD, St),
    St1 = derive_application(add(Full, St)),
    #{sap := SAP} = St1#dtls.secrets,
    St2 = webrtc_dtls13_epoch:install_read(3, SAP, St1#dtls{peer_finished = true}),
    St3 =
        case St2#dtls.cert_requested of
            true ->
                S1 = queue(certificate, certificate_body(St2#dtls.cr_context, St2), St2),
                queue(certificate_verify, certificate_verify_body(client, St2#dtls.peer_schemes, S1), S1);
            false ->
                St2
        end,
    #{chs := CHS, cap := CAP} = St3#dtls.secrets,
    St4 = queue(finished, finished_body(CHS, St3), St3),
    %% Application data uses epoch 3 once our Finished is sent.
    webrtc_dtls13_epoch:install_write(3, CAP, St4#dtls{state = wait_ack});
client(S, new_session_ticket, _M, _Full, _Now, St) when S =:= wait_ack; S =:= connected ->
    %% No resumption: the ticket is acknowledged and dropped. The server
    %% only sends it after our Finished, so it also confirms our flight.
    St1 = maybe_final(St),
    St1#dtls{ack_now = true};
client(S, key_update, Req, _Full, _Now, St) when S =:= wait_ack; S =:= connected ->
    webrtc_dtls13_epoch:peer_key_update(Req, maybe_final(St));
client(_State, Type, _M, _Full, _Now, St) ->
    fail(?ALERT_UNEXPECTED_MESSAGE, {unexpected_message, Type}, St).

maybe_final(#dtls{state = wait_ack} = St) -> final_flight_acked(webrtc_dtls13:implicit_ack(St));
maybe_final(St) -> St.

%% @doc The server acknowledged our final flight: the handshake is
%% complete on both sides (RFC 9147 §5.7 note 1).
-spec final_flight_acked(#dtls{}) -> #dtls{}.
final_flight_acked(#dtls{state = wait_ack} = St) ->
    webrtc_dtls_hs:maybe_verify(St#dtls{state = connected, handshake_done = true, rtx_at = infinity});
final_flight_acked(St) ->
    St.

%%====================================================================
%% Shared helpers
%%====================================================================

%% @doc Append a TLS 1.3 style message to the transcript.
-spec add(binary(), #dtls{}) -> #dtls{}.
add(Msg, #dtls{transcript = T} = St) ->
    St#dtls{transcript = [Msg | T]}.

-spec transcript_hash(#dtls{}) -> binary().
transcript_hash(#dtls{suite13 = #{hash := H}, transcript = T}) ->
    crypto:hash(H, lists:reverse(T)).

-spec prefix_hash(#dtls{}) -> {binary(), sha256 | sha384}.
prefix_hash(#dtls{suite13 = #{hash := H}}) ->
    {webrtc_dtls13_keys:prefix(), H}.

%% @doc Handshake traffic secrets from the transcript up to ServerHello,
%% read and write keys for epoch 2.
-spec install_handshake_keys(binary(), #dtls{}) -> #dtls{}.
install_handshake_keys(HS, St) ->
    {P, H} = prefix_hash(St),
    TH = transcript_hash(St),
    CHS = webrtc_dtls13_keys:derive_secret(P, H, HS, <<"c hs traffic">>, TH),
    SHS = webrtc_dtls13_keys:derive_secret(P, H, HS, <<"s hs traffic">>, TH),
    {Mine, Theirs} =
        case St#dtls.role of
            client -> {CHS, SHS};
            server -> {SHS, CHS}
        end,
    St1 = St#dtls{secrets = #{hs => HS, chs => CHS, shs => SHS}},
    St2 = webrtc_dtls13_epoch:install_read(2, Theirs, St1),
    webrtc_dtls13_epoch:install_write(2, Mine, St2).

%% @doc Application traffic and exporter secrets from the transcript
%% up to the server Finished (RFC 8446 §7.1).
-spec derive_application(#dtls{}) -> #dtls{}.
derive_application(#dtls{secrets = #{hs := HS} = Secrets} = St) ->
    {P, H} = prefix_hash(St),
    TH = transcript_hash(St),
    MS = webrtc_dtls13_keys:master_secret(P, H, HS),
    St#dtls{
        secrets = Secrets#{
            cap => webrtc_dtls13_keys:derive_secret(P, H, MS, <<"c ap traffic">>, TH),
            sap => webrtc_dtls13_keys:derive_secret(P, H, MS, <<"s ap traffic">>, TH)
        },
        exporter = webrtc_dtls13_keys:derive_secret(P, H, MS, <<"exp master">>, TH)
    }.

%% @doc Queue a handshake message of the flight being built and add it
%% to the transcript.
-spec queue(webrtc_dtls_msg:msg_type(), binary(), #dtls{}) -> #dtls{}.
queue(Type, Body, St) ->
    {_, St1} = webrtc_dtls:queue_handshake(Type, Body, false, St),
    add(webrtc_dtls13_msg:transcript_msg(Type, Body), St1).

-spec certificate_body(binary(), #dtls{}) -> binary().
certificate_body(Ctx, St) ->
    webrtc_dtls13_msg:encode(certificate, #{context => Ctx, certs => [St#dtls.cert_der]}).

-spec certificate_verify_body(client | server, [0..16#FFFF], #dtls{}) -> binary().
certificate_verify_body(Role, PeerSchemes, St) ->
    Scheme = choose_scheme(PeerSchemes, St),
    Content = webrtc_dtls13_keys:cv_content(Role, transcript_hash(St)),
    Sig = webrtc_dtls_crypto:sign(Scheme, Content, St#dtls.key),
    webrtc_dtls13_msg:encode(certificate_verify, #{scheme => webrtc_dtls_crypto:sig_scheme_id(Scheme), signature => Sig}).

-spec finished_body(binary(), #dtls{}) -> binary().
finished_body(BaseKey, St) ->
    {P, H} = prefix_hash(St),
    webrtc_dtls13_keys:finished(P, H, BaseKey, transcript_hash(St)).

-spec verify_finished(binary(), binary(), #dtls{}) -> ok.
verify_finished(BaseKey, VD, St) ->
    Expected = finished_body(BaseKey, St),
    (byte_size(VD) =:= byte_size(Expected) andalso crypto:hash_equals(Expected, VD)) orelse
        fail(?ALERT_DECRYPT_ERROR, bad_finished, St),
    ok.

%% @doc Verify the peer's CertificateVerify (RFC 8446 §4.4.3). The
%% scheme must be one we offered and usable in TLS 1.3, and an ECDSA
%% scheme must match the curve of the certificate key (§4.2.3).
-spec verify_certificate_verify(client | server, map(), #dtls{}) -> ok.
verify_certificate_verify(PeerRole, #{scheme := Id, signature := Sig}, St) ->
    Scheme = webrtc_dtls_crypto:sig_scheme_name(Id),
    lists:member(Scheme, offered_schemes()) orelse fail(?ALERT_ILLEGAL_PARAMETER, {bad_signature_scheme, Id}, St),
    curve_matches(Scheme, St#dtls.peer_key) orelse fail(?ALERT_ILLEGAL_PARAMETER, signature_curve_mismatch, St),
    Content = webrtc_dtls13_keys:cv_content(PeerRole, transcript_hash(St)),
    webrtc_dtls_crypto:verify(Scheme, Content, Sig, St#dtls.peer_key) orelse
        fail(?ALERT_DECRYPT_ERROR, bad_certificate_verify, St),
    ok.

curve_matches(ecdsa_secp256r1_sha256, {ecdsa, {_, {namedCurve, C}}}) -> C =:= {1, 2, 840, 10045, 3, 1, 7};
curve_matches(ecdsa_secp384r1_sha384, {ecdsa, {_, {namedCurve, C}}}) -> C =:= {1, 3, 132, 0, 34};
curve_matches(ed25519, {eddsa, _}) -> true;
curve_matches(rsa_pss_rsae_sha256, {rsa, _}) -> true;
curve_matches(_, _) -> false.

%% @doc Signature schemes usable for CertificateVerify in TLS 1.3:
%% RSASSA-PKCS1-v1_5 is excluded (RFC 8446 §4.2.3).
-spec offered_schemes() -> [webrtc_dtls_crypto:sig_scheme()].
offered_schemes() ->
    [S || S <- webrtc_dtls_crypto:signature_schemes(), S =/= rsa_pkcs1_sha256].

-spec choose_scheme([0..16#FFFF], #dtls{}) -> webrtc_dtls_crypto:sig_scheme().
choose_scheme(PeerIds, St) ->
    Mine = [S || S <- webrtc_dtls_crypto:scheme_for_key(St#dtls.key), S =/= rsa_pkcs1_sha256],
    case [S || S <- Mine, lists:member(webrtc_dtls_crypto:sig_scheme_id(S), PeerIds)] of
        [S | _] -> S;
        [] -> fail(?ALERT_HANDSHAKE_FAILURE, no_common_signature_scheme, St)
    end.

%% @doc Store the peer certificate and check its fingerprint, as for
%% DTLS 1.2 (RFC 8122 §5).
-spec peer_certificate([binary()], #dtls{}) -> #dtls{}.
peer_certificate([Der | _], St) ->
    case webrtc_dtls_cert:public_key(Der) of
        {ok, Key} -> webrtc_dtls_hs:check_fingerprint(St#dtls{peer_cert = Der, peer_key = Key});
        {error, Reason} -> fail(?ALERT_BAD_CERTIFICATE, Reason, St)
    end.
