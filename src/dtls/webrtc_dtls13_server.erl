%% @private DTLS 1.3 handshake, server side (RFC 9147 §5, RFC 8446 §4).
%%
%% The HelloRetryRequest is stateless (RFC 9147 §5.1): the cookie
%% carries the hash of the first ClientHello and the parameters chosen
%% for it, authenticated with an HMAC under a per-endpoint secret and
%% bounded in age. Nothing is kept between the HelloRetryRequest and
%% the second ClientHello.
-module(webrtc_dtls13_server).

-include("webrtc_dtls.hrl").

-export([client_hello/4, handle/6, make_cookie/5, open_cookie/3]).

-import(webrtc_dtls, [fail/3]).
-import(webrtc_dtls13_hs, [add/2, queue/3]).

-define(COOKIE_VERSION, 1).

%%====================================================================
%% ClientHello
%%====================================================================

%% @doc A ClientHello that offers DTLS 1.3, which we selected.
-spec client_hello(map(), binary(), integer(), #dtls{}) -> #dtls{}.
client_hello(M0, Body, Now, St) ->
    %% The body as received: the PSK binder covers it (RFC 8446 §4.2.11.2).
    M = M0#{raw => Body},
    #{random := CR, cookie := Legacy, suites := Suites, compression := Comp, extensions := Exts} = M,
    %% RFC 9147 §5.3: a DTLS 1.3 ClientHello has an empty legacy_cookie.
    Legacy =:= <<>> orelse fail(?ALERT_ILLEGAL_PARAMETER, legacy_cookie_not_empty, St),
    %% RFC 8446 §4.1.2: exactly the null compression method.
    Comp =:= [0] orelse fail(?ALERT_ILLEGAL_PARAMETER, bad_compression, St),
    SuiteId =
        case [S || S <- St#dtls.suites13, lists:member(S, Suites)] of
            [S0 | _] -> S0;
            [] -> fail(?ALERT_HANDSHAKE_FAILURE, no_common_suite, St)
        end,
    {ok, #{hash := H} = Suite} = webrtc_dtls13_keys:suite(SuiteId),
    Schemes =
        case proplists:get_value(signature_algorithms, Exts) of
            undefined -> fail(?ALERT_MISSING_EXTENSION, missing_signature_algorithms, St);
            Ss -> Ss
        end,
    _ = webrtc_dtls13_hs:choose_scheme(Schemes, St),
    ClientGroups =
        case proplists:get_value(supported_groups, Exts) of
            undefined -> fail(?ALERT_MISSING_EXTENSION, missing_supported_groups, St);
            Gs -> [webrtc_dtls_crypto:group_name(G) || G <- Gs]
        end,
    Shares =
        case webrtc_dtls13_msg:ext(client_hello, key_share, Exts) of
            {ok, L} -> [{webrtc_dtls_crypto:group_name(G), K} || {G, K} <- L];
            undefined -> fail(?ALERT_MISSING_EXTENSION, missing_key_share, St);
            {error, _} -> fail(?ALERT_DECODE_ERROR, bad_key_share, St)
        end,
    Usable = [G || G <- St#dtls.groups, lists:keymember(G, 1, Shares)],
    Selected =
        case {Usable, [G || G <- St#dtls.groups, lists:member(G, ClientGroups)]} of
            {[G1 | _], _} -> {share, G1};
            {[], [G2 | _]} -> {retry, G2};
            {[], []} -> fail(?ALERT_HANDSHAKE_FAILURE, no_common_group, St)
        end,
    CH = webrtc_dtls13_msg:transcript_msg(client_hello, Body),
    case webrtc_dtls13_msg:ext(client_hello, cookie, Exts) of
        {ok, Cookie} ->
            second_client_hello(Cookie, SuiteId, Selected, Shares, CH, CR, M, Now, St#dtls{suite13 = Suite});
        undefined when element(1, Selected) =:= share, St#dtls.early_data ->
            %% 0-RTT cannot survive a HelloRetryRequest: a ClientHello with
            %% early data on a ticket whose binder verifies (and used for
            %% the first time) skips the cookie exchange.
            {share, Group} = Selected,
            St1 = St#dtls{suite13 = Suite},
            case resume(M, [CH], erlang:system_time(millisecond), St1) of
                #{early := true} = R ->
                    proceed(Group, Shares, [CH], CR, M#{resume => R}, St1);
                R when not St#dtls.use_cookie ->
                    proceed(Group, Shares, [CH], CR, M#{resume => R}, St1);
                _ ->
                    Cookie = make_cookie(SuiteId, {false, Group}, crypto:hash(H, CH), Now, St),
                    hello_retry(SuiteId, false, Group, Cookie, St)
            end;
        undefined when St#dtls.use_cookie; element(1, Selected) =:= retry ->
            Group = element(2, Selected),
            Retry = element(1, Selected) =:= retry,
            Cookie = make_cookie(SuiteId, {Retry, Group}, crypto:hash(H, CH), Now, St),
            hello_retry(SuiteId, Retry, Group, Cookie, St);
        undefined ->
            {share, Group} = Selected,
            proceed(Group, Shares, [CH], CR, M, St#dtls{suite13 = Suite});
        {error, _} ->
            fail(?ALERT_DECODE_ERROR, bad_cookie, St)
    end.

second_client_hello(Cookie, SuiteId, Selected, Shares, CH, CR, M, Now, St) ->
    {CSuite, {Retry, CGroup}, CH1Hash} =
        case open_cookie(Cookie, Now, St) of
            {ok, C} -> C;
            error -> fail(?ALERT_ILLEGAL_PARAMETER, bad_cookie, St)
        end,
    %% The second ClientHello must lead to the parameters of the retry.
    CSuite =:= SuiteId orelse fail(?ALERT_ILLEGAL_PARAMETER, suite_changed_after_hrr, St),
    Group =
        case Selected of
            {share, G} when not Retry; G =:= CGroup -> G;
            _ -> fail(?ALERT_ILLEGAL_PARAMETER, bad_key_share_after_hrr, St)
        end,
    HRR = hrr_body(SuiteId, Retry, CGroup, Cookie),
    T = [
        CH,
        webrtc_dtls13_msg:transcript_msg(server_hello, HRR),
        webrtc_dtls13_msg:message_hash(CH1Hash)
    ],
    proceed(Group, Shares, T, CR, M, St).

%% Stateless HelloRetryRequest; the server stays in wait_client_hello
%% and the message sequence is taken from the ClientHello (§5.2).
hello_retry(SuiteId, Retry, Group, Cookie, St) ->
    Body = hrr_body(SuiteId, Retry, Group, Cookie),
    {_, St1} = webrtc_dtls:queue_handshake(server_hello, Body, false, St#dtls{send_msg_seq = St#dtls.recv_msg_seq - 1}),
    St1#dtls{send_msg_seq = 0}.

hrr_body(SuiteId, Retry, Group, Cookie) ->
    Exts =
        [webrtc_dtls13_msg:selected_version_ext()] ++
            [webrtc_dtls13_msg:hrr_group_ext(webrtc_dtls_crypto:group_id(Group)) || Retry] ++
            [webrtc_dtls13_msg:cookie_ext(Cookie)],
    webrtc_dtls_msg:encode_body(server_hello, #{
        version => ?DTLS12,
        random => webrtc_dtls13_keys:hrr_random(),
        session_id => <<>>,
        suite => SuiteId,
        extensions => Exts
    }).

%% ServerHello and the rest of the server flight.
proceed(Group, Shares, T0, CR, M, #dtls{suite13 = #{id := SuiteId, hash := H}} = St) ->
    #{extensions := Exts} = M,
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
    {_, PeerPub} = lists:keyfind(Group, 1, Shares),
    {Pub, Priv} = webrtc_dtls_crypto:generate_ecdhe(Group),
    Shared =
        case webrtc_dtls_crypto:ecdhe_shared(Group, PeerPub, Priv) of
            {ok, S} -> S;
            {error, _} -> fail(?ALERT_ILLEGAL_PARAMETER, bad_ecdhe_point, St)
        end,
    SR = crypto:strong_rand_bytes(32),
    Resume =
        case M of
            #{resume := R} -> R;
            _ -> resume(M, T0, erlang:system_time(millisecond), St)
        end,
    %% RFC 9147 §9, RFC 9146 §3: when both sides want connection IDs,
    %% ours goes in the ServerHello and the client's in our records.
    PeerCid =
        case {St#dtls.cid, webrtc_dtls13_msg:ext(client_hello, connection_id, Exts)} of
            {Ours, {ok, C}} when is_binary(Ours) -> C;
            {_, {error, _}} -> fail(?ALERT_DECODE_ERROR, bad_connection_id, St);
            _ -> undefined
        end,
    SH = webrtc_dtls_msg:encode_body(server_hello, #{
        version => ?DTLS12,
        random => SR,
        session_id => <<>>,
        suite => SuiteId,
        extensions => [
            webrtc_dtls13_msg:selected_version_ext(),
            webrtc_dtls13_msg:server_share_ext(webrtc_dtls_crypto:group_id(Group), Pub)
        ] ++ [webrtc_dtls13_msg:connection_id_ext(St#dtls.cid) || PeerCid =/= undefined]
          ++ [webrtc_dtls13_msg:server_psk_ext(0) || Resume =/= none]
    }),
    St1 = St#dtls{
        version = dtls13,
        peer_cid = PeerCid,
        client_random = CR,
        server_random = SR,
        group = Group,
        srtp_profile = Profile,
        transcript = T0,
        send_msg_seq = St#dtls.recv_msg_seq - 1,
        cert_requested = true
    },
    St2 = queue(server_hello, SH, St1),
    P = webrtc_dtls13_keys:prefix(),
    Early =
        case Resume of
            none -> webrtc_dtls13_keys:early_secret(P, H);
            #{psk := Psk} -> webrtc_dtls13_keys:early_secret(P, H, Psk)
        end,
    HS = webrtc_dtls13_keys:handshake_secret(P, H, Shared, Early),
    St3 = webrtc_dtls13_hs:install_handshake_keys(HS, St2),
    %% 0-RTT (RFC 8446 §4.2.10): accepted early data is read in epoch 1
    %% with the client early traffic keys.
    {EarlyExt, St3a} =
        case Resume of
            #{early := true} ->
                CES = webrtc_dtls13_keys:client_early_secret(P, H, Early, crypto:hash(H, lists:reverse(T0))),
                {[webrtc_dtls13_msg:early_data_ext()],
                 (webrtc_dtls13_epoch:install_read(1, CES, St3))#dtls{zero_rtt = accepted}};
            _ ->
                {[], St3}
        end,
    St4 = queue(encrypted_extensions, webrtc_dtls13_msg:encode(encrypted_extensions, SrtpExt ++ EarlyExt), St3a),
    case Resume of
        none -> full_flight(Exts, St4);
        #{cert := ClientCert} -> resumed_flight(ClientCert, St4)
    end.

%% A resumed handshake (§2.2): no certificates; the client is the one of
%% the ticket, checked against the current fingerprints.
resumed_flight(ClientCert, St0) ->
    St = webrtc_dtls13_hs:peer_certificate([ClientCert], St0#dtls{resumed = true, cert_requested = false}),
    #{shs := SHS} = St#dtls.secrets,
    St1 = queue(finished, webrtc_dtls13_hs:finished_body(SHS, St), St),
    St2 = webrtc_dtls13_hs:derive_application(St1),
    #{sap := SAP} = St2#dtls.secrets,
    St3 = webrtc_dtls13_epoch:install_write(3, SAP, St2),
    St3#dtls{write_epoch = 2, state = wait_client_finished, cv_ok = true}.

full_flight(Exts, St4) ->
    %% RFC 8827 §6.5: both sides authenticate with certificates.
    Schemes = [webrtc_dtls_crypto:sig_scheme_id(S) || S <- webrtc_dtls13_hs:offered_schemes()],
    CReq = webrtc_dtls13_msg:encode(certificate_request, #{
        context => <<>>, extensions => [{signature_algorithms, Schemes}]
    }),
    St5 = queue(certificate_request, CReq, St4),
    St6 = queue(certificate, webrtc_dtls13_hs:certificate_body(<<>>, St5), St5),
    ClientSchemes = proplists:get_value(signature_algorithms, Exts),
    St7 = queue(certificate_verify, webrtc_dtls13_hs:certificate_verify_body(server, ClientSchemes, St6), St6),
    #{shs := SHS} = St7#dtls.secrets,
    St8 = queue(finished, webrtc_dtls13_hs:finished_body(SHS, St7), St7),
    St9 = webrtc_dtls13_hs:derive_application(St8),
    #{sap := SAP} = St9#dtls.secrets,
    %% Install the epoch 3 write keys; they are used once the client
    %% Finished is verified.
    St10 = webrtc_dtls13_epoch:install_write(3, SAP, St9),
    St10#dtls{write_epoch = 2, state = wait_client_cert}.

%%====================================================================
%% Client flight
%%====================================================================

%% @doc Messages of the client's final flight and post-handshake
%% messages.
-spec handle(atom(), webrtc_dtls_msg:msg_type(), term(), binary(), integer(), #dtls{}) -> #dtls{}.
handle(wait_client_cert, certificate, #{context := Ctx, certs := Certs}, Full, _Now, St0) ->
    %% The client's flight implicitly acknowledges ours.
    St = webrtc_dtls13:implicit_ack(St0),
    Ctx =:= <<>> orelse fail(?ALERT_ILLEGAL_PARAMETER, bad_certificate_context, St),
    %% WebRTC requires mutual authentication (RFC 8827 §6.5).
    Certs =/= [] orelse fail(?ALERT_CERTIFICATE_REQUIRED, certificate_required, St),
    add(Full, (webrtc_dtls13_hs:peer_certificate(Certs, St))#dtls{state = wait_client_cv});
handle(wait_client_cv, certificate_verify, CV, Full, _Now, St) ->
    webrtc_dtls13_hs:verify_certificate_verify(client, CV, St),
    add(Full, St#dtls{cv_ok = true, state = wait_client_finished});
handle(wait_client_finished, finished, VD, Full, _Now, St0) ->
    %% A resumed handshake has no client flight before Finished: it
    %% acknowledges ours.
    St = webrtc_dtls13:implicit_ack(St0),
    #{chs := CHS, cap := CAP} = St#dtls.secrets,
    webrtc_dtls13_hs:verify_finished(CHS, VD, St),
    St1 = webrtc_dtls13_hs:resumption_secret(add(Full, St)),
    St2 = webrtc_dtls13_epoch:install_read(3, CAP, St1#dtls{peer_finished = true}),
    %% The final flight is acknowledged (RFC 9147 §5.7), in epoch 3.
    St3 = St2#dtls{write_epoch = 3, state = connected, handshake_done = true, ack_now = true},
    issue_ticket(webrtc_dtls_hs:maybe_verify(St3));
handle(connected, key_update, Req, _Full, _Now, St) ->
    webrtc_dtls13_epoch:peer_key_update(Req, St);
handle(_State, Type, _M, _Full, _Now, St) ->
    fail(?ALERT_UNEXPECTED_MESSAGE, {unexpected_message, Type}, St).

%%====================================================================
%% Resumption (RFC 8446 §2.2, §4.2.11, §4.6.1)
%%====================================================================

%% The ticket of a ClientHello we resume with, or `none' for a full
%% handshake: its binder verifies, its suite has the selected hash, it
%% is within its lifetime and its client certificate is among the
%% current fingerprints (the certificate binding of RFC 8827 §6.5 holds
%% without certificates). Early data is accepted for a fresh ticket
%% seen for the first time, never after a HelloRetryRequest.
resume(#{extensions := Exts, raw := Body}, T0, Now, #dtls{resumption = true, suite13 = #{hash := H}} = St) ->
    Modes = webrtc_dtls13_msg:ext(client_hello, psk_key_exchange_modes, Exts),
    case {Modes, webrtc_dtls13_msg:ext(client_hello, pre_shared_key, Exts)} of
        {{ok, Ms}, {ok, {[{Ticket, ObfAge} | _], [Binder | _], BL}}} ->
            maybe
                true ?= lists:member(1, Ms),
                {ok, {1, Psk, Id, Issued, AgeAdd, Cert, MaxEarly}} ?= webrtc_dtls_tickets:open(Ticket),
                {ok, #{hash := H}} ?= webrtc_dtls13_keys:suite(Id),
                true ?= Now - Issued < St#dtls.ticket_lifetime * 1000,
                true ?= fingerprint_known(Cert, St),
                P = webrtc_dtls13_keys:prefix(),
                Truncated = binary:part(Body, 0, byte_size(Body) - 2 - BL),
                TH = crypto:hash(H, [lists:reverse(tl(T0)), <<1, (byte_size(Body)):24>>, Truncated]),
                BK = webrtc_dtls13_keys:binder_key(P, H, webrtc_dtls13_keys:early_secret(P, H, Psk)),
                true ?= crypto:hash_equals(webrtc_dtls13_keys:binder(P, H, BK, TH), Binder),
                Age = (ObfAge - AgeAdd) band 16#FFFFFFFF,
                Fresh = abs((Now - Issued) - Age) < 10000,
                Early = St#dtls.early_data andalso MaxEarly > 0 andalso Fresh andalso length(T0) =:= 1 andalso
                    webrtc_dtls13_msg:ext(client_hello, early_data, Exts) =:= {ok, true} andalso
                    webrtc_dtls_tickets:first_use(Ticket, Issued + St#dtls.ticket_lifetime * 1000),
                #{psk => Psk, cert => Cert, early => Early}
            else
                _ -> none
            end;
        _ ->
            none
    end;
resume(_M, _T0, _Now, _St) ->
    none.

fingerprint_known(Der, #dtls{remote_fps = FPs}) when is_list(FPs) ->
    lists:any(fun({Hash, _} = FP) -> webrtc_dtls_cert:fingerprint(Hash, Der) =:= FP end, FPs);
fingerprint_known(_Der, _St) ->
    false.

%% After every handshake, a ticket for the next one (§4.6.1), sealed
%% with the PSK, the suite, the time, age_add, the client certificate
%% and the early data limit.
issue_ticket(#dtls{resumption = true, secrets = #{rms := RMS}, suite13 = #{id := Id, hash := H},
                   peer_cert = Cert, state = connected} = St) when is_binary(Cert) ->
    N = St#dtls.ticket_nonce,
    Nonce = <<N:8>>,
    Psk = webrtc_dtls13_keys:resumption_psk(webrtc_dtls13_keys:prefix(), H, RMS, Nonce),
    <<AgeAdd:32>> = crypto:strong_rand_bytes(4),
    MaxEarly = case St#dtls.early_data of true -> 16384; false -> 0 end,
    Ticket = webrtc_dtls_tickets:seal({1, Psk, Id, erlang:system_time(millisecond), AgeAdd, Cert, MaxEarly}),
    Body = webrtc_dtls13_msg:encode(new_session_ticket, #{
        lifetime => St#dtls.ticket_lifetime, age_add => AgeAdd, nonce => Nonce, ticket => Ticket,
        max_early_data => MaxEarly
    }),
    {_, St1} = webrtc_dtls:queue_handshake(new_session_ticket, Body, false, St#dtls{ticket_nonce = (N + 1) band 255}),
    St1;
issue_ticket(St) ->
    St.

%%====================================================================
%% Stateless cookie
%%====================================================================

%% @doc Cookie = version, suite, retry flag, group, creation time (s),
%% hash of the first ClientHello and an HMAC-SHA256 over all of it.
-spec make_cookie(0..16#FFFF, {boolean(), webrtc_dtls_crypto:group()}, binary(), integer(), #dtls{}) -> binary().
make_cookie(SuiteId, {Retry, Group}, CH1Hash, Now, #dtls{cookie_secret = K}) ->
    Flag =
        case Retry of
            true -> 1;
            false -> 0
        end,
    Data = <<?COOKIE_VERSION, SuiteId:16, Flag, (webrtc_dtls_crypto:group_id(Group)):16,
        (Now div 1000):64/signed, (byte_size(CH1Hash)), CH1Hash/binary>>,
    <<Data/binary, (crypto:mac(hmac, sha256, K, Data))/binary>>.

%% @doc Authenticate a cookie and check its age (cookie_lifetime ms).
-spec open_cookie(binary(), integer(), #dtls{}) ->
    {ok, {0..16#FFFF, {boolean(), webrtc_dtls_crypto:group()}, binary()}} | error.
open_cookie(Cookie, Now, #dtls{cookie_secret = K, cookie_lifetime = Life}) when byte_size(Cookie) > 32 ->
    DLen = byte_size(Cookie) - 32,
    <<Data:DLen/binary, Mac:32/binary>> = Cookie,
    case crypto:hash_equals(crypto:mac(hmac, sha256, K, Data), Mac) of
        true ->
            case Data of
                <<?COOKIE_VERSION, SuiteId:16, Flag, Gid:16, T:64/signed, HL, H:HL/binary>> when
                    Flag =< 1, T * 1000 =< Now + 1000, Now - T * 1000 =< Life
                ->
                    case webrtc_dtls_crypto:group_name(Gid) of
                        unknown -> error;
                        G -> {ok, {SuiteId, {Flag =:= 1, G}, H}}
                    end;
                _ ->
                    error
            end;
        false ->
            error
    end;
open_cookie(_, _, _) ->
    error.
