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
client_hello(M, Body, Now, St) ->
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
    SH = webrtc_dtls_msg:encode_body(server_hello, #{
        version => ?DTLS12,
        random => SR,
        session_id => <<>>,
        suite => SuiteId,
        extensions => [
            webrtc_dtls13_msg:selected_version_ext(),
            webrtc_dtls13_msg:server_share_ext(webrtc_dtls_crypto:group_id(Group), Pub)
        ]
    }),
    St1 = St#dtls{
        version = dtls13,
        client_random = CR,
        server_random = SR,
        group = Group,
        srtp_profile = Profile,
        transcript = T0,
        send_msg_seq = St#dtls.recv_msg_seq - 1,
        cert_requested = true
    },
    St2 = queue(server_hello, SH, St1),
    HS = webrtc_dtls13_keys:handshake_secret(webrtc_dtls13_keys:prefix(), H, Shared),
    St3 = webrtc_dtls13_hs:install_handshake_keys(HS, St2),
    St4 = queue(encrypted_extensions, webrtc_dtls13_msg:encode(encrypted_extensions, SrtpExt), St3),
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
    St10 = webrtc_dtls13:install_write(3, SAP, St9),
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
handle(wait_client_finished, finished, VD, Full, _Now, St) ->
    #{chs := CHS, cap := CAP} = St#dtls.secrets,
    webrtc_dtls13_hs:verify_finished(CHS, VD, St),
    St1 = add(Full, St),
    St2 = webrtc_dtls13:install_read(3, CAP, St1#dtls{peer_finished = true}),
    %% The final flight is acknowledged (RFC 9147 §5.7), in epoch 3.
    St3 = St2#dtls{write_epoch = 3, state = connected, handshake_done = true, ack_now = true},
    webrtc_dtls_hs:maybe_verify(St3);
handle(connected, key_update, Req, _Full, _Now, St) ->
    webrtc_dtls13:peer_key_update(Req, St);
handle(_State, Type, _M, _Full, _Now, St) ->
    fail(?ALERT_UNEXPECTED_MESSAGE, {unexpected_message, Type}, St).

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
