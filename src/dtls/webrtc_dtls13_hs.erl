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
    take_ticket/1,
    bind_psk/2,
    client_early_keys/1,
    ticket_key/1,
    resumption_secret/1,
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
client_hello_parts(#dtls{kx = {Group, Pub, _}, versions = Vs, suites13 = S13, cookie13 = Cookie, cid = Cid} = St) ->
    Versions = [?DTLS13 || lists:member(dtls13, Vs)] ++ [?DTLS12 || lists:member(dtls12, Vs)],
    Exts =
        [
            webrtc_dtls13_msg:supported_versions_ext(Versions),
            webrtc_dtls13_msg:key_share_ext([{webrtc_dtls_crypto:group_id(Group), Pub}])
        ] ++ [webrtc_dtls13_msg:cookie_ext(Cookie) || Cookie =/= undefined]
          ++ [webrtc_dtls13_msg:connection_id_ext(Cid) || is_binary(Cid), lists:member(dtls13, Vs)]
          ++ psk_exts(St),
    {S13, Exts};
client_hello_parts(_) ->
    {[], []}.

%%====================================================================
%% Resumption, client side (RFC 8446 §2.2, §4.2.11)
%%====================================================================

%% @doc The ticket stored for this peer (its fingerprints), taken once.
-spec take_ticket(#dtls{}) -> #dtls{}.
take_ticket(#dtls{resumption = true, remote_fps = [_ | _] = FPs, suites13 = S13} = St) ->
    case webrtc_dtls_tickets:take_client(ticket_key(FPs)) of
        {ok, #{suite := Id} = T} ->
            case lists:member(Id, S13) of
                true -> St#dtls{psk = T};
                false -> St
            end;
        error ->
            St
    end;
take_ticket(St) ->
    St.

%% @doc Where tickets for a peer are kept: its fingerprints.
-spec ticket_key([webrtc_dtls_cert:fingerprint()]) -> term().
ticket_key(FPs) ->
    lists:sort(FPs).

%% early_data (when 0-RTT is wanted and allowed), the PSK modes and, as
%% the last extension, pre_shared_key with a zero binder.
psk_exts(#dtls{psk = #{ticket := T, age_add := A, received := R, suite := Id, max_early := M}} = St) ->
    {ok, #{hash := H}} = webrtc_dtls13_keys:suite(Id),
    Age = (erlang:system_time(millisecond) - R + A) band 16#FFFFFFFF,
    Early = St#dtls.early_data andalso M > 0 andalso St#dtls.hrr =:= false,
    [webrtc_dtls13_msg:early_data_ext() || Early] ++
        [webrtc_dtls13_msg:psk_modes_ext(), webrtc_dtls13_msg:client_psk_ext(T, Age, webrtc_dtls13_keys:hash_len(H))];
%% Without a ticket the modes still go out, so the server issues one
%% (RFC 8446 §4.2.9: no NewSessionTicket without them).
psk_exts(#dtls{resumption = true}) ->
    [webrtc_dtls13_msg:psk_modes_ext()];
psk_exts(_) ->
    [].

%% @doc Fill the binder of an encoded ClientHello: the Finished
%% construction over the transcript up to the identities (§4.2.11.2).
-spec bind_psk(binary(), #dtls{}) -> binary().
bind_psk(Body, #dtls{psk = #{psk := Psk, suite := Id}, transcript = T} = St) ->
    {ok, #{hash := H}} = webrtc_dtls13_keys:suite(Id),
    HL = webrtc_dtls13_keys:hash_len(H),
    P = webrtc_dtls13_keys:prefix(),
    Truncated = binary:part(Body, 0, byte_size(Body) - 3 - HL),
    Prior = case St#dtls.hrr of true -> lists:reverse(T); false -> [] end,
    TH = crypto:hash(H, [Prior, <<1, (byte_size(Body)):24>>, Truncated]),
    BK = webrtc_dtls13_keys:binder_key(P, H, webrtc_dtls13_keys:early_secret(P, H, Psk)),
    <<Truncated/binary, (HL + 1):16, HL, (webrtc_dtls13_keys:binder(P, H, BK, TH))/binary>>;
bind_psk(Body, _St) ->
    Body.

%% @doc Once the first ClientHello with early_data is out, early data
%% goes in epoch 1 with the client early traffic keys (RFC 9147 §6.1).
-spec client_early_keys(#dtls{}) -> #dtls{}.
client_early_keys(#dtls{psk = #{psk := Psk, suite := Id, max_early := M}, early_data = true, hrr = false,
                        zero_rtt = undefined} = St) when M > 0 ->
    {ok, #{hash := H} = Suite} = webrtc_dtls13_keys:suite(Id),
    P = webrtc_dtls13_keys:prefix(),
    CES = webrtc_dtls13_keys:client_early_secret(P, H, webrtc_dtls13_keys:early_secret(P, H, Psk),
                                                 crypto:hash(H, client_hello_msg(St))),
    Keys = webrtc_dtls13_keys:traffic_keys(P, Suite, CES),
    St#dtls{zero_rtt = offered, write_ciphers = (St#dtls.write_ciphers)#{1 => Keys},
            write_seq = (St#dtls.write_seq)#{1 => 0}};
client_early_keys(St) ->
    St.

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
        zero_rtt = case St#dtls.zero_rtt of offered -> rejected; Z -> Z end,
        version = dtls13,
        hrr = true,
        suite13 = Suite,
        cookie13 = Cookie,
        kx = Kx,
        transcript = Transcript
    }),
    %% RFC 8446 §4.1.2: no early data after a HelloRetryRequest; what
    %% was sent is lost and the caller resends it.
    St2 = case St#dtls.zero_rtt of offered -> webrtc_dtls:emit(early_data_rejected, St1); _ -> St1 end,
    send_client_hello2(St2).

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
    only_extensions([43, 51] ++ [54 || is_binary(St#dtls.cid)] ++ [41 || St#dtls.psk =/= undefined], Exts, St),
    %% RFC 8446 §4.2.11: the server took our ticket.
    Resumed =
        case {St#dtls.psk, webrtc_dtls13_msg:ext(server_hello, pre_shared_key, Exts)} of
            {#{suite := TId}, {ok, 0}} ->
                {ok, #{hash := TH}} = webrtc_dtls13_keys:suite(TId),
                TH =:= maps:get(hash, Suite) orelse fail(?ALERT_ILLEGAL_PARAMETER, psk_hash_mismatch, St),
                true;
            {_, undefined} ->
                false;
            _ ->
                fail(?ALERT_ILLEGAL_PARAMETER, bad_pre_shared_key, St)
        end,
    %% RFC 9147 §9: the server's connection ID, sent in our records from
    %% the handshake epoch on.
    PeerCid =
        case webrtc_dtls13_msg:ext(server_hello, connection_id, Exts) of
            undefined -> undefined;
            {ok, C} -> C;
            {error, _} -> fail(?ALERT_DECODE_ERROR, bad_connection_id, St)
        end,
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
        resumed = Resumed,
        peer_cid = PeerCid,
        suite13 = Suite,
        group = Group,
        server_random = SR,
        kx = undefined,
        transcript = T0
    }),
    Early =
        case Resumed of
            true -> webrtc_dtls13_keys:early_secret(webrtc_dtls13_keys:prefix(), H, maps:get(psk, St#dtls.psk));
            false -> webrtc_dtls13_keys:early_secret(webrtc_dtls13_keys:prefix(), H)
        end,
    HS = webrtc_dtls13_keys:handshake_secret(webrtc_dtls13_keys:prefix(), H, Shared, Early),
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
            case {Type, St#dtls.role} of
                {T, _} when T =:= new_connection_id; T =:= request_connection_id -> connection_id(T, Msg, St);
                {_, client} -> client(St#dtls.state, Type, Msg, Full, Now, St);
                {_, server} -> webrtc_dtls13_server:handle(St#dtls.state, Type, Msg, Full, Now, St)
            end;
        {error, _} ->
            %% A message type without a place in DTLS 1.3 here (a late
            %% ClientHello, an unknown type) is unexpected.
            case webrtc_dtls13_msg:known(Type) of
                true -> fail(?ALERT_DECODE_ERROR, {decode_error, Type}, St);
                false -> fail(?ALERT_UNEXPECTED_MESSAGE, {unexpected_message, Type}, St)
            end
    end.

%% RFC 9147 §9: without negotiated connection IDs these messages are
%% unexpected; otherwise see webrtc_dtls13_cid.
connection_id(_Type, _Msg, #dtls{peer_cid = undefined} = St) ->
    fail(?ALERT_UNEXPECTED_MESSAGE, connection_id_not_negotiated, St);
connection_id(Type, Msg, St) ->
    webrtc_dtls13_cid:received(Type, Msg, St).

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

client(wait_ee, encrypted_extensions, Exts, Full, _Now, St0) ->
    Offered = St0#dtls.zero_rtt =:= offered,
    only_extensions([?EXT_SUPPORTED_GROUPS, ?EXT_USE_SRTP] ++ [42 || Offered], Exts, St0),
    %% RFC 8446 §4.2.10: early data was accepted when the server echoes
    %% early_data (only possible when it resumed).
    St =
        case {Offered, lists:keymember(42, 1, Exts) andalso St0#dtls.resumed} of
            {true, true} -> St0#dtls{zero_rtt = accepted};
            {true, false} -> webrtc_dtls:emit(early_data_rejected, St0#dtls{zero_rtt = rejected});
            {false, _} -> St0
        end,
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
    case St#dtls.resumed of
        %% A resumed handshake has no certificates (§2.2): the peer is
        %% the certificate of the full handshake the ticket came from,
        %% checked again against the current fingerprints.
        true ->
            St1 = peer_certificate([maps:get(peer_cert, St#dtls.psk)], St),
            add(Full, St1#dtls{srtp_profile = Profile, state = wait_finished, cv_ok = true});
        false ->
            add(Full, St#dtls{srtp_profile = Profile, state = wait_cert_cr})
    end;
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
    St4 = resumption_secret(queue(finished, finished_body(CHS, St3), St3)),
    %% Application data uses epoch 3 once our Finished is sent; early
    %% data ends here (zero_rtt is already accepted or rejected).
    webrtc_dtls13_epoch:install_write(3, CAP, St4#dtls{state = wait_ack});
client(S, new_session_ticket, M, _Full, _Now, St) when S =:= wait_ack; S =:= connected ->
    %% The server only sends it after our Finished, so it also confirms
    %% our flight. Kept for a later resumption with the same peer.
    St1 = maybe_final(St),
    store_ticket(M, St1),
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
            ms => MS,
            cap => webrtc_dtls13_keys:derive_secret(P, H, MS, <<"c ap traffic">>, TH),
            sap => webrtc_dtls13_keys:derive_secret(P, H, MS, <<"s ap traffic">>, TH)
        },
        exporter = webrtc_dtls13_keys:derive_secret(P, H, MS, <<"exp master">>, TH)
    }.

%% @doc resumption_master_secret, once the client Finished is in the
%% transcript (RFC 8446 §7.1).
-spec resumption_secret(#dtls{}) -> #dtls{}.
resumption_secret(#dtls{resumption = true, secrets = #{ms := MS} = Secrets} = St) ->
    {P, H} = prefix_hash(St),
    St#dtls{secrets = Secrets#{rms => webrtc_dtls13_keys:resumption_master_secret(P, H, MS, transcript_hash(St))}};
resumption_secret(St) ->
    St.

store_ticket(#{ticket := T, nonce := N, age_add := A, lifetime := L, max_early_data := M},
             #dtls{resumption = true, secrets = #{rms := RMS}, suite13 = #{id := Id, hash := H},
                   remote_fps = [_ | _] = FPs, peer_cert = Cert}) when is_binary(Cert), L > 0 ->
    Psk = webrtc_dtls13_keys:resumption_psk(webrtc_dtls13_keys:prefix(), H, RMS, N),
    ok = webrtc_dtls_tickets:put_client(ticket_key(FPs), #{
        ticket => T, psk => Psk, suite => Id, age_add => A, lifetime => L, max_early => M,
        received => erlang:system_time(millisecond), peer_cert => Cert
    });
store_ticket(_M, _St) ->
    ok.

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
