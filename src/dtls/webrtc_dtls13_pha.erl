%% @private DTLS 1.3 post-handshake client authentication (RFC 8446
%% §4.6.2, §4.2.6; RFC 9147 §5.8.4).
%%
%% A client created with `post_handshake_auth => true' offers the
%% extension; the server may then ask it for its certificate at any time
%% after the handshake (`webrtc_dtls:request_client_auth/2'). The
%% client answers with Certificate, CertificateVerify and Finished over
%% the handshake transcript followed by the CertificateRequest, the
%% Finished keyed by its current application traffic secret. The
%% certificate must match the remote fingerprints (RFC 8827 §6.5), as
%% in the handshake. One request at a time.
-module(webrtc_dtls13_pha).

-include("webrtc_dtls.hrl").

-export([client_ext/1, offered/1, request/1, client_request/3, server/4]).

-define(EXT_PHA, 49).

%% @doc The extension of a client that accepts it.
-spec client_ext(#dtls{}) -> [{49, binary()}].
client_ext(#dtls{pha = true}) -> [{?EXT_PHA, <<>>}];
client_ext(_) -> [].

%% @doc Whether a ClientHello offered it.
-spec offered([{term(), term()}]) -> boolean().
offered(Exts) -> lists:keymember(?EXT_PHA, 1, Exts).

%% @doc Server: ask for the client's certificate.
-spec request(#dtls{}) -> {ok, #dtls{}} | {error, not_offered | pending}.
request(#dtls{pha = false}) ->
    {error, not_offered};
request(#dtls{pha_state = S}) when S =/= undefined ->
    {error, pending};
request(St) ->
    Ctx = crypto:strong_rand_bytes(8),
    Schemes = [webrtc_dtls_crypto:sig_scheme_id(S) || S <- webrtc_dtls13_hs:offered_schemes()],
    Body = webrtc_dtls13_msg:encode(certificate_request, #{context => Ctx, extensions => [{signature_algorithms, Schemes}]}),
    {_, St1} = webrtc_dtls:queue_handshake(certificate_request, Body, false, St),
    T = [webrtc_dtls13_msg:transcript_msg(certificate_request, Body) | St#dtls.transcript],
    {ok, St1#dtls{pha_state = {wait_cert, Ctx, T}}}.

%% @doc Client: a CertificateRequest after the handshake, `Full' as it
%% goes in the transcript.
-spec client_request(map(), binary(), #dtls{}) -> #dtls{}.
client_request(#{context := Ctx, extensions := Exts}, Full, #dtls{pha = true} = St) when Ctx =/= <<>> ->
    Schemes =
        case proplists:get_value(signature_algorithms, Exts) of
            undefined -> webrtc_dtls:fail(?ALERT_MISSING_EXTENSION, missing_signature_algorithms, St);
            L -> L
        end,
    Base = St#dtls.transcript,
    T0 = [Full | Base],
    Cert = webrtc_dtls13_hs:certificate_body(Ctx, St),
    T1 = [webrtc_dtls13_msg:transcript_msg(certificate, Cert) | T0],
    CV = webrtc_dtls13_hs:certificate_verify_body(client, Schemes, St#dtls{transcript = T1}),
    T2 = [webrtc_dtls13_msg:transcript_msg(certificate_verify, CV) | T1],
    #{secret := Secret} = maps:get(St#dtls.write_epoch, St#dtls.write_ciphers),
    Fin = webrtc_dtls13_hs:finished_body(Secret, St#dtls{transcript = T2}),
    S1 = queue([{certificate, Cert}, {certificate_verify, CV}, {finished, Fin}], St),
    S1#dtls{ack_now = true};
client_request(_M, _Full, St) ->
    %% §4.6.2: not offered, so unexpected.
    webrtc_dtls:fail(?ALERT_UNEXPECTED_MESSAGE, {unexpected_message, certificate_request}, St).

queue(Msgs, St) ->
    lists:foldl(fun({Type, Body}, S) -> {_, S1} = webrtc_dtls:queue_handshake(Type, Body, false, S), S1 end,
                St, Msgs).

%% @doc Server: the client's answer, message by message.
-spec server(atom(), term(), binary(), #dtls{}) -> #dtls{}.
server(certificate, #{context := Ctx, certs := Certs}, Full, #dtls{pha_state = {wait_cert, Ctx, T}} = St) ->
    Certs =/= [] orelse webrtc_dtls:fail(?ALERT_CERTIFICATE_REQUIRED, certificate_required, St),
    St1 = webrtc_dtls13_hs:peer_certificate(Certs, St),
    St1#dtls{pha_state = {wait_cv, Ctx, [Full | T]}, ack_now = true};
server(certificate, _M, _Full, #dtls{pha_state = {wait_cert, _, _}} = St) ->
    webrtc_dtls:fail(?ALERT_ILLEGAL_PARAMETER, bad_certificate_context, St);
server(certificate_verify, CV, Full, #dtls{pha_state = {wait_cv, Ctx, T}} = St) ->
    webrtc_dtls13_hs:verify_certificate_verify(client, CV, St#dtls{transcript = T}),
    St#dtls{pha_state = {wait_finished, Ctx, [Full | T]}, ack_now = true};
server(finished, VD, _Full, #dtls{pha_state = {wait_finished, _Ctx, T}, read_keys = RK} = St) ->
    #{secret := Secret} = maps:get(lists:max(maps:keys(RK)), RK),
    webrtc_dtls13_hs:verify_finished(Secret, VD, St#dtls{transcript = T}),
    webrtc_dtls:emit({peer_authenticated, St#dtls.peer_cert}, St#dtls{pha_state = undefined, ack_now = true});
server(Type, _M, _Full, St) ->
    webrtc_dtls:fail(?ALERT_UNEXPECTED_MESSAGE, {unexpected_message, Type}, St).
