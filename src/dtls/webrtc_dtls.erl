%% @doc DTLS endpoint for WebRTC (RFC 9147 DTLS 1.3 and RFC 6347 DTLS
%% 1.2, RFC 5764, RFC 8842), as a sans-IO engine (see
%% docs/ARCHITECTURE.md). Both versions are offered by default; the
%% server picks DTLS 1.3 when the client offers it.
%%
%% ```
%% Cert = webrtc_dtls_cert:generate(),
%% D0 = webrtc_dtls:new(#{role => client, cert => Cert,
%%                         remote_fingerprints => [FP]}),
%% {D1, Actions} = webrtc_dtls:start(Now, D0),
%% %% execute Actions; feed datagrams with handle_packet/3 and timers
%% %% with handle_timeout/2 at next_timeout/1.
%% '''
%%
%% Actions: `{send, Datagram}' and `{event, Event}' where Event is
%% `{connected, Info}', `{data, Bin}', `{closed, Reason}' or
%% `{failed, Reason}'.
%%
%% `connected' is only reported once the handshake finished AND the peer
%% certificate matched one of the remote fingerprints. When the remote
%% fingerprints are not known yet (the answer has not arrived), the
%% handshake completes and the endpoint waits for
%% `set_remote_fingerprints/2'; application data received meanwhile is
%% held, not delivered.
%%
%% This module owns the API and the DTLS 1.2 record layer, flights and
%% timers; `webrtc_dtls_hs' owns the DTLS 1.2 handshake messages and the
%% hello exchange. DTLS 1.3 is in `webrtc_dtls13' (records, ACKs,
%% KeyUpdate), `webrtc_dtls13_hs' and `webrtc_dtls13_server'.
-module(webrtc_dtls).

-include("webrtc_dtls.hrl").

-export([
    new/1,
    start/2,
    handle_packet/3,
    handle_timeout/2,
    next_timeout/1,
    send/2,
    close/1,
    set_remote_fingerprints/2,
    export_keying_material/4,
    srtp_profile/1,
    peer_certificate/1,
    status/1,
    role/1,
    info/1,
    key_update/2
]).

%% Used by webrtc_dtls_hs, webrtc_dtls_reasm and the DTLS 1.3 modules.
-export([
    queue_handshake/4,
    queue_ccs/1,
    install_write/2,
    emit/2,
    fail/3,
    plain_record/3,
    peer_retransmitted/2,
    alert_datagram/3,
    pack/2
]).

-export_type([state/0, action/0, event/0]).

-type state() :: #dtls{}.
-type action() :: {send, binary()} | {event, event()}.
-type event() ::
    {connected, map()}
    | {data, binary()}
    | {closed, term()}
    | {failed, term()}.

-define(DEFAULT_SRTP, [16#0007, 16#0008, 16#0001, 16#0002]).
-define(MAX_HELD, 64).
-define(MAX_EARLY, 32).
-define(MAX_SEQ, 16#FFFFFFFFFFFF).

%%====================================================================
%% API
%%====================================================================

%% @doc Create an endpoint. Options:
%% <ul>
%% <li>`role' (required): `client' or `server', from the SDP setup
%%     attribute (RFC 8842 §5: active is client, passive is server).</li>
%% <li>`cert' (required): a `webrtc_dtls_cert:cert()'.</li>
%% <li>`remote_fingerprints': list of `webrtc_dtls_cert:fingerprint()'.</li>
%% <li>`srtp_profiles': DTLS-SRTP profile ids in preference order;
%%     `[]' disables use_srtp.</li>
%% <li>`versions': `['dtlsv1.3', 'dtlsv1.2']' (default) or a subset;
%%     the client offers them, the server picks the highest version the
%%     client offers.</li>
%% <li>`suites': DTLS 1.3 and DTLS 1.2 cipher suite ids in preference
%%     order (default: all supported). DTLS 1.3 is only offered when
%%     the list has a DTLS 1.3 suite.</li>
%% <li>`mtu' (default 1200), `use_cookie' (server, default true; a
%%     HelloVerifyRequest in DTLS 1.2, a HelloRetryRequest with a
%%     stateless cookie in DTLS 1.3), `require_ems' (DTLS 1.2, default
%%     true), `rtx_initial' (ms, default 400), `rtx_max' (ms, default
%%     60000), `rtx_limit' (default 7), `rekey_records' (DTLS 1.3:
%%     records sent before a KeyUpdate, default 2^23),
%%     `cookie_lifetime' (ms, default 60000).</li>
%% </ul>
-spec new(map()) -> state().
new(#{role := Role, cert := #{der := Der, key := Key}} = Opts) when
    Role =:= client; Role =:= server
->
    Initial = maps:get(rtx_initial, Opts, 400),
    Suites = maps:get(suites, Opts, webrtc_dtls13_keys:supported_suites() ++ webrtc_dtls_crypto:supported_suites()),
    Suites13 = [S || S <- Suites, webrtc_dtls13_keys:suite(S) =/= error],
    %% Without a DTLS 1.3 suite the endpoint does not support DTLS 1.3
    %% (and a server then sets no downgrade sentinel).
    Versions = [
        V
     || V <- [version_atom(N) || N <- maps:get(versions, Opts, ['dtlsv1.3', 'dtlsv1.2'])],
        V =/= dtls13 orelse Suites13 =/= []
    ],
    #dtls{
        role = Role,
        state =
            case Role of
                client -> idle;
                server -> wait_client_hello
            end,
        cert_der = Der,
        key = Key,
        remote_fps = maps:get(remote_fingerprints, Opts, undefined),
        srtp_profiles = maps:get(srtp_profiles, Opts, ?DEFAULT_SRTP),
        versions = Versions,
        suites = suites_for_key(Key, Suites),
        suites13 = Suites13,
        rekey_records = maps:get(rekey_records, Opts, 1 bsl 23),
        cookie_lifetime = maps:get(cookie_lifetime, Opts, 60000),
        groups = maps:get(groups, Opts, [x25519, secp256r1, secp384r1]),
        require_ems = maps:get(require_ems, Opts, true),
        use_cookie = maps:get(use_cookie, Opts, true),
        cookie_secret = crypto:strong_rand_bytes(32),
        mtu = maps:get(mtu, Opts, 1200),
        rtx_initial = Initial,
        rtx_interval = Initial,
        rtx_max_interval = maps:get(rtx_max, Opts, 60000),
        rtx_limit = maps:get(rtx_limit, Opts, 7)
    }.

version_atom('dtlsv1.3') -> dtls13;
version_atom('dtlsv1.2') -> dtls12.

%% Only offer DTLS 1.2 suites whose authentication matches our
%% certificate key.
suites_for_key(Key, Suites) ->
    Auth =
        case element(1, Key) of
            'RSAPrivateKey' -> rsa;
            _ -> ecdsa
        end,
    [S || S <- Suites, {ok, #{auth := A}} <- [webrtc_dtls_crypto:suite(S)], A =:= Auth].

%% @doc Start the handshake. The client sends its ClientHello; the server
%% waits for one.
-spec start(integer(), state()) -> {state(), [action()]}.
start(Now, #dtls{role = client, state = idle} = St) ->
    run(Now, St, fun(S) -> webrtc_dtls_hs:start_client(S) end);
start(_Now, St) ->
    {St, []}.

-spec handle_packet(binary(), integer(), state()) -> {state(), [action()]}.
handle_packet(_Bin, _Now, #dtls{state = S} = St) when S =:= failed; S =:= closed ->
    {St, []};
handle_packet(Bin, Now, #dtls{version = dtls12} = St0) ->
    run(Now, St0, fun(S) ->
        lists:foldl(fun(R, Acc) -> handle_record(R, Now, Acc) end, S, webrtc_dtls_record:decode(Bin))
    end);
handle_packet(Bin, Now, St0) ->
    %% Hello exchange or DTLS 1.3: plaintext and unified header records
    %% may share a datagram (RFC 9147 §4.1).
    run(Now, St0, fun(S) -> webrtc_dtls13:handle_records(webrtc_dtls13_record:split(Bin), Now, S) end).

-spec handle_timeout(integer(), state()) -> {state(), [action()]}.
handle_timeout(_Now, #dtls{state = S} = St) when S =:= failed; S =:= closed ->
    {St, []};
handle_timeout(Now, #dtls{version = dtls13} = St) ->
    run(Now, St, fun(S) -> webrtc_dtls13:timeout(Now, S) end);
handle_timeout(Now, #dtls{rtx_at = At} = St) when At =/= infinity, Now >= At ->
    case St#dtls.rtx_count >= St#dtls.rtx_limit of
        true ->
            St1 = St#dtls{state = failed, rtx_at = infinity},
            {St1, [{event, {failed, handshake_timeout}}]};
        false ->
            Interval = min(St#dtls.rtx_interval * 2, St#dtls.rtx_max_interval),
            {St1, Dgrams} = transmit(St#dtls.last_flight, St),
            St2 = St1#dtls{
                rtx_count = St#dtls.rtx_count + 1,
                rtx_interval = Interval,
                rtx_at = Now + Interval
            },
            {St2, [{send, D} || D <- Dgrams]}
    end;
handle_timeout(_Now, St) ->
    {St, []}.

-spec next_timeout(state()) -> integer() | infinity.
next_timeout(#dtls{rtx_at = At, ack_at = Ack}) ->
    min(At, Ack).

%% @doc Send application data (one record). Only valid once connected.
-spec send(iodata(), state()) -> {ok, state(), [action()]} | {error, term()}.
send(Data, #dtls{state = connected, verified = true, version = dtls13} = St) ->
    Bin = iolist_to_binary(Data),
    case byte_size(Bin) =< 16384 of
        true -> webrtc_dtls13:send(Bin, St);
        false -> {error, too_large}
    end;
send(Data, #dtls{state = connected, verified = true, write_epoch = E} = St) when E > 0 ->
    Bin = iolist_to_binary(Data),
    case byte_size(Bin) =< 16384 of
        true ->
            case encode_record(application_data, E, Bin, St) of
                {ok, Rec, St1} -> {ok, St1, [{send, Rec}]};
                {error, _} = Err -> Err
            end;
        false ->
            {error, too_large}
    end;
send(_Data, _St) ->
    {error, not_connected}.

%% @doc Send close_notify and close (RFC 5246 §7.2.1).
-spec close(state()) -> {state(), [action()]}.
close(#dtls{state = S} = St) when S =:= closed; S =:= failed ->
    {St, []};
close(St) ->
    {Alert, St1} = alert_datagram(1, ?ALERT_CLOSE_NOTIFY, St),
    {St1#dtls{state = closed, rtx_at = infinity}, [{send, A} || A <- Alert]}.

%% @doc Provide the remote fingerprints once the remote description is
%% known. Verifies a certificate that was already received.
-spec set_remote_fingerprints([webrtc_dtls_cert:fingerprint()], state()) ->
    {state(), [action()]}.
set_remote_fingerprints(FPs, St) ->
    run(erlang:monotonic_time(millisecond), St#dtls{remote_fps = FPs}, fun(S) ->
        webrtc_dtls_hs:maybe_verify(S)
    end).

%% @doc Keying material exporter: RFC 5705 for DTLS 1.2, RFC 8446 §7.5
%% for DTLS 1.3. DTLS-SRTP uses `<<"EXTRACTOR-dtls_srtp">>' with
%% `no_context' (RFC 5764 §4.2).
-spec export_keying_material(binary(), binary() | no_context, non_neg_integer(), state()) ->
    {ok, binary()} | {error, not_connected}.
export_keying_material(Label, Context, Len, #dtls{handshake_done = true, verified = true, version = dtls13} = St) ->
    #{hash := H} = St#dtls.suite13,
    {ok, webrtc_dtls13_keys:exporter(webrtc_dtls13_keys:prefix(), H, St#dtls.exporter, Label, Context, Len)};
export_keying_material(Label, Context, Len, #dtls{handshake_done = true, verified = true} = St) ->
    #{prf := Hash} = St#dtls.suite,
    F = webrtc_dtls_crypto:export(
        Hash, St#dtls.master, {St#dtls.client_random, St#dtls.server_random}, Label, Context
    ),
    {ok, F(Len)};
export_keying_material(_, _, _, _) ->
    {error, not_connected}.

-spec srtp_profile(state()) -> undefined | 0..16#FFFF.
srtp_profile(#dtls{srtp_profile = P}) -> P.

-spec peer_certificate(state()) -> undefined | binary().
peer_certificate(#dtls{peer_cert = C}) -> C.

-spec status(state()) -> atom().
status(#dtls{state = S}) -> S.

-spec role(state()) -> client | server.
role(#dtls{role = R}) -> R.

%% @doc Connection parameters. `extended_master_secret' is always true
%% for DTLS 1.3, whose key schedule binds every secret to the handshake
%% transcript, the property RFC 7627 adds to DTLS 1.2.
-spec info(state()) -> map().
info(#dtls{version = dtls13} = St) ->
    (info12(St))#{suite => suite_name(St#dtls.suite13), extended_master_secret => true};
info(#dtls{} = St) ->
    info12(St).

info12(St) ->
    #{
        role => St#dtls.role,
        state => St#dtls.state,
        version => version_name(St#dtls.version),
        suite => suite_name(St#dtls.suite),
        group => St#dtls.group,
        srtp_profile => St#dtls.srtp_profile,
        extended_master_secret => St#dtls.ems,
        verified => St#dtls.verified
    }.

version_name(dtls13) -> 'dtlsv1.3';
version_name(dtls12) -> 'dtlsv1.2';
version_name(undefined) -> undefined.

suite_name(undefined) -> undefined;
suite_name(#{name := N}) -> N.

%% @doc Update our sending keys and ask the peer to update its own
%% (DTLS 1.3 KeyUpdate, RFC 9147 §8). The new keys are used once the
%% peer acknowledged the KeyUpdate.
-spec key_update(integer(), state()) -> {ok, state(), [action()]} | {error, not_connected | not_supported | pending}.
key_update(Now, #dtls{version = dtls13, state = connected, ku_pending = false} = St) ->
    {St1, A} = run(Now, St, fun(S) -> webrtc_dtls13:start_key_update(update_requested, S) end),
    {ok, St1, A};
key_update(_Now, #dtls{version = dtls13, state = connected}) ->
    {error, pending};
key_update(_Now, #dtls{state = connected}) ->
    {error, not_supported};
key_update(_Now, _St) ->
    {error, not_connected}.

%%====================================================================
%% Running the engine
%%====================================================================

%% Run F, convert protocol failures into fatal alerts, flush the flight
%% being built and return the accumulated actions.
run(Now, St0, F) ->
    St1 =
        try
            F(St0)
        catch
            throw:{dtls_alert, Desc, Reason, StA} -> fatal(Desc, Reason, StA)
        end,
    St2 =
        case St1#dtls.version of
            dtls13 -> webrtc_dtls13:flush(Now, St1);
            _ -> flush(Now, St1)
        end,
    {St2#dtls{out = []}, lists:reverse(St2#dtls.out)}.

%% @private Abort the handshake from webrtc_dtls_hs.
-spec fail(0..255, term(), state()) -> no_return().
fail(Desc, Reason, St) ->
    throw({dtls_alert, Desc, Reason, St}).

fatal(Desc, Reason, St) ->
    {Dgrams, St1} = alert_datagram(2, Desc, St),
    St2 = St1#dtls{state = failed, rtx_at = infinity, ack_at = infinity, ack_now = false, building = []},
    St3 = lists:foldl(fun(D, S) -> push({send, D}, S) end, St2, Dgrams),
    emit({failed, Reason}, St3).

%% @private
-spec emit(event(), state()) -> state().
emit(Event, St) ->
    push({event, Event}, St).

push(Action, #dtls{out = Out} = St) ->
    St#dtls{out = [Action | Out]}.

%%====================================================================
%% Inbound records
%%====================================================================

%% @private A DTLS 1.2 style record during the hello exchange.
-spec plain_record(webrtc_dtls_record:dtls_record(), integer(), state()) -> state().
plain_record(R, Now, St) ->
    handle_record(R, Now, St).

handle_record(_R, _Now, #dtls{state = S} = St) when S =:= failed; S =:= closed ->
    St;
handle_record(#{epoch := E} = R, Now, #dtls{read_epoch = RE} = St) when E =:= RE ->
    case open_record(R, St) of
        {ok, Plain} ->
            #{seq := Seq} = R,
            W = maps:get(E, St#dtls.replay, webrtc_dtls_record:replay_new()),
            case webrtc_dtls_record:replay_check(Seq, W) of
                ok ->
                    St1 = St#dtls{
                        replay = maps:put(E, webrtc_dtls_record:replay_update(Seq, W), St#dtls.replay)
                    },
                    content(maps:get(type, R), Plain, E, Now, St1);
                replay ->
                    St
            end;
        error ->
            %% RFC 6347 §4.1.2.7: invalid records are silently discarded.
            St
    end;
handle_record(#{epoch := 0, type := handshake, fragment := Frag}, Now, #dtls{read_epoch = RE} = St) when
    RE > 0
->
    %% Plaintext retransmission of an earlier flight of the peer.
    case webrtc_dtls_msg:decode_fragment(Frag) of
        {ok, [_ | _]} -> peer_retransmitted(Now, St);
        _ -> St
    end;
handle_record(#{epoch := E} = R, _Now, #dtls{read_epoch = RE, pending_read = P, early = Early} = St) when
    E =:= RE + 1, P =/= undefined, length(Early) < ?MAX_EARLY
->
    St#dtls{early = [R | Early]};
handle_record(_R, _Now, St) ->
    St.

open_record(#{epoch := 0, fragment := F}, _St) ->
    {ok, F};
open_record(R, #dtls{read_cipher = C}) when C =/= undefined ->
    case webrtc_dtls_record:unprotect(R, C) of
        {ok, P} -> {ok, P};
        {error, _} -> error
    end;
open_record(_, _) ->
    error.

content(change_cipher_spec, <<1>>, _E, Now, #dtls{pending_read = P} = St) when P =/= undefined ->
    St1 = St#dtls{read_cipher = P, read_epoch = St#dtls.read_epoch + 1, pending_read = undefined},
    Early = lists:reverse(St1#dtls.early),
    lists:foldl(fun(R, S) -> handle_record(R, Now, S) end, St1#dtls{early = []}, Early);
content(change_cipher_spec, _, _E, _Now, St) ->
    St;
content(alert, <<Level, Desc>>, E, _Now, St) ->
    handle_alert(Level, Desc, E, St);
content(alert, _, _E, _Now, St) ->
    St;
content(handshake, Frag, E, Now, St) ->
    case webrtc_dtls_msg:decode_fragment(Frag) of
        {ok, Frags} -> lists:foldl(fun(F, S) -> webrtc_dtls_reasm:fragment(F, E, Now, S) end, St, Frags);
        {error, _} -> webrtc_dtls:fail(?ALERT_DECODE_ERROR, decode_error, St)
    end;
content(application_data, Data, E, _Now, #dtls{handshake_done = true} = St) when E > 0 ->
    case St#dtls.verified of
        true ->
            emit({data, Data}, St);
        false when length(St#dtls.held) < ?MAX_HELD ->
            St#dtls{held = [Data | St#dtls.held]};
        false ->
            St
    end;
content(_Type, _Data, _E, _Now, St) ->
    St.

handle_alert(_Level, ?ALERT_CLOSE_NOTIFY, _E, St) ->
    {Dgrams, St1} = alert_datagram(1, ?ALERT_CLOSE_NOTIFY, St),
    St2 = lists:foldl(fun(D, S) -> push({send, D}, S) end, St1, Dgrams),
    emit({closed, peer_closed}, St2#dtls{state = closed, rtx_at = infinity, building = []});
handle_alert(2, Desc, _E, St) ->
    emit({failed, {alert, Desc}}, St#dtls{state = failed, rtx_at = infinity, building = []});
handle_alert(_Level, _Desc, _E, St) ->
    St.

%%====================================================================
%% Peer retransmission
%%====================================================================

%% The peer resent a flight we already processed: our reply was lost,
%% send our last flight again (§4.2.4). Rate limited to one resend per
%% half initial timeout so a flood of copies does not amplify.
%% @private
-spec peer_retransmitted(integer(), state()) -> state().
peer_retransmitted(_Now, #dtls{last_flight = []} = St) ->
    St;
peer_retransmitted(Now, #dtls{last_peer_rtx = Last, rtx_initial = I} = St) when
    Last =:= undefined; Now - Last >= I div 2
->
    {St1, Dgrams} = transmit(St#dtls.last_flight, St),
    lists:foldl(fun(D, S) -> push({send, D}, S) end, St1#dtls{last_peer_rtx = Now}, Dgrams);
peer_retransmitted(_Now, St) ->
    St.

%%====================================================================
%% Outbound flights
%%====================================================================

%% @private Queue a handshake message in the flight being built and add
%% it to the transcript. Returns the full message (with header).
-spec queue_handshake(webrtc_dtls_msg:msg_type(), binary(), boolean(), state()) ->
    {binary(), state()}.
queue_handshake(Type, Body, InTranscript, #dtls{send_msg_seq = Seq, write_epoch = E} = St) ->
    Full = webrtc_dtls_msg:full(Type, Seq, Body),
    T =
        case InTranscript of
            true -> [Full | St#dtls.transcript];
            false -> St#dtls.transcript
        end,
    Item = {handshake, E, Type, Seq, Body},
    {Full, St#dtls{send_msg_seq = Seq + 1, transcript = T, building = St#dtls.building ++ [Item]}}.

%% @private Queue ChangeCipherSpec; following messages use the next epoch.
-spec queue_ccs(state()) -> state().
queue_ccs(#dtls{write_epoch = E} = St) ->
    St#dtls{
        building = St#dtls.building ++ [{change_cipher_spec, E}],
        write_epoch = E + 1,
        write_seq = maps:put(E + 1, 0, St#dtls.write_seq)
    }.

%% @private Install the write cipher for epoch 1 and the pending read
%% cipher, from the key block.
-spec install_write(webrtc_dtls_crypto:suite(), state()) -> state().
install_write(Suite, #dtls{role = Role, keys = {CK, SK, CIV, SIV}} = St) ->
    CCipher = webrtc_dtls_record:new_cipher(Suite, CK, CIV),
    SCipher = webrtc_dtls_record:new_cipher(Suite, SK, SIV),
    {W, R} =
        case Role of
            client -> {CCipher, SCipher};
            server -> {SCipher, CCipher}
        end,
    St#dtls{write_ciphers = maps:put(1, W, St#dtls.write_ciphers), pending_read = R}.

%% Send the flight being built, if any, and arm the retransmission timer
%% when we expect an answer.
flush(_Now, #dtls{building = []} = St) ->
    St;
flush(Now, #dtls{building = Items} = St) ->
    {St1, Dgrams} = transmit(Items, St),
    St2 = lists:foldl(fun(D, S) -> push({send, D}, S) end, St1, Dgrams),
    Waiting = lists:member(St2#dtls.state, [
        wait_server_hello, wait_server_hello_done, wait_server_finished, wait_client_finished
    ]),
    St2#dtls{
        building = [],
        last_flight = Items,
        rtx_count = 0,
        rtx_interval = St#dtls.rtx_initial,
        rtx_at =
            case Waiting of
                true -> Now + St#dtls.rtx_initial;
                false -> infinity
            end
    }.

%% Encode flight items into datagrams no larger than the MTU (records are
%% packed together, handshake messages are fragmented).
transmit(Items, St0) ->
    {Records, St} = lists:foldl(
        fun(Item, {Acc, S}) ->
            {Rs, S1} = item_records(Item, S),
            {Acc ++ Rs, S1}
        end,
        {[], St0},
        Items
    ),
    {St, pack(Records, St#dtls.mtu)}.

item_records({change_cipher_spec, E}, St) ->
    {ok, R, St1} = encode_record(change_cipher_spec, E, <<1>>, St),
    {[R], St1};
item_records({handshake, E, Type, Seq, Body}, St) ->
    Max = St#dtls.mtu - 13 - overhead(E, St),
    lists:foldl(
        fun(Frag, {Acc, S}) ->
            {ok, R, S1} = encode_record(handshake, E, Frag, S),
            {Acc ++ [R], S1}
        end,
        {[], St},
        webrtc_dtls_msg:fragments(Type, Seq, Body, Max)
    ).

overhead(0, _St) ->
    0;
overhead(E, #dtls{write_ciphers = Cs}) ->
    #{explicit_nonce := X} = maps:get(E, Cs),
    X + 16.

encode_record(Type, E, Data, #dtls{version = dtls13} = St) ->
    webrtc_dtls13:encode_record(Type, E, Data, St);
encode_record(Type, E, Data, #dtls{write_seq = Seqs} = St) ->
    Seq = maps:get(E, Seqs, 0),
    case Seq > ?MAX_SEQ of
        true ->
            {error, sequence_exhausted};
        false ->
            Rec =
                case E of
                    0 ->
                        webrtc_dtls_record:encode(Type, ?DTLS12, 0, Seq, Data);
                    _ ->
                        webrtc_dtls_record:protect(
                            Type, ?DTLS12, E, Seq, Data, maps:get(E, St#dtls.write_ciphers)
                        )
                end,
            {ok, Rec, St#dtls{write_seq = Seqs#{E => Seq + 1}}}
    end.

%% @private Pack records into datagrams of at most `Mtu' bytes.
-spec pack([binary()], pos_integer()) -> [binary()].
pack(Records, Mtu) ->
    pack(Records, Mtu, <<>>, []).

pack([], _Mtu, <<>>, Acc) ->
    lists:reverse(Acc);
pack([], _Mtu, Cur, Acc) ->
    lists:reverse([Cur | Acc]);
pack([R | Rest], Mtu, <<>>, Acc) ->
    pack(Rest, Mtu, R, Acc);
pack([R | Rest], Mtu, Cur, Acc) when byte_size(Cur) + byte_size(R) =< Mtu ->
    pack(Rest, Mtu, <<Cur/binary, R/binary>>, Acc);
pack([R | Rest], Mtu, Cur, Acc) ->
    pack(Rest, Mtu, R, [Cur | Acc]).

%% @private
-spec alert_datagram(1 | 2, 0..255, state()) -> {[binary()], state()}.
alert_datagram(Level, Desc, #dtls{write_epoch = E} = St) ->
    case encode_record(alert, E, <<Level, Desc>>, St) of
        {ok, R, St1} -> {[R], St1};
        {error, _} -> {[], St}
    end.
