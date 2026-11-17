%% @private DTLS 1.3 engine (RFC 9147): inbound records with epoch and
%% record number reconstruction, replay protection, the ACK mechanism
%% (§7) with selective retransmission (§5.8), flights and timers.
%% Epoch keys and KeyUpdate (§8) are in `webrtc_dtls13_epoch'.
%% Handshake messages are handled by
%% `webrtc_dtls13_hs' and `webrtc_dtls13_server'; the public API is in
%% `webrtc_dtls'.
-module(webrtc_dtls13).

-include("webrtc_dtls.hrl").

-export([
    handle_records/3,
    flush/2,
    timeout/2,
    send/2,
    encode_record/4,
    implicit_ack/1
]).

-import(webrtc_dtls, [fail/3, emit/2]).

%% RFC 9147 §5.8.3, §5.8.2, §4.4.
-define(MAX_RECORDS, 10).
-define(MIN_RTX, 50).
-define(SMALL_RECORD, 512).
-define(MAX_EARLY, 32).
-define(MAX_HELD, 64).
%% The default TCP MSL (RFC 9293 §3.4.2): how long the previous read
%% epoch stays usable after a KeyUpdate (RFC 9147 §4.2.1).
-define(MSL, 120000).
%% RFC 9147 §4.5.3: records failing authentication per key.
-define(INTEGRITY_LIMIT, (1 bsl 36)).
%% RFC 8446 §5.5: 2^24.5 full-size records for AES-GCM.
-define(GCM_LIMIT, 23726566).
-define(SEQ_LIMIT, ((1 bsl 48) - 1)).

-define(HANDSHAKE_STATES, [
    wait_ee, wait_cert_cr, wait_cert, wait_cv, wait_finished, wait_client_cert, wait_client_cv, wait_client_finished
]).

%%====================================================================
%% Inbound
%%====================================================================

%% @doc Process the records of one datagram. Records of an epoch whose
%% keys are not installed yet are buffered and processed once the keys
%% are available.
-spec handle_records([webrtc_dtls13_record:rec()], integer(), #dtls{}) -> #dtls{}.
handle_records(Recs, Now, St) ->
    lists:foldl(fun(R, S) -> step(R, Now, S) end, St, Recs).

step(R, Now, St0) ->
    Before = maps:keys(St0#dtls.read_keys),
    St1 = one(R, Now, St0),
    case St1#dtls.early =/= [] andalso maps:keys(St1#dtls.read_keys) =/= Before of
        true ->
            Early = lists:reverse(St1#dtls.early),
            handle_records(Early, Now, St1#dtls{early = []});
        false ->
            St1
    end.

one(_R, _Now, #dtls{state = S} = St) when S =:= failed; S =:= closed ->
    St;
one(R, Now, #dtls{version = dtls13} = St) ->
    record(R, Now, St);
one(#{format := plain} = R, Now, St) ->
    %% Hello exchange, version not chosen yet.
    webrtc_dtls12:record(maps:remove(format, R), Now, St);
one(#{format := unified} = R, _Now, #dtls{role = client, state = wait_server_hello} = St) ->
    %% Possibly the server's encrypted flight overtaking its ServerHello.
    buffer(R, St);
one(_R, _Now, St) ->
    St.

%% Only records that may belong to a handshake epoch (2 or 3) whose
%% keys are not installed yet are kept; others (e.g. 0-RTT data we never
%% accept) cannot take the space.
buffer(#{epoch_bits := B} = R, #dtls{early = Early, read_keys = RK, handshake_done = false} = St) when
    (B =:= 2 orelse B =:= 3), length(Early) < ?MAX_EARLY
->
    case maps:is_key(B, RK) of
        true -> St;
        false -> St#dtls{early = [R | Early]}
    end;
buffer(_R, St) ->
    St.

record(#{format := plain, epoch := 0, seq := Seq, type := Type, fragment := F}, Now, St) ->
    W = maps:get(0, St#dtls.replay, webrtc_dtls_record:replay_new()),
    case webrtc_dtls_record:replay_check(Seq, W) of
        ok ->
            St1 = St#dtls{replay = maps:put(0, webrtc_dtls_record:replay_update(Seq, W), St#dtls.replay)},
            plain(Type, F, Seq, Now, St1);
        replay ->
            St
    end;
record(#{format := plain}, _Now, St) ->
    %% DTLSPlaintext only exists in epoch 0.
    St;
record(#{format := unified, epoch_bits := Bits} = R, Now, St) ->
    %% RFC 9147 §9: a CID we do not receive on is not ours.
    case webrtc_dtls13_cid:known(maps:get(cid, R, <<>>), St) of
        true ->
            case webrtc_dtls13_record:select_epoch(Bits, maps:keys(St#dtls.read_keys)) of
                {ok, E} -> decrypt(E, R, Now, St);
                error -> buffer(R, St)
            end;
        false ->
            St
    end.

first_of_epoch(E, Now, #dtls{prev_epoch_until = undefined, read_keys = RK} = St) when E >= 4 ->
    case E =:= lists:max(maps:keys(RK)) andalso maps:is_key(E - 1, RK) of
        true -> St#dtls{prev_epoch_until = Now + ?MSL};
        false -> St
    end;
first_of_epoch(_E, _Now, St) ->
    St.

%% Only ClientHello, ServerHello and HelloRetryRequest are sent in
%% plaintext. Once handshake keys exist, plaintext handshake records
%% only signal a peer retransmission and plaintext alerts are ignored.
plain(handshake, F, Seq, Now, #dtls{role = client, state = wait_server_hello} = St) ->
    case webrtc_dtls_msg:decode_fragment(F) of
        {ok, [_ | _] = Frags} ->
            case lists:all(fun(#{type := T}) -> T =:= server_hello end, Frags) of
                true -> handshake(F, 0, Seq, Now, St);
                false -> St
            end;
        _ ->
            St
    end;
plain(handshake, F, _Seq, Now, St) ->
    case webrtc_dtls_msg:decode_fragment(F) of
        {ok, Frags = [_ | _]} ->
            case lists:all(fun(Fr) -> webrtc_dtls_reasm:classify(Fr, St) =:= old end, Frags) of
                true -> peer_retransmitted(Now, St);
                false -> St
            end;
        _ ->
            St
    end;
plain(alert, <<Level, Desc>>, _Seq, _Now, #dtls{read_keys = RK} = St) when map_size(RK) =:= 0 ->
    alert(Level, Desc, St);
plain(_Type, _F, _Seq, _Now, St) ->
    St.

%% After a KeyUpdate the previous epoch is dropped one MSL after the
%% first record of the new one (§4.2.1, §8).
decrypt(E, R, Now, #dtls{read_keys = RK, prev_epoch_until = Until} = St) when is_integer(Until), Now >= Until ->
    case E =:= lists:max(maps:keys(RK)) - 1 of
        true -> St#dtls{read_keys = maps:remove(E, RK), prev_epoch_until = undefined};
        false -> open(E, R, Now, St)
    end;
decrypt(E, R, Now, St) ->
    open(E, R, Now, St).

open(E, R, Now, #dtls{read_keys = RK, replay = Rp} = St) ->
    Keys = maps:get(E, RK),
    W = maps:get(E, Rp, webrtc_dtls_record:replay_new()),
    {Max, _} = W,
    case webrtc_dtls13_record:open(R, Keys, Max + 1) of
        record_overflow ->
            %% RFC 8446 §5.2: an authentic record above 2^14 bytes of
            %% plaintext ends the connection.
            fail(?ALERT_RECORD_OVERFLOW, record_overflow, St);
        {ok, Seq, Type, Content} ->
            case webrtc_dtls_record:replay_check(Seq, W) of
                ok ->
                    St1 = first_of_epoch(E, Now, St#dtls{replay = Rp#{E => webrtc_dtls_record:replay_update(Seq, W)}}),
                    content(Type, Content, E, Seq, Now, webrtc_dtls13_cid:seen(maps:get(cid, R, <<>>), St1));
                replay ->
                    St
            end;
        error ->
            %% §4.5.2: discard silently; §4.5.3: count forgeries.
            Failures = maps:get(failures, Keys, 0) + 1,
            St1 = St#dtls{read_keys = RK#{E => Keys#{failures => Failures}}},
            case Failures >= ?INTEGRITY_LIMIT of
                true -> fail(?ALERT_DECRYPT_ERROR, integrity_limit, St1);
                false -> St1
            end
    end.

content(handshake, F, E, Seq, Now, St) ->
    handshake(F, E, Seq, Now, St);
content(alert, <<Level, Desc>>, _E, _Seq, _Now, St) ->
    alert(Level, Desc, St);
content(alert, _, _E, _Seq, _Now, St) ->
    fail(?ALERT_DECODE_ERROR, bad_alert, St);
content(ack, Body, E, _Seq, Now, St) ->
    case webrtc_dtls13_record:decode_ack(Body) of
        {ok, Recs} -> ack(Recs, E, Now, St);
        error -> fail(?ALERT_DECODE_ERROR, bad_ack, St)
    end;
content(application_data, Data, E, _Seq, _Now, #dtls{peer_finished = true} = St) when E >= 3 ->
    %% RFC 9147 §5.8.1: data is processed only after the peer Finished,
    %% and reported only after the connection is announced.
    case St#dtls.announced of
        true -> emit({data, Data}, St);
        false when length(St#dtls.held) < ?MAX_HELD -> St#dtls{held = [Data | St#dtls.held]};
        false -> St
    end;
content(application_data, Data, 1, _Seq, _Now, #dtls{role = server, zero_rtt = accepted} = St) ->
    %% 0-RTT data (RFC 8446 §2.3), reported once the connection is.
    case St#dtls.announced of
        true -> emit({data, Data}, St);
        false when length(St#dtls.held) < ?MAX_HELD -> St#dtls{held = [Data | St#dtls.held]};
        false -> St
    end;
content(_Type, _Data, _E, _Seq, _Now, St) ->
    St.

%% RFC 8446 §6: close_notify and user_canceled are the only non-error
%% alerts; every other alert terminates the connection.
alert(Level, _Desc, St) when Level =/= 1, Level =/= 2 ->
    fail(?ALERT_ILLEGAL_PARAMETER, {bad_alert_level, Level}, St);
alert(_Level, ?ALERT_CLOSE_NOTIFY, St) ->
    {Dgrams, St1} = webrtc_dtls:alert_datagram(1, ?ALERT_CLOSE_NOTIFY, St),
    St2 = lists:foldl(fun(D, S) -> push({send, D}, S) end, St1, Dgrams),
    emit({closed, peer_closed}, stop(St2#dtls{state = closed}));
alert(_Level, 90, St) ->
    St;
alert(_Level, Desc, St) ->
    emit({failed, {alert, Desc}}, stop(St#dtls{state = failed})).

stop(St) ->
    St#dtls{rtx_at = infinity, ack_at = infinity, building = [], ack_now = false}.

%% Handshake fragments of one record. The record is acknowledged when
%% one of its fragments was processed or buffered (§7).
handshake(F, E, Seq, Now, St) ->
    case webrtc_dtls_msg:decode_fragment(F) of
        {ok, Frags} ->
            Classes = [webrtc_dtls_reasm:classify(Fr, St) || Fr <- Frags],
            New = [Fr || {Fr, new} <- lists:zip(Frags, Classes)],
            Old = [Fr || {Fr, old} <- lists:zip(Frags, Classes), not stateless_reply(Fr, St)],
            case New of
                [] when Classes =/= [], St#dtls.handshake_done ->
                    %% A copy of a message already processed after the
                    %% handshake: acknowledge it again (§7, §5.8.1), on
                    %% the ACK timer so that a burst of copies gets one.
                    received(E, Seq, St);
                [] when Old =/= [] ->
                    peer_retransmitted(Now, St);
                [] ->
                    St;
                _ ->
                    %% After the handshake a new message in an epoch we
                    %% already moved past spans a key change (RFC 8446 §5.1).
                    post_handshake(St) andalso E < lists:max(maps:keys(St#dtls.read_keys)) andalso
                        fail(?ALERT_UNEXPECTED_MESSAGE, message_after_key_change, St),
                    St1 = lists:foldl(fun(Fr, S) -> webrtc_dtls_reasm:add(Fr, E, S) end, St, New),
                    webrtc_dtls_reasm:deliver(Now, received(E, Seq, St1))
            end;
        {error, _} ->
            fail(?ALERT_DECODE_ERROR, decode_error, St)
    end.

%% A copy of a HelloRetryRequest, the only ServerHello before the
%% real one: the server is stateless, so it says nothing of our
%% ClientHello being lost, and the HRR is acknowledged by our next
%% flight (§5.1, §7.1).
stateless_reply(#{type := server_hello}, #dtls{role = client, state = wait_server_hello}) -> true;
stateless_reply(_, _) -> false.

%% A record to acknowledge. One ACK carries as many record numbers as
%% fit in the MTU (§7.1), so only that many of the latest are kept.
received(E, Seq, #dtls{rcv_recs = Recs} = St) ->
    St#dtls{rcv_recs = lists:sublist([{E, Seq} | Recs], ack_capacity(St)), rcv_new = true}.

ack_capacity(#dtls{mtu = Mtu} = St) ->
    max(1, (Mtu - webrtc_dtls13_record:overhead(St#dtls.peer_cid) - 2) div 16).

%%====================================================================
%% ACK (RFC 9147 §7.2)
%%====================================================================

ack(Recs, E, Now, St) ->
    %% §7: during the handshake an ACK is sent in an epoch at least that of
    %% the records it acknowledges. After it only the highest sending epoch
    %% is required, and a peer that did not update its keys acknowledges
    %% our later epochs from an older one (Figure 14).
    not St#dtls.handshake_done andalso lists:any(fun({RE, _}) -> RE > E end, Recs) andalso
        fail(?ALERT_ILLEGAL_PARAMETER, ack_for_later_epoch, St),
    Known = lists:append([maps:get(R, St#dtls.sent_recs) || R <- Recs, maps:is_key(R, St#dtls.sent_recs)]),
    case Known of
        [] ->
            St;
        _ ->
            Acked = lists:foldl(
                fun({MS, Off, Len}, A) -> A#{MS => [{Off, Off + Len} | maps:get(MS, A, [])]} end,
                St#dtls.acked,
                Known
            ),
            St1 = St#dtls{acked = Acked},
            case [I || I <- St1#dtls.last_flight, unacked(I, Acked) =/= []] of
                [] -> flight_done(rtt_sample(Now, St1));
                _ -> resend(Now, St1)
            end
    end.

%% RFC 9147 §5.8.2: a flight acknowledged without retransmission sets
%% the timer of the next ones to 1.5 times its round-trip time.
rtt_sample(Now, #dtls{rtx_count = 0, flight_at = At} = St) when is_integer(At) ->
    Rtt = max(0, Now - At),
    St#dtls{rtx_base = min(max(?MIN_RTX, (3 * Rtt + 1) div 2), St#dtls.rtx_max_interval)};
rtt_sample(_Now, St) ->
    St.

flight_done(St0) ->
    St = St0#dtls{last_flight = [], sent_recs = #{}, acked = #{}, rtx_at = infinity},
    St1 =
        case St of
            #dtls{ku_pending = true} -> webrtc_dtls13_epoch:key_update_acked(St);
            #dtls{state = wait_ack} -> webrtc_dtls13_hs:final_flight_acked(St);
            _ -> St
        end,
    webrtc_dtls13_cid:flight_done(St1).

%% @doc The peer's next flight acknowledges our last flight.
-spec implicit_ack(#dtls{}) -> #dtls{}.
implicit_ack(St) ->
    St#dtls{last_flight = [], sent_recs = #{}, acked = #{}, rtx_at = infinity}.

%% Byte ranges {Start, End} of a message not acknowledged yet. An empty
%% message is one empty range until a record carrying it is
%% acknowledged.
unacked({handshake, _E, _T, Seq, Body}, Acked) ->
    Ranges = lists:sort(maps:get(Seq, Acked, [])),
    case byte_size(Body) of
        0 when Ranges =:= [] -> [{0, 0}];
        0 -> [];
        Len -> gaps(Ranges, 0, Len)
    end.

gaps(_, Pos, Len) when Pos >= Len -> [];
gaps([], Pos, Len) -> [{Pos, Len}];
gaps([{S, E} | Rest], Pos, Len) when S > Pos -> [{Pos, min(S, Len)} | gaps(Rest, max(E, Pos), Len)];
gaps([{_S, E} | Rest], Pos, Len) -> gaps(Rest, max(E, Pos), Len).

%% The peer resent its previous flight while none of ours was
%% acknowledged: part of our flight was lost (§5.8.1 case 3). A copy
%% within half the initial timeout of our flight belongs to the burst we
%% answered, not to a retransmission by the peer's timer.
peer_retransmitted(Now, #dtls{last_flight = [_ | _], acked = A, sent_at = Sent, rtx_initial = I} = St) when
    map_size(A) =:= 0, Sent =:= undefined orelse Now - Sent >= I div 2
->
    resend(Now, St);
peer_retransmitted(_Now, St) ->
    St.

%% Retransmit the unacknowledged part of the last flight, at most once
%% per half initial timeout so that copies and ACKs do not amplify.
resend(Now, #dtls{last_peer_rtx = Last, rtx_initial = I} = St) when Last =:= undefined; Now - Last >= I div 2 ->
    {St1, Dgrams} = transmit(St#dtls.last_flight, St),
    St2 = lists:foldl(fun(D, S) -> push({send, D}, S) end, St1#dtls{last_peer_rtx = Now, sent_at = Now}, Dgrams),
    St2#dtls{rtx_at = Now + St2#dtls.rtx_interval};
resend(_Now, St) ->
    St.

%%====================================================================
%% Outbound
%%====================================================================

%% @doc Send a pending ACK, then the flight being built, if any, and arm
%% the retransmission or ACK timer.
-spec flush(integer(), #dtls{}) -> #dtls{}.
flush(Now, St0) ->
    St1 =
        case St0#dtls.ack_now of
            true -> send_ack(St0#dtls{ack_now = false, ack_at = infinity});
            false -> St0
        end,
    case St1#dtls.building of
        [] ->
            arm_ack(Now, St1);
        Items ->
            %% A handshake flight acknowledges the peer's (§7.1); after
            %% the handshake ours does not, so a pending ACK stays.
            {Rcv, AckAt} =
                case post_handshake(St1) of
                    true -> {St1#dtls.rcv_recs, St1#dtls.ack_at};
                    false -> {[], infinity}
                end,
            St2 = St1#dtls{
                building = [],
                last_flight = Items,
                sent_recs = #{},
                acked = #{},
                rcv_recs = Rcv,
                ack_at = AckAt,
                rtx_count = 0,
                rtx_interval = base(St1),
                flight_at = Now,
                sent_at = Now
            },
            {St3, Dgrams} = transmit(Items, St2),
            St4 = lists:foldl(fun(D, S) -> push({send, D}, S) end, St3, Dgrams),
            announce(arm_ack(Now, St4#dtls{rtx_at = Now + base(St4)}))
    end.

%% A client is connected once its Finished flight is out, ahead of
%% any data the owner then sends (RFC 8446 §4.4.4).
announce(#dtls{state = wait_ack, announced = false} = St) -> webrtc_dtls_hs:maybe_verify(St);
announce(St) -> St.

%% Part of the incoming flight arrived but we cannot answer yet: ACK
%% what we have after a quarter of the retransmission timeout (§7.1),
%% once per new record so the timer does not re-arm after its ACK.
%% Post-handshake messages are acknowledged after the same delay (§7.1
%% allows it), so one ACK covers a flight of them.
arm_ack(Now, #dtls{rcv_recs = [_ | _], rcv_new = true, ack_at = infinity, state = S} = St) ->
    case lists:member(S, ?HANDSHAKE_STATES) orelse post_handshake(St) of
        true -> St#dtls{ack_at = Now + max(1, St#dtls.rtx_interval div 4)};
        false -> St
    end;
arm_ack(_Now, St) ->
    St.

%% Our Finished is out: what the peer sends now is post-handshake.
post_handshake(#dtls{handshake_done = true}) -> true;
post_handshake(#dtls{state = wait_ack, last_flight = [_ | _]}) -> true;
post_handshake(_) -> false.

send_ack(#dtls{rcv_recs = []} = St) ->
    St;
send_ack(#dtls{rcv_recs = Recs0, write_epoch = E, mtu = Mtu} = St) ->
    %% §7: during the handshake an ACK covers no record of a later epoch
    %% than its own. After the handshake it goes in our highest sending
    %% epoch whatever the records' epochs: a peer's KeyUpdates are
    %% acknowledged without waiting for one of ours (Figure 14).
    Recs =
        case St#dtls.handshake_done of
            true -> Recs0;
            false -> [R || {RE, _} = R <- Recs0, RE =< E]
        end,
    N = max(1, (Mtu - webrtc_dtls13_record:overhead(St#dtls.peer_cid) - 2) div 16),
    case Recs of
        [] ->
            St;
        _ ->
            Body = webrtc_dtls13_record:encode_ack(lists:sublist(Recs, N)),
            case encode(ack, E, Body, St#dtls{rcv_new = false}) of
                {ok, Rec, _, St1} ->
                    %% The record numbers stay (the latest that fit, see
                    %% received/3): an ACK repeats them in case an
                    %% earlier one was lost (§7.1).
                    push({send, Rec}, St1);
                {error, _} ->
                    St
            end
    end.

%% @doc Retransmission and ACK timers.
-spec timeout(integer(), #dtls{}) -> #dtls{}.
timeout(Now, St0) ->
    St1 =
        case St0#dtls.ack_at of
            At when At =/= infinity, Now >= At -> send_ack(St0#dtls{ack_at = infinity});
            _ -> St0
        end,
    case St1#dtls.rtx_at of
        R when R =/= infinity, Now >= R ->
            case St1#dtls.rtx_count >= St1#dtls.rtx_limit of
                true ->
                    Reason =
                        case St1#dtls.handshake_done of
                            true -> ack_timeout;
                            false -> handshake_timeout
                        end,
                    emit({failed, Reason}, stop(St1#dtls{state = failed}));
                false ->
                    %% After the handshake the backed-off value stays
                    %% until a flight goes through without retransmission
                    %% (§5.8.2). Handshake flights start from the RTT
                    %% based value: under heavy loss a carried back-off
                    %% held the whole handshake back.
                    Interval = min(St1#dtls.rtx_interval * 2, St1#dtls.rtx_max_interval),
                    Count = St1#dtls.rtx_count + 1,
                    {St2, Dgrams} = transmit(St1#dtls.last_flight, St1#dtls{rtx_count = Count, sent_at = Now}),
                    St3 = lists:foldl(fun(D, S) -> push({send, D}, S) end, St2, Dgrams),
                    Base = case St1#dtls.handshake_done of true -> Interval; false -> St1#dtls.rtx_base end,
                    St3#dtls{rtx_interval = Interval, rtx_base = Base, rtx_at = Now + Interval}
            end;
        _ ->
            St1
    end.

%% @doc Application data in the current epoch. A KeyUpdate starts when
%% the record count reaches `rekey_records'; sending stops at the AEAD
%% limit until the new keys are in use.
-spec send(binary(), #dtls{}) -> {ok, #dtls{}, [webrtc_dtls:action()]} | {error, term()}.
send(Bin, #dtls{write_epoch = E, write_seq = WS, write_ciphers = WC} = St) ->
    Seq = maps:get(E, WS, 0),
    #{cipher := C} = maps:get(E, WC),
    case Seq >= limit(C) of
        true ->
            {error, key_limit};
        false ->
            {ok, Rec, _, St1} = encode(application_data, E, Bin, St),
            %% Not while our final flight waits for its ACK: a KeyUpdate
            %% flight would take its place.
            case Seq + 1 >= St1#dtls.rekey_records andalso not St1#dtls.ku_pending andalso St1#dtls.state =:= connected of
                true ->
                    Now = erlang:monotonic_time(millisecond),
                    St2 = flush(Now, webrtc_dtls13_epoch:start_key_update(update_requested, St1#dtls{out = []})),
                    {ok, St2#dtls{out = []}, [{send, Rec} | lists:reverse(St2#dtls.out)]};
                false ->
                    {ok, St1, [{send, Rec}]}
            end
    end.

limit(chacha20_poly1305) -> ?SEQ_LIMIT;
limit(_) -> ?GCM_LIMIT.

%% @doc Encode one record in `Epoch' (plaintext in epoch 0).
-spec encode_record(webrtc_dtls_record:content_type(), non_neg_integer(), iodata(), #dtls{}) ->
    {ok, binary(), #dtls{}} | {error, term()}.
encode_record(Type, E, Data, St) ->
    case encode(Type, E, Data, St) of
        {ok, Rec, _Seq, St1} -> {ok, Rec, St1};
        {error, _} = Err -> Err
    end.

encode(Type, E, Data, #dtls{write_seq = Seqs} = St) ->
    Seq = maps:get(E, Seqs, 0),
    case Seq > ?SEQ_LIMIT of
        true ->
            {error, sequence_exhausted};
        false ->
            Rec =
                case E of
                    0 -> webrtc_dtls_record:encode(Type, ?DTLS12, 0, Seq, Data);
                    _ -> webrtc_dtls13_record:protect(Type, E, Seq, Data, maps:get(E, St#dtls.write_ciphers), St#dtls.peer_cid)
                end,
            {ok, Rec, Seq, St#dtls{write_seq = Seqs#{E => Seq + 1}}}
    end.

%% Encode the unacknowledged parts of a flight. Fragments of consecutive
%% messages of one epoch share a record, and a record takes what is left
%% of the datagram before a new datagram starts, so a flight uses as few
%% records and datagrams as the MTU allows. Each record remembers the
%% fragments it carries, for ACKs. At most MAX_RECORDS records go in one
%% transmission (§5.8.3); the rest follow the next ACK or timer.
transmit(Items, St) ->
    Pieces = [{E, webrtc_dtls_msg:type_code(Type), byte_size(Body), MS, Body, Off, End}
              || {handshake, E, Type, MS, Body} = Item <- Items, {Off, End} <- unacked(Item, St#dtls.acked)],
    build(Pieces, #{mtu => record_mtu(St), used => 0, rec => none, recs => 0, dgram => [], out => []}, St).

build([], B, St) ->
    finish(B, St);
build(_, #{rec := none, recs := N} = B, St) when N >= ?MAX_RECORDS ->
    finish(B, St);
build([{E, T, L, MS, Body, Off, End} = P | Rest], B, St) ->
    %% A fragment needs its 12-byte header and a byte, or only the header
    %% for an empty message.
    Need = case End - Off of 0 -> 12; _ -> 13 end,
    case room(E, B, St) of
        Room when Room >= Need ->
            N = min(End - Off, Room - 12),
            Frag = <<T, L:24, MS:16, Off:24, N:24, (binary:part(Body, Off, N))/binary>>,
            B1 = add_fragment(E, Frag, {MS, Off, N}, B),
            case Off + N of
                End -> build(Rest, B1, St);
                Off1 -> build([setelement(6, P, Off1) | Rest], B1, St)
            end;
        _ ->
            {B1, St1} = make_room(B, St),
            build([P | Rest], B1, St1)
    end.

%% Payload bytes the next fragment of epoch E can take: the rest of the
%% open record of that epoch, or of a new record in this datagram.
room(E, #{rec := {E, Size, _, _}, mtu := Mtu, used := U}, St) -> Mtu - U - header(E, St) - Size;
room(E, #{rec := none, mtu := Mtu, used := U}, St) -> Mtu - U - header(E, St);
room(_E, _B, _St) -> 0.

add_fragment(E, Frag, Info, #{rec := none} = B) ->
    B#{rec := {E, byte_size(Frag), [Frag], [Info]}};
add_fragment(E, Frag, Info, #{rec := {E, Size, Payload, Infos}} = B) ->
    B#{rec := {E, Size + byte_size(Frag), [Frag | Payload], [Info | Infos]}}.

%% Close the open record, or else the datagram (a datagram without any
%% record yet always has room, the MTU leaves space for one fragment).
make_room(#{rec := none, dgram := D, out := Out} = B, St) ->
    {B#{used := 0, dgram := [], out := [iolist_to_binary(lists:reverse(D)) | Out]}, St};
make_room(B, St) ->
    close_record(B, St).

close_record(#{rec := {E, _, Payload, Infos}, used := U, recs := N, dgram := D} = B, St) ->
    {ok, Rec, RSeq, St1} = encode(handshake, E, lists:reverse(Payload), St),
    St2 = St1#dtls{sent_recs = maps:put({E, RSeq}, lists:reverse(Infos), St1#dtls.sent_recs)},
    {B#{rec := none, used := U + byte_size(Rec), recs := N + 1, dgram := [Rec | D]}, St2}.

finish(#{rec := none, dgram := [], out := Out}, St) ->
    {St, lists:reverse(Out)};
finish(#{rec := none} = B, St) ->
    {B1, St1} = make_room(B, St),
    finish(B1, St1);
finish(B, St) ->
    {B1, St1} = close_record(B, St),
    finish(B1, St1).

%% The timer a new flight starts with.
base(#dtls{rtx_base = undefined, rtx_initial = I}) -> I;
base(#dtls{rtx_base = B}) -> B.

%% §4.4: from the second retransmission on, smaller records, in case
%% the path MTU is lower than ours.
record_mtu(#dtls{rtx_count = N, mtu = Mtu}) when N >= 2 -> max(min(Mtu, ?SMALL_RECORD), Mtu div 2);
record_mtu(#dtls{mtu = Mtu}) -> Mtu.

%% Protected records carry the peer's CID (RFC 9147 §9).
header(0, _St) -> 13;
header(_, #dtls{peer_cid = Cid}) -> webrtc_dtls13_record:overhead(Cid).

push(Action, #dtls{out = Out} = St) ->
    St#dtls{out = [Action | Out]}.
