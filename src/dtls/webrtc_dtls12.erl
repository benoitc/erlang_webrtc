%% @private DTLS 1.2 record layer, flights and timers (RFC 6347 §4.1,
%% §4.2.3, §4.2.4): record protection and replay protection, records of
%% the next epoch held until ChangeCipherSpec, flight retransmission with
%% exponential back-off. The hello exchange uses the same plaintext
%% records before a version is chosen.
-module(webrtc_dtls12).

-include("webrtc_dtls.hrl").

-export([
    handle_records/3,
    record/3,
    peer_retransmitted/2,
    timeout/2,
    flush/2,
    encode_record/4,
    pack/2
]).

-import(webrtc_dtls, [emit/2]).

-define(MAX_HELD, 64).
-define(MAX_EARLY, 32).
-define(MAX_SEQ, 16#FFFFFFFFFFFF).

%%====================================================================
%% Inbound records
%%====================================================================

%% @doc Records of one datagram.
-spec handle_records([webrtc_dtls_record:dtls_record()], integer(), #dtls{}) -> #dtls{}.
handle_records(Recs, Now, St) ->
    lists:foldl(fun(R, Acc) -> record(R, Now, Acc) end, St, Recs).

%% @doc One record (also used for the hello exchange before a version is
%% chosen).
-spec record(webrtc_dtls_record:dtls_record(), integer(), #dtls{}) -> #dtls{}.
record(R, Now, St) ->
    handle_record(R, Now, St).

handle_record(_R, _Now, #dtls{state = S} = St) when S =:= failed; S =:= closed ->
    St;
handle_record(#{epoch := E} = R, Now, #dtls{read_epoch = RE} = St) when E =:= RE ->
    case open_record(R, St) of
        record_overflow ->
            %% RFC 5246 §6.2.1: an authentic record above 2^14 bytes of
            %% plaintext ends the connection.
            webrtc_dtls:fail(?ALERT_RECORD_OVERFLOW, record_overflow, St);
        {ok, Type, Plain} ->
            #{seq := Seq} = R,
            W = maps:get(E, St#dtls.replay, webrtc_dtls_record:replay_new()),
            case webrtc_dtls_record:replay_check(Seq, W) of
                ok ->
                    St1 = St#dtls{
                        replay = maps:put(E, webrtc_dtls_record:replay_update(Seq, W), St#dtls.replay)
                    },
                    content(Type, Plain, E, Now, St1);
                replay ->
                    St
            end;
        error ->
            %% RFC 6347 §4.1.2.7: invalid records are silently discarded.
            St
    end;
handle_record(#{epoch := 0, type := handshake, fragment := Frag, seq := Seq}, Now, #dtls{read_epoch = RE} = St) when
    RE > 0
->
    %% Plaintext retransmission of an earlier flight of the peer. A
    %% retransmission has a new sequence number; a record already seen is
    %% a replay and is dropped (RFC 6347 §4.1.2.6).
    W = maps:get(0, St#dtls.replay, webrtc_dtls_record:replay_new()),
    case webrtc_dtls_record:replay_check(Seq, W) of
        replay ->
            St;
        ok ->
            St1 = St#dtls{replay = maps:put(0, webrtc_dtls_record:replay_update(Seq, W), St#dtls.replay)},
            case webrtc_dtls_msg:decode_fragment(Frag) of
                {ok, [_ | _]} -> peer_retransmitted(Now, St1);
                _ -> St1
            end
    end;
handle_record(#{epoch := E} = R, _Now, #dtls{read_epoch = RE, pending_read = P, early = Early} = St) when
    E =:= RE + 1, P =/= undefined, length(Early) < ?MAX_EARLY
->
    St#dtls{early = [R | Early]};
handle_record(_R, _Now, St) ->
    St.

open_record(#{epoch := 0, type := T, fragment := F}, _St) when T =/= tls12_cid ->
    {ok, T, F};
open_record(#{epoch := 0}, _St) ->
    error;
open_record(R, #dtls{read_cipher = C} = St) when C =/= undefined ->
    %% RFC 9146 §6: a CID we do not receive on is not ours.
    case webrtc_dtls13_cid:known(maps:get(cid, R, <<>>), St) of
        true ->
            case webrtc_dtls_record:open(R, C) of
                {ok, T, P} -> {ok, T, P};
                {error, record_overflow} -> record_overflow;
                {error, _} -> error
            end;
        false ->
            error
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

handle_alert(Level, _Desc, _E, St) when Level =/= 1, Level =/= 2 ->
    webrtc_dtls:fail(?ALERT_ILLEGAL_PARAMETER, {bad_alert_level, Level}, St);
handle_alert(_Level, ?ALERT_CLOSE_NOTIFY, _E, St) ->
    {Dgrams, St1} = webrtc_dtls:alert_datagram(1, ?ALERT_CLOSE_NOTIFY, St),
    St2 = lists:foldl(fun(D, S) -> push({send, D}, S) end, St1, Dgrams),
    emit({closed, peer_closed}, St2#dtls{state = closed, rtx_at = infinity, building = []});
handle_alert(2, Desc, _E, St) ->
    emit({failed, {alert, Desc}}, St#dtls{state = failed, rtx_at = infinity, building = []});
handle_alert(_Level, _Desc, _E, St) ->
    St.

%%====================================================================
%% Peer retransmission
%%====================================================================

%% @doc The peer resent a flight we already processed: our reply was
%% lost, send our last flight again (§4.2.4). Rate limited to one resend
%% per half initial timeout so a flood of copies does not amplify.
-spec peer_retransmitted(integer(), #dtls{}) -> #dtls{}.
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

%% @doc Send the flight being built, if any, and arm the retransmission
%% timer when we expect an answer.
-spec flush(integer(), #dtls{}) -> #dtls{}.
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
overhead(E, #dtls{write_ciphers = Cs, peer_cid = Cid}) ->
    webrtc_dtls_record:overhead(maps:get(E, Cs), Cid) - 13.

%% @doc Encode one DTLS 1.2 record (plaintext in epoch 0).
-spec encode_record(webrtc_dtls_record:content_type(), non_neg_integer(), iodata(), #dtls{}) ->
    {ok, binary(), #dtls{}} | {error, sequence_exhausted}.
encode_record(Type, E, Data, #dtls{write_seq = Seqs} = St) ->
    Seq = maps:get(E, Seqs, 0),
    case Seq > ?MAX_SEQ of
        true ->
            {error, sequence_exhausted};
        false ->
            Rec =
                case E of
                    0 ->
                        webrtc_dtls_record:encode(Type, plain_version(St), 0, Seq, Data);
                    _ ->
                        %% RFC 9146: the peer's CID in records with
                        %% negotiated keys.
                        webrtc_dtls_record:protect(
                            Type, ?DTLS12, E, Seq, Data, maps:get(E, St#dtls.write_ciphers), St#dtls.peer_cid
                        )
                end,
            {ok, Rec, St#dtls{write_seq = Seqs#{E => Seq + 1}}}
    end.

%% Record version of plaintext records. Until the server picked a version
%% the client's ClientHello records carry DTLS 1.0, as RFC 9147 §4
%% allows for the initial ClientHello and DTLS 1.2 clients do, except
%% after a HelloRetryRequest, which RFC 9147 asks to carry {254, 253}.
plain_version(#dtls{role = client, version = undefined, hrr = false}) -> ?DTLS10;
plain_version(_) -> ?DTLS12.

%% @doc Pack records into datagrams of at most `Mtu' bytes.
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


%% @doc Flight retransmission timer (RFC 6347 §4.2.4).
-spec timeout(integer(), #dtls{}) -> {#dtls{}, [webrtc_dtls:action()]}.
timeout(Now, #dtls{rtx_at = At} = St) when At =/= infinity, Now >= At ->
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
timeout(_Now, St) ->
    {St, []}.

push(Action, #dtls{out = Out} = St) ->
    St#dtls{out = [Action | Out]}.
