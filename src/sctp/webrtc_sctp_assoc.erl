%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Sans-IO SCTP association (RFC 9260) for SCTP over DTLS
%% (RFC 8261), with partial reliability (RFC 3758, RFC 7496), stream
%% reconfiguration (RFC 6525), message interleaving (RFC 8260) and zero
%% checksum (RFC 9653).
%%
%% The engine follows the contract of docs/ARCHITECTURE.md: it never
%% does IO, reads the clock or starts timers. The owner feeds it the
%% decrypted DTLS application data with `handle_packet/3', calls
%% `handle_timeout/2' at the time returned by `next_timeout/1' and
%% executes the returned actions:
%%
%% - `{send, Bin}': send `Bin' as one DTLS application data record.
%% - `{event, Event}': report to the upper layer.
%%
%% Events:
%%
%% - `{connected, Info}' and `{restarted, Info}' (peer restart,
%%   §5.2.4 case A, all state was reset). `Info' holds the negotiated
%%   features: `message_interleaving', `partial_reliability',
%%   `stream_reconfig', `zero_checksum', `outbound_streams',
%%   `inbound_streams', `peer_rwnd'.
%% - `{message, StreamId, Ppid, Data}': a complete user message.
%% - `{message_too_large, StreamId}': a message over `max_message_size'
%%   was dropped; later data on the stream is dropped until it is reset.
%% - `{stream_reset, [StreamId]}': the peer reset these incoming streams
%%   (`[]' means all). The next message starts at sequence number 0.
%% - `{outgoing_stream_reset, [StreamId]}': a reset requested with
%%   `reset_streams/3' completed.
%% - `{stream_reset_failed, [StreamId], Result}': the peer refused it.
%% - `{buffered_amount_low, StreamId}': the bytes queued on the stream
%%   fell to the threshold set with `set_buffered_amount_low_threshold/3'.
%% - `{peer_error, [Cause]}': the peer sent an ERROR chunk.
%% - `{closed, Reason}': the association is over. Reasons: `shutdown',
%%   `aborted' (local abort), `{peer_abort, [Cause]}',
%%   `max_retransmissions', `handshake_timeout', `stale_cookie',
%%   `shutdown_timeout' (T5-shutdown-guard, 5 times `rto_max'),
%%   `{protocol_violation, Info}'.
%%
%% Options of `new/1' (all optional): `local_port', `remote_port'
%% (default 5000), `mtu' (largest SCTP packet, default 1200; the base
%% size of path MTU discovery), `max_mtu' (largest packet PLPMTUD probes
%% for, default `mtu': no discovery),
%% `outbound_streams', `inbound_streams' (default 65535),
%% `receive_buffer' (advertised window, default 1 MiB), `send_buffer'
%% (bytes queued and not yet sent, default 8 MiB), `max_message_size'
%% (largest incoming message, default 256 KiB), `rto_initial',
%% `rto_min', `rto_max' (ms, defaults 1000, 1000, 60000), `max_backoff'
%% (ms or `infinity', the default: the ceiling of the doubling after a
%% timer expires, see webrtc_sctp_ack:backoff/3), `max_burst'
%% (4), `max_retransmissions' (Association.Max.Retrans, 10, or
%% `infinity': never give up on the peer, the owner ends the association),
%% `max_init_retransmissions' (8), `cookie_lifetime' (ms, 60000),
%% `heartbeat_interval' (ms or `infinity', 30000), `sack_delay' (ms,
%% at most 500, default 200), `sack_frequency' (2), `interleaving'
%% (offer I-DATA, default false), `zero_checksum' (accept and send zero
%% checksums when the peer agrees, only valid over DTLS, default false),
%% `cookie_secret' (binary, default random) and `random_seed'
%% (deterministic tags and TSNs for tests).
-module(webrtc_sctp_assoc).

-include("webrtc_sctp_assoc.hrl").

-export([
    new/1,
    connect/2,
    send/6,
    reset_streams/3,
    shutdown/2,
    abort/2,
    abort/3,
    handle_packet/3,
    handle_timeout/2,
    next_timeout/1,
    buffered_amount/2,
    set_buffered_amount_low_threshold/3,
    set_stream_priority/3,
    stats/1,
    state/1,
    info/1,
    path_changed/2,
    reset_congestion/1
]).

-export_type([assoc/0, action/0, event/0, send_opts/0]).

-opaque assoc() :: #assoc{}.
-type action() :: {send, binary()} | {event, event()}.
-type event() ::
    {connected, map()}
    | {restarted, map()}
    | {message, 0..65535, 0..16#FFFFFFFF, binary()}
    | {message_too_large, 0..65535}
    | {stream_reset, [0..65535]}
    | {outgoing_stream_reset, [0..65535]}
    | {stream_reset_failed, [0..65535], term()}
    | {buffered_amount_low, 0..65535}
    | {peer_error, [term()]}
    | {closed, term()}.
-type send_opts() :: #{
    ordered => boolean(),
    max_retransmits => non_neg_integer() | infinity,
    max_lifetime => non_neg_integer() | infinity
}.

%%====================================================================
%% API
%%====================================================================

-spec new(map()) -> assoc().
new(Opts) when is_map(Opts) ->
    C = cfg(Opts),
    Rand =
        case maps:get(random_seed, Opts, undefined) of
            undefined -> crypto;
            Seed -> rand:seed_s(exsss, Seed)
        end,
    #assoc{
        cfg = C,
        snd = webrtc_sctp_send:new(C),
        rcv = webrtc_sctp_recv:new(C),
        rand = Rand,
        pmtu = webrtc_sctp_pmtu:new(C)
    }.

cfg(O) ->
    C = #cfg{
        local_port = opt(local_port, O, 5000, fun port/1),
        remote_port = opt(remote_port, O, 5000, fun port/1),
        mtu = opt(mtu, O, 1200, fun(V) -> is_integer(V) andalso V >= 256 andalso V =< 65535 end),
        max_mtu = opt(max_mtu, O, maps:get(mtu, O, 1200), fun(V) -> is_integer(V) andalso V >= 256 andalso V =< 65535 end),
        os = opt(outbound_streams, O, 65535, fun streams/1),
        mis = opt(inbound_streams, O, 65535, fun streams/1),
        rbuf = opt(receive_buffer, O, 1048576, fun(V) -> is_integer(V) andalso V >= 1500 end),
        send_buffer = opt(send_buffer, O, 8388608, fun pos/1),
        max_message_size = opt(max_message_size, O, 262144, fun pos/1),
        rto_initial = opt(rto_initial, O, 1000, fun pos/1),
        rto_min = opt(rto_min, O, 1000, fun pos/1),
        rto_max = opt(rto_max, O, 60000, fun pos/1),
        max_backoff = opt(max_backoff, O, infinity, fun(V) -> V =:= infinity orelse pos(V) end),
        max_burst = opt(max_burst, O, 4, fun pos/1),
        assoc_max_retrans = opt(max_retransmissions, O, 10, fun(V) -> V =:= infinity orelse nonneg(V) end),
        max_init_retrans = opt(max_init_retransmissions, O, 8, fun nonneg/1),
        cookie_life = opt(cookie_lifetime, O, 60000, fun pos/1),
        hb_interval = opt(heartbeat_interval, O, 30000, fun(V) -> V =:= infinity orelse pos(V) end),
        sack_delay = opt(sack_delay, O, 200, fun(V) ->
            is_integer(V) andalso V >= 0 andalso V =< 500
        end),
        sack_freq = opt(sack_frequency, O, 2, fun pos/1),
        interleaving = opt(interleaving, O, false, fun is_boolean/1),
        zero_checksum = opt(zero_checksum, O, false, fun is_boolean/1),
        secret =
            case maps:find(cookie_secret, O) of
                error -> crypto:strong_rand_bytes(32);
                {ok, _} -> opt(cookie_secret, O, <<>>, fun is_binary/1)
            end
    },
    C#cfg{rto_max = max(C#cfg.rto_max, C#cfg.rto_min)}.

opt(K, O, Def, Valid) ->
    V = maps:get(K, O, Def),
    case Valid(V) of
        true -> V;
        false -> error({badarg, K})
    end.

port(V) -> is_integer(V) andalso V >= 0 andalso V =< 65535.
streams(V) -> is_integer(V) andalso V >= 1 andalso V =< 65535.
pos(V) -> is_integer(V) andalso V > 0.
nonneg(V) -> is_integer(V) andalso V >= 0.

%% @doc Start the association: send INIT (no-op unless closed).
-spec connect(integer(), assoc()) -> {assoc(), [action()]}.
connect(Now, A) ->
    webrtc_sctp_out:take(webrtc_sctp_handshake:connect(Now, A)).

%% @doc Queue a user message. Messages sent before the association is
%% established wait in the queue. Options: `ordered' (default true) and
%% one partial reliability policy, `max_retransmits' or `max_lifetime'
%% (milliseconds, counted from this call).
-spec send(0..65535, 0..16#FFFFFFFF, binary(), send_opts(), integer(), assoc()) ->
    {ok, assoc(), [action()]} | {error, atom()}.
send(Sid, Ppid, Data, Opts, Now, #assoc{} = A) when
    is_integer(Sid),
    Sid >= 0,
    Sid =< 65535,
    is_integer(Ppid),
    Ppid >= 0,
    Ppid =< ?U32,
    is_binary(Data)
->
    case A#assoc.state of
        closed when A#assoc.terminated -> {error, closed};
        St when
            St =:= shutdown_pending;
            St =:= shutdown_sent;
            St =:= shutdown_received;
            St =:= shutdown_ack_sent
        ->
            {error, shutting_down};
        _ ->
            case webrtc_sctp_send:enqueue(Sid, Ppid, Data, Opts, Now, A#assoc.snd) of
                {ok, Snd} ->
                    {A1, Acts} = done(Now, A#assoc{snd = Snd}),
                    {ok, A1, Acts};
                {error, _} = E ->
                    E
            end
    end;
send(_, _, _, _, _, _) ->
    {error, badarg}.

%% @doc Reset outgoing streams (RFC 6525), used to close data channels.
%% The request is sent once every message queued on these streams has
%% been handed to SCTP.
-spec reset_streams([0..65535], integer(), assoc()) ->
    {ok, assoc(), [action()]} | {error, atom()}.
reset_streams(Sids, Now, #assoc{state = St} = A) when
    is_list(Sids), (St =:= established orelse St =:= shutdown_pending)
->
    case webrtc_sctp_reconfig:request(Sids, Now, A) of
        {ok, A1} ->
            {A2, Acts} = done(Now, A1),
            {ok, A2, Acts};
        {error, _} = E ->
            E
    end;
reset_streams(_Sids, _Now, _A) ->
    {error, not_connected}.

%% @doc Graceful shutdown (§9.2): queued data is sent and acknowledged
%% before SHUTDOWN.
-spec shutdown(integer(), assoc()) -> {assoc(), [action()]}.
shutdown(Now, #assoc{state = established} = A) ->
    done(Now, A#assoc{state = shutdown_pending});
shutdown(_Now, #assoc{state = St, terminated = false} = A) when
    St =:= closed; St =:= cookie_wait; St =:= cookie_echoed
->
    webrtc_sctp_out:take(webrtc_sctp_out:terminate(shutdown, A));
shutdown(_Now, A) ->
    {A, []}.

-spec abort(integer(), assoc()) -> {assoc(), [action()]}.
abort(Now, A) ->
    abort(<<>>, Now, A).

%% @doc Abort the association (§9.1); `Reason' goes into a User-Initiated
%% Abort cause when not empty.
-spec abort(binary(), integer(), assoc()) -> {assoc(), [action()]}.
abort(_Reason, _Now, #assoc{state = closed} = A) ->
    {A, []};
abort(Reason, _Now, #assoc{peer_vtag = Peer} = A) when is_binary(Reason) ->
    Causes =
        case Reason of
            <<>> -> [];
            _ -> [{user_abort, Reason}]
        end,
    A1 =
        case Peer of
            0 -> A;
            _ -> webrtc_sctp_out:raw(Peer, [{abort, false, Causes}], auto, A)
        end,
    webrtc_sctp_out:take(webrtc_sctp_out:terminate(aborted, A1)).

-spec buffered_amount(0..65535, assoc()) -> non_neg_integer().
buffered_amount(Sid, #assoc{snd = Snd}) ->
    webrtc_sctp_send:buffered_amount(Sid, Snd).

-spec set_buffered_amount_low_threshold(0..65535, non_neg_integer(), assoc()) -> assoc().
set_buffered_amount_low_threshold(Sid, Low, #assoc{snd = Snd} = A) when
    is_integer(Low), Low >= 0
->
    A#assoc{snd = webrtc_sctp_send:set_low_threshold(Sid, Low, Snd)}.

%% @doc Scheduling weight of an outgoing stream (RFC 8260 §3.6).
-spec set_stream_priority(0..65535, 0..65535, assoc()) -> assoc().
set_stream_priority(Sid, W, #assoc{snd = Snd} = A) ->
    A#assoc{snd = webrtc_sctp_send:set_priority(Sid, W, Snd)}.

-spec state(assoc()) -> atom().
state(#assoc{state = S}) -> S.

%% @doc Negotiated parameters (empty before establishment).
-spec info(assoc()) -> map().
info(#assoc{state = St, peer = P, snd = Snd, rcv = Rcv, pmtu = Pm}) ->
    (webrtc_sctp_pmtu:info(Pm))#{
        state => St,
        outbound_streams => Snd#snd.os,
        inbound_streams => Rcv#rcv.mis,
        message_interleaving => maps:get(idata, P, false),
        partial_reliability => maps:get(pr, P, false),
        stream_reconfig => maps:get(reconfig, P, false),
        zero_checksum => maps:get(zero_checksum, P, false)
    }.

%% @doc Counters and current congestion control state.
-spec stats(assoc()) -> map().
stats(#assoc{stats = S0, snd = Snd, rcv = Rcv, state = St, error_count = E, pmtu = Pm}) ->
    S1 = maps:merge(maps:merge(S0, Snd#snd.stats), Rcv#rcv.stats),
    S1#{
        pmtu => webrtc_sctp_pmtu:mtu(Pm),
        state => St,
        cwnd => Snd#snd.cwnd,
        ssthresh => Snd#snd.ssthresh,
        peer_rwnd => Snd#snd.rwnd,
        flight_size => Snd#snd.flight,
        outstanding_chunks => map_size(Snd#snd.out),
        rto => Snd#snd.rto,
        srtt => Snd#snd.srtt,
        buffered_amount => Snd#snd.buffered,
        a_rwnd => webrtc_sctp_recv:a_rwnd(Rcv),
        error_count => E
    }.

-spec next_timeout(assoc()) -> integer() | infinity.
next_timeout(#assoc{t1 = T1, t2 = T2, t5 = T5, hb_at = Hb, snd = Snd, rcv = Rcv} = A) ->
    lists:min([
        t(T1),
        t(T2),
        t(T5),
        t(Hb),
        webrtc_sctp_send:next_timeout(Snd),
        webrtc_sctp_recv:next_timeout(Rcv),
        webrtc_sctp_reconfig:next_timeout(A),
        webrtc_sctp_pmtu:next_timeout(A#assoc.pmtu)
    ]).

%% Integers sort before atoms, so `infinity' never wins lists:min/1.
t(undefined) -> infinity;
t({_, D, _, _}) -> D;
t({D, _}) -> D;
t(D) when is_integer(D) -> D.

%%====================================================================
%% Timers
%%====================================================================

-spec handle_timeout(integer(), assoc()) -> {assoc(), [action()]}.
handle_timeout(Now, A0) ->
    A1 = webrtc_sctp_handshake:t1_expired(Now, A0),
    A2 = t5_expired(Now, t2_expired(Now, A1)),
    A3 = t3_expired(Now, A2),
    A4 = heartbeat(Now, A3),
    A5 = reconfig_expired(Now, A4),
    A6 = webrtc_sctp_pmtu:timeout(Now, A5),
    done(Now, A6).

t2_expired(Now, #assoc{t2 = {D, Rto}, cfg = C, state = St} = A) when Now >= D ->
    case incr_error(A) of
        #assoc{state = closed} = A1 ->
            A1;
        A1 ->
            Rto1 = webrtc_sctp_ack:backoff(Rto, C#cfg.rto_max, C#cfg.max_backoff),
            A2 = A1#assoc{t2 = {Now + Rto1, Rto1}},
            case St of
                shutdown_sent ->
                    webrtc_sctp_out:ctrl({shutdown, webrtc_sctp_recv:cum_tsn(A2#assoc.rcv)}, A2);
                shutdown_ack_sent ->
                    webrtc_sctp_out:ctrl(shutdown_ack, A2);
                _ ->
                    A2#assoc{t2 = undefined}
            end
    end;
t2_expired(_Now, A) ->
    A.

%% §9.2: the shutdown we started took more than 5 times RTO.Max.
t5_expired(Now, #assoc{t5 = At, state = St} = A) when is_integer(At), Now >= At ->
    case St of
        S when S =:= shutdown_sent; S =:= shutdown_pending ->
            webrtc_sctp_out:terminate(shutdown_timeout, webrtc_sctp_out:abort_peer(A#assoc{t5 = undefined}));
        _ ->
            A#assoc{t5 = undefined}
    end;
t5_expired(_Now, A) ->
    A.

t3_expired(Now, #assoc{snd = #snd{t3 = T3} = Snd} = A) when is_integer(T3), Now >= T3 ->
    {Snd1, Counted} = webrtc_sctp_ack:handle_t3(Now, Snd),
    A1 = A#assoc{snd = Snd1},
    case Counted of
        true -> incr_error(webrtc_sctp_pmtu:black_hole(Now, A1));
        false -> A1
    end;
t3_expired(_Now, A) ->
    A.

reconfig_expired(Now, #assoc{state = St} = A) when St =/= closed ->
    case webrtc_sctp_reconfig:timeout(Now, A) of
        {A1, true} -> incr_error(A1);
        {A1, false} -> A1
    end;
reconfig_expired(_Now, A) ->
    A.

%% RFC 9260 §8.3: heartbeat an idle path, count unanswered ones.
heartbeat(Now, #assoc{hb_at = At, state = St, cfg = C, snd = Snd} = A) when
    is_integer(At), Now >= At, St =/= closed
->
    Ival = C#cfg.hb_interval,
    Rto = Snd#snd.rto,
    case Snd#snd.last_data_sent of
        T when is_integer(T), Now - T < Ival ->
            A#assoc{hb_at = T + Ival + Rto, hb_out = undefined};
        _ ->
            A1 =
                case A#assoc.hb_out of
                    undefined -> A;
                    _ -> incr_error(A)
                end,
            case A1#assoc.state of
                closed ->
                    A1;
                _ ->
                    {N1, A2} = webrtc_sctp_handshake:rand32(A1),
                    {N2, A3} = webrtc_sctp_handshake:rand32(A2),
                    Nonce = <<N1:32, N2:32>>,
                    Info = <<Nonce/binary, Now:64/signed>>,
                    A4 = A3#assoc{hb_out = {Nonce, Now}, hb_at = Now + Rto + Ival},
                    webrtc_sctp_out:bump(
                        heartbeats_sent, webrtc_sctp_out:ctrl({heartbeat, Info}, A4)
                    )
            end
    end;
heartbeat(_Now, A) ->
    A.

%% Association.Max.Retrans (§8.1): the peer is considered unreachable.
%% An ABORT still goes out, in case only the other direction is broken.
incr_error(#assoc{error_count = E, cfg = C} = A) ->
    %% `infinity' (a SHOULD of §8.1 not applied): the owner ends the
    %% association instead. WebRTC transports end it when ICE consent
    %% or DTLS ends, so a long outage the path survives does not close
    %% the data channels (RFC 8831 §6.2 still sees the peer unreachable
    %% through that path), as libwebrtc and Pion do.
    case C#cfg.assoc_max_retrans =/= infinity andalso E + 1 > C#cfg.assoc_max_retrans of
        true -> webrtc_sctp_out:terminate(max_retransmissions, webrtc_sctp_out:abort_peer(A));
        false -> A#assoc{error_count = E + 1}
    end.

%%====================================================================
%% Incoming packets
%%====================================================================

-spec handle_packet(binary(), integer(), assoc()) -> {assoc(), [action()]}.
handle_packet(Bin, Now, #assoc{cfg = C} = A) when is_binary(Bin) ->
    case webrtc_sctp_chunk:decode(Bin) of
        {error, _} ->
            webrtc_sctp_out:take(webrtc_sctp_out:bump(packets_invalid, A));
        {ok, #sctp_packet{src_port = Src, dst_port = Dst} = P} ->
            Ok =
                webrtc_sctp_chunk:checksum_ok(Bin, C#cfg.zero_checksum) andalso
                    Src =:= C#cfg.remote_port andalso Dst =:= C#cfg.local_port,
            case Ok of
                false ->
                    webrtc_sctp_out:take(webrtc_sctp_out:bump(packets_invalid, A));
                true ->
                    A1 = webrtc_sctp_out:bump(packets_received, A),
                    done_packet(Now, packet(P, Now, A1))
            end
    end.

packet(#sctp_packet{chunks = []}, _Now, A) ->
    A;
packet(#sctp_packet{vtag = 0, chunks = [#sctp_init{ack = false} = Init]}, Now, A) ->
    webrtc_sctp_handshake:handle_init(Init, Now, A);
packet(#sctp_packet{vtag = Vtag, chunks = Chunks} = P, Now, A) ->
    Alone = fun(#sctp_init{}) -> true; ({shutdown_complete, _}) -> true; (_) -> false end,
    case lists:any(fun(Ch) -> is_record(Ch, sctp_init) andalso not Ch#sctp_init.ack end, Chunks) orelse
        (length(Chunks) > 1 andalso lists:any(Alone, Chunks)) of
        true ->
            %% INIT must be alone with a zero tag (§8.5.1 A); INIT ACK and
            %% SHUTDOWN COMPLETE are never bundled either (§6.10).
            webrtc_sctp_out:bump(packets_invalid, A);
        false ->
            case Chunks of
                [{cookie_echo, Cookie} | Rest] ->
                    case webrtc_sctp_handshake:handle_cookie_echo(Cookie, Vtag, Now, A) of
                        {continue, A1} -> chunks(Rest, P, Now, A1);
                        {stop, A1} -> A1
                    end;
                _ when A#assoc.state =:= closed ->
                    webrtc_sctp_handshake:ootb(P, Now, A);
                [{abort, true, _} | _] when Vtag =:= A#assoc.peer_vtag, Vtag =/= 0 ->
                    chunks(Chunks, P, Now, A);
                [{shutdown_complete, true} | _] when Vtag =:= A#assoc.peer_vtag, Vtag =/= 0 ->
                    chunks(Chunks, P, Now, A);
                _ when Vtag =:= A#assoc.my_vtag ->
                    chunks(Chunks, P, Now, A);
                _ ->
                    webrtc_sctp_out:bump(packets_bad_vtag, A)
            end
    end.

chunks([], _P, _Now, A) ->
    A;
chunks([C | Rest], P, Now, A) ->
    case chunk(C, P, Now, A) of
        {continue, A1} -> chunks(Rest, P, Now, A1);
        {stop, A1} -> A1
    end.

-define(DATA_STATES(S),
    (S =:= established orelse S =:= shutdown_pending orelse S =:= shutdown_sent orelse
        S =:= shutdown_received)
).

chunk(#sctp_data{} = D, _P, _Now, #assoc{state = St, rcv = Rcv} = A) when ?DATA_STATES(St) ->
    case webrtc_sctp_recv:handle_data(D, Rcv) of
        {ok, Rcv1, Evs, Errs} ->
            A1 = lists:foldl(fun webrtc_sctp_out:event/2, A#assoc{rcv = Rcv1}, Evs),
            case Errs of
                [] -> {continue, A1};
                _ -> {continue, webrtc_sctp_out:ctrl({op_error, Errs}, A1)}
            end;
        {abort, Cause} ->
            {stop, protocol_abort(Cause, A)}
    end;
chunk(#sctp_sack{} = S, _P, Now, #assoc{state = St, snd = Snd} = A) when ?DATA_STATES(St) ->
    case webrtc_sctp_ack:handle_sack(S, Now, Snd) of
        {ok, Snd1, true} ->
            {continue, A#assoc{snd = Snd1, error_count = 0}};
        {ok, Snd1, false} ->
            {continue, A#assoc{snd = Snd1}};
        {error, protocol_violation} ->
            {stop, protocol_abort({protocol_violation, <<"SACK of unsent TSN">>}, A)}
    end;
chunk(#sctp_init{ack = true} = Ack, _P, Now, A) ->
    webrtc_sctp_handshake:handle_init_ack(Ack, Now, A);
chunk({heartbeat, Info}, _P, _Now, #assoc{state = St} = A) when
    St =/= closed, St =/= cookie_wait
->
    {continue, webrtc_sctp_out:ctrl({heartbeat_ack, Info}, A)};
chunk({heartbeat_ack, <<"PLPMTUD", _/binary>> = Info}, _P, Now, A) ->
    {continue, webrtc_sctp_pmtu:ack(Info, Now, A)};
chunk(
    {heartbeat_ack, <<Nonce:8/binary, Sent:64/signed>>}, _P, Now, #assoc{hb_out = {Nonce, _}} = A
) ->
    Snd = webrtc_sctp_ack:rtt_sample(Now - Sent, A#assoc.snd),
    {continue, A#assoc{snd = Snd, hb_out = undefined, error_count = 0}};
chunk({abort, T, Causes}, #sctp_packet{vtag = Vtag}, _Now, A) ->
    Valid =
        case T of
            false -> Vtag =:= A#assoc.my_vtag;
            true -> Vtag =:= A#assoc.peer_vtag andalso Vtag =/= 0
        end,
    case Valid of
        true -> {stop, webrtc_sctp_out:terminate({peer_abort, Causes}, A)};
        false -> {stop, A}
    end;
chunk({shutdown, Cum}, _P, Now, #assoc{state = St} = A) ->
    shutdown_chunk(St, Cum, Now, A);
chunk(shutdown_ack, #sctp_packet{vtag = Vtag}, _Now, #assoc{state = St} = A) ->
    if
        St =:= cookie_wait; St =:= cookie_echoed ->
            {stop, webrtc_sctp_out:raw(Vtag, [{shutdown_complete, true}], crc32c, A)};
        St =:= shutdown_sent; St =:= shutdown_ack_sent ->
            A1 = webrtc_sctp_out:raw(A#assoc.peer_vtag, [{shutdown_complete, false}], auto, A),
            {stop, webrtc_sctp_out:terminate(shutdown, A1)};
        true ->
            {continue, A}
    end;
chunk(
    {shutdown_complete, T}, #sctp_packet{vtag = Vtag}, _Now, #assoc{state = shutdown_ack_sent} = A
) ->
    Valid =
        case T of
            false -> Vtag =:= A#assoc.my_vtag;
            true -> Vtag =:= A#assoc.peer_vtag
        end,
    case Valid of
        true -> {stop, webrtc_sctp_out:terminate(shutdown, A)};
        false -> {stop, A}
    end;
chunk({op_error, Causes}, _P, Now, #assoc{state = St} = A) ->
    case lists:keyfind(stale_cookie, 1, Causes) of
        {stale_cookie, Usec} when St =:= cookie_echoed ->
            {stop, webrtc_sctp_handshake:handle_stale_cookie(Usec, Now, A)};
        _ ->
            {continue, webrtc_sctp_out:event({peer_error, Causes}, A)}
    end;
chunk(cookie_ack, _P, Now, A) ->
    {continue, webrtc_sctp_handshake:handle_cookie_ack(Now, A)};
chunk({Fwd, _, _} = F, _P, _Now, #assoc{state = St, rcv = Rcv} = A) when
    (Fwd =:= forward_tsn orelse Fwd =:= i_forward_tsn), ?DATA_STATES(St)
->
    case webrtc_sctp_recv:handle_forward_tsn(F, Rcv) of
        {ok, Rcv1, Evs} ->
            {continue, lists:foldl(fun webrtc_sctp_out:event/2, A#assoc{rcv = Rcv1}, Evs)};
        {abort, Cause} ->
            {stop, protocol_abort(Cause, A)}
    end;
chunk({reconfig, Params}, _P, Now, #assoc{state = St} = A) when ?DATA_STATES(St) ->
    {continue, webrtc_sctp_reconfig:handle(Params, Now, A)};
chunk({unknown_chunk, Type, _, _} = C, _P, _Now, A) ->
    {Action, Report} = webrtc_sctp_chunk:unrecognized_chunk_action(Type),
    A1 =
        case Report of
            true ->
                webrtc_sctp_out:ctrl(
                    {op_error, [{unrecognized_chunk, webrtc_sctp_chunk:encode_chunk(C)}]}, A
                );
            false ->
                A
        end,
    case Action of
        stop -> {stop, A1};
        skip -> {continue, A1}
    end;
chunk(_Other, _P, _Now, A) ->
    %% PAD, duplicate COOKIE ECHO, chunks not valid in this state.
    {continue, A}.

%% SHUTDOWN chunk (§9.2).
shutdown_chunk(St, Cum, Now, #assoc{snd = Snd} = A) when
    St =:= established; St =:= shutdown_pending; St =:= shutdown_received
->
    case webrtc_sctp_ack:handle_cum_ack(Cum, Now, Snd) of
        {ok, Snd1, _} ->
            {continue, A#assoc{snd = Snd1, state = shutdown_received}};
        {error, protocol_violation} ->
            {stop, protocol_abort({protocol_violation, <<"SHUTDOWN acks unsent TSN">>}, A)}
    end;
shutdown_chunk(shutdown_sent, _Cum, Now, #assoc{snd = Snd} = A) ->
    A1 = A#assoc{state = shutdown_ack_sent, t2 = {Now + Snd#snd.rto, Snd#snd.rto}},
    {continue, webrtc_sctp_out:ctrl(shutdown_ack, A1)};
shutdown_chunk(_St, _Cum, _Now, A) ->
    {continue, A}.

protocol_abort(Cause, #assoc{peer_vtag = Peer} = A) ->
    A1 = webrtc_sctp_out:raw(Peer, [{abort, false, [Cause]}], auto, A),
    webrtc_sctp_out:terminate({protocol_violation, Cause}, A1).

%%====================================================================
%% After each input
%%====================================================================

done_packet(Now, #assoc{state = St, rcv = Rcv0} = A0) when St =/= closed ->
    %% §9.2: in SHUTDOWN-SENT answer DATA with SACK and SHUTDOWN.
    A1 =
        case St =:= shutdown_sent andalso Rcv0#rcv.got_data of
            true ->
                Rto = (A0#assoc.snd)#snd.rto,
                A0x = A0#assoc{
                    rcv = Rcv0#rcv{sack_now = true}, t2 = {Now + Rto, Rto}, error_count = 0
                },
                webrtc_sctp_out:ctrl({shutdown, webrtc_sctp_recv:cum_tsn(Rcv0)}, A0x);
            false ->
                A0
        end,
    Rcv1 = webrtc_sctp_recv:packet_done(Now, A1#assoc.rcv),
    {Rcv2, Seqs, Evs} = webrtc_sctp_recv:check_deferred(Rcv1),
    A2 = lists:foldl(fun webrtc_sctp_out:event/2, A1#assoc{rcv = Rcv2}, Evs),
    done(Now, webrtc_sctp_reconfig:deferred_done(Seqs, A2));
done_packet(Now, A) ->
    done(Now, A).

done(Now, A) ->
    webrtc_sctp_out:take(webrtc_sctp_out:flush(Now, progress(Now, A))).

%% @doc The lower layer moved to another path (RFC 8261 §6.1, ICE
%% selected a new pair): path MTU back to the base and searched again,
%% congestion state and RTO back to their initial values (RFC 9260
%% §7.2.1, §6.3).
-spec path_changed(integer(), assoc()) -> {assoc(), [action()]}.
path_changed(Now, #assoc{state = established} = A0) ->
    A = webrtc_sctp_pmtu:path_changed(Now, A0),
    done(Now, A#assoc{snd = webrtc_sctp_send:reset_path(A#assoc.cfg, A#assoc.snd)});
path_changed(Now, A) ->
    done(Now, A).

%% @doc Restart congestion control, keeping the path's RTT and MTU: the
%% DSCP of the association changed (RFC 8837 §5).
-spec reset_congestion(assoc()) -> assoc().
reset_congestion(#assoc{snd = Snd} = A) ->
    A#assoc{snd = webrtc_sctp_send:reset_congestion(Snd)}.

%% Move a pending shutdown forward once all data is acknowledged.
progress(Now, #assoc{state = shutdown_pending, snd = Snd} = A) ->
    case webrtc_sctp_send:idle(Snd) of
        true ->
            Rto = Snd#snd.rto,
            Guard = case A#assoc.t5 of undefined -> Now + 5 * Snd#snd.rto_max; G -> G end,
            A1 = A#assoc{state = shutdown_sent, t2 = {Now + Rto, Rto}, t5 = Guard},
            webrtc_sctp_out:ctrl({shutdown, webrtc_sctp_recv:cum_tsn(A#assoc.rcv)}, A1);
        false ->
            A
    end;
progress(Now, #assoc{state = shutdown_received, snd = Snd} = A) ->
    case webrtc_sctp_send:idle(Snd) of
        true ->
            Rto = Snd#snd.rto,
            A1 = A#assoc{state = shutdown_ack_sent, t2 = {Now + Rto, Rto}},
            webrtc_sctp_out:ctrl(shutdown_ack, A1);
        false ->
            A
    end;
progress(_Now, A) ->
    A.
