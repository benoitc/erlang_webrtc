%% @doc Congestion control of one media session, as a sans-IO engine:
%% transport-wide sequence numbers and feedback
%% (`webrtc_twcc_sender', `webrtc_twcc_receiver'), the bandwidth
%% estimate (`webrtc_gcc'), the pacer (`webrtc_pacer') and the RTP
%% circuit breakers (`webrtc_circuit_breaker'). `webrtc_media' drives it.
%%
%% Send path: `enqueue/3' takes `{Class, Size, Data}' and returns the
%% `Data' that may leave now; `handle_timeout/2' returns the rest when
%% the pacer allows. For each packet that leaves, the caller puts
%% `twcc_seq/1' (when not `undefined') in the transport-wide-cc header
%% extension, then calls `sent/4' with the wire size.
%%
%% Pacing applies once the estimate is backed by feedback (transport-wide
%% feedback or REMB): before that, or when the peer gives no feedback at
%% all, the target is a guess and packets are not held back. The pacing
%% rate is `pacing_factor' x target. Retransmissions are limited to the
%% target bitrate over one second, as libwebrtc does: after a sudden
%% capacity drop, NACKs for everything lost would otherwise keep the
%% bottleneck overloaded. Retransmissions over the limit are dropped
%% and counted (`rtx_limited').
%%
%% Events: `{bandwidth_estimate, Bps}' and
%% `{circuit_breaker, Key, Reason}'.
%%
%% Circuit breakers (RFC 8083, mandatory in WebRTC per RFC 8834 §7.1):
%% the RTCP and media timeout breakers halt their stream (§4.5, the
%% sender ceases transmission): `halted/2' tells the media session to
%% stop sending RTP on it. The congestion breaker first cuts the target
%% to a tenth of the rate being sent, as §4.3 allows, and re-arms; if it
%% triggers again over the next CB_INTERVAL the stream is halted. The
%% cut is lifted once `circuit_breaker_hold' ms pass without a new
%% trigger. It is not restarted automatically; `resume/3' restarts it,
%% no sooner than `circuit_breaker_hold' ms (default 15000, the RTCP
%% timeout interval) after it tripped, so a retry loop cannot keep
%% overloading the path (RFC 8083 §4.5, RFC 8084).
%%
%% Probing (`webrtc_cc_probe'): with transport-wide feedback, the first
%% video packet starts probe clusters of padding packets ahead of the
%% estimate; their results lift it at once instead of the slow startup
%% ramp. Later it probes again while media is application limited,
%% after a large drop once the path recovers, and on a raised
%% `max_bitrate'.
%%
%% Options (all optional): `pacing' (default true), `probing' (default
%% true), `pacing_factor' (2.5), `burst_ms' (10), `max_queue_packets' (1000), `max_queue_ms'
%% (1000), `twcc_interval' (100), `rtcp_timeout' (15000),
%% `circuit_breaker_hold' (15000), and the
%% `webrtc_gcc' options `start_bitrate', `min_bitrate', `max_bitrate',
%% `startup_gain', `change_threshold', `feedback_timeout'.
-module(webrtc_cc).

-include("webrtc_rtp_rtcp.hrl").

-export([
    new/1,
    configure/2,
    set_options/3,
    enqueue/3,
    twcc_seq/1,
    sent/4,
    sent_probe/5,
    video_sent/2,
    arrival/4,
    rtcp/3,
    report/5,
    halted/2,
    resume/3,
    handle_timeout/2,
    next_timeout/1,
    target/1,
    stats/1
]).

-export_type([state/0, event/0]).

-type event() :: webrtc_gcc:event() | webrtc_circuit_breaker:event().

-define(GCC_OPTS, [start_bitrate, min_bitrate, max_bitrate, startup_gain, change_threshold, feedback_timeout]).

-record(cc, {
    pacing :: boolean(),
    factor :: float(),
    pacer :: webrtc_pacer:pacer(),
    gcc :: webrtc_gcc:state(),
    cb :: webrtc_circuit_breaker:state(),
    twcc_tx :: undefined | webrtc_twcc_sender:state(),
    twcc_rx :: undefined | webrtc_twcc_receiver:state(),
    twcc_interval :: pos_integer(),
    rtx_sent :: webrtc_cc_rate:rate(),
    %% Media sent (probe padding left out), for the ALR detector.
    media_sent :: webrtc_cc_rate:rate(),
    rtx_limited = 0 :: non_neg_integer(),
    unpaced = 0 :: non_neg_integer(),
    %% Streams halted by a circuit breaker: Key => {Reason, TrippedAt}.
    halted = #{} :: #{term() => {atom(), integer()}},
    %% Streams whose congestion breaker cut the rate: Key => Since.
    reduced = #{} :: #{term() => integer()},
    max_bitrate :: pos_integer(),
    hold :: pos_integer(),
    probe :: webrtc_cc_probe:state()
}).

-opaque state() :: #cc{}.

-spec new(map()) -> state().
new(Opts) ->
    Gcc = webrtc_gcc:new(maps:with(?GCC_OPTS, Opts)),
    Factor = float(maps:get(pacing_factor, Opts, 2.5)),
    #cc{
        hold = maps:get(circuit_breaker_hold, Opts, 15000),
        max_bitrate = maps:get(max_bitrate, Opts, 50000000),
        pacing = maps:get(pacing, Opts, true),
        factor = Factor,
        pacer = webrtc_pacer:new(#{
            rate => pacing_rate(Factor, webrtc_gcc:target(Gcc)),
            burst_ms => maps:get(burst_ms, Opts, 10),
            max_packets => maps:get(max_queue_packets, Opts, 1000),
            max_queue_ms => maps:get(max_queue_ms, Opts, 1000)
        }),
        gcc = Gcc,
        cb = webrtc_circuit_breaker:new(maps:with([rtcp_timeout], Opts)),
        twcc_interval = maps:get(twcc_interval, Opts, 100),
        rtx_sent = webrtc_cc_rate:new(1000),
        media_sent = webrtc_cc_rate:new(1000),
        probe = webrtc_cc_probe:new(maps:with([probing, max_bitrate], Opts))
    }.

%% @doc Turn transport-wide CC on for sending (the peer accepts the
%% extension) and for receiving (we offered it), `sender_ssrc' being
%% the SSRC our feedback is sent from.
-spec configure(#{twcc_send := boolean(), twcc_recv := boolean(), sender_ssrc := 0..16#FFFFFFFF}, state()) ->
    state().
configure(#{twcc_send := Send, twcc_recv := Recv, sender_ssrc := Ssrc}, Cc) ->
    Tx =
        case {Send, Cc#cc.twcc_tx} of
            {true, undefined} -> webrtc_twcc_sender:new(#{});
            {true, T} -> T;
            {false, _} -> undefined
        end,
    Rx =
        case {Recv, Cc#cc.twcc_rx} of
            {true, undefined} -> webrtc_twcc_receiver:new(#{sender_ssrc => Ssrc, interval => Cc#cc.twcc_interval});
            {true, R} -> R;
            {false, _} -> undefined
        end,
    Cc#cc{twcc_tx = Tx, twcc_rx = Rx}.

%% @doc Change options at run time: `pacing' (false releases every
%% queued packet), `pacing_factor', `min_bitrate', `max_bitrate'.
-spec set_options(map(), integer(), state()) -> {[term()], [event()], state()}.
set_options(Opts, Now, Cc0) ->
    {Events, Gcc} = webrtc_gcc:set_limits(maps:with([min_bitrate, max_bitrate], Opts), Cc0#cc.gcc),
    Max = maps:get(max_bitrate, Opts, Cc0#cc.max_bitrate),
    Probe = webrtc_cc_probe:max_raised(Now, Cc0#cc.max_bitrate, Max, webrtc_gcc:target(Cc0#cc.gcc), Cc0#cc.probe),
    Cc1 = retarget(Now, Cc0#cc{
        max_bitrate = Max,
        probe = Probe,
        gcc = Gcc,
        pacing = maps:get(pacing, Opts, Cc0#cc.pacing),
        factor = float(maps:get(pacing_factor, Opts, Cc0#cc.factor))
    }),
    case Cc1#cc.pacing of
        true ->
            {[], Events, Cc1};
        false ->
            {Pkts, P} = webrtc_pacer:flush(Cc1#cc.pacer),
            {[D || {_, _, D} <- Pkts], Events, Cc1#cc{pacer = P}}
    end.

-spec enqueue(webrtc_pacer:packet(), integer(), state()) -> {[term()], state()}.
enqueue({rtx, Size, _} = Pkt, Now, #cc{gcc = G, rtx_sent = R} = Cc) ->
    case webrtc_gcc:has_input(G) of
        false ->
            enqueue_paced(Pkt, Now, Cc);
        true ->
            case (webrtc_cc_rate:bytes(Now, R) + Size) * 8 > webrtc_gcc:target(G) of
                true -> {[], Cc#cc{rtx_limited = Cc#cc.rtx_limited + 1}};
                false -> enqueue_paced(Pkt, Now, Cc#cc{rtx_sent = webrtc_cc_rate:add(Now, Size, R)})
            end
    end;
enqueue(Pkt, Now, Cc) ->
    enqueue_paced(Pkt, Now, Cc).

enqueue_paced({_, _, Data} = Pkt, Now, Cc) ->
    case paced(Cc) of
        true ->
            {Out, P} = webrtc_pacer:enqueue(Pkt, Now, Cc#cc.pacer),
            {[D || {_, _, D} <- Out], Cc#cc{pacer = P}};
        false ->
            {[Data], Cc#cc{unpaced = Cc#cc.unpaced + 1}}
    end.

paced(#cc{pacing = P, gcc = G}) -> P andalso webrtc_gcc:has_input(G).

%% @doc The transport-wide sequence number for the next packet that
%% leaves, `undefined' when the extension is not negotiated.
-spec twcc_seq(state()) -> 0..65535 | undefined.
twcc_seq(#cc{twcc_tx = undefined}) -> undefined;
twcc_seq(#cc{twcc_tx = Tx}) -> webrtc_twcc_sender:next_seq(Tx).

%% @doc A packet of stream `Key' left with `Size' bytes on the wire.
-spec sent(term(), non_neg_integer(), integer(), state()) -> state().
sent(Key, Size, Now, Cc) ->
    Tx =
        case Cc#cc.twcc_tx of
            undefined -> undefined;
            T -> webrtc_twcc_sender:sent(Size, Now, T)
        end,
    Cc#cc{
        twcc_tx = Tx,
        media_sent = webrtc_cc_rate:add(Now, Size, Cc#cc.media_sent),
        gcc = webrtc_gcc:sent(Size, Now, Cc#cc.gcc),
        cb = webrtc_circuit_breaker:sent(Key, Size, Now, Cc#cc.cb)
    }.

%% @doc A probe padding packet of cluster `Cluster' left (see
%% `handle_timeout/2').
-spec sent_probe(term(), non_neg_integer(), integer(), pos_integer(), state()) -> state().
sent_probe(Key, Size, Now, Cluster, #cc{twcc_tx = Tx} = Cc) when Tx =/= undefined ->
    Cc#cc{
        twcc_tx = webrtc_twcc_sender:sent(Size, Now, {probe, Cluster}, Tx),
        gcc = webrtc_gcc:sent(Size, Now, Cc#cc.gcc),
        cb = webrtc_circuit_breaker:sent(Key, Size, Now, Cc#cc.cb)
    };
sent_probe(_Key, _Size, _Now, _Cluster, Cc) ->
    Cc.

%% @doc A video packet left: with transport-wide feedback the first
%% probes start (`webrtc_cc_probe').
-spec video_sent(integer(), state()) -> state().
video_sent(_Now, #cc{twcc_tx = undefined} = Cc) ->
    Cc;
video_sent(Now, #cc{probe = P, gcc = G} = Cc) ->
    Cc#cc{probe = webrtc_cc_probe:start(Now, webrtc_gcc:target(G), P)}.

%% @doc A packet carrying transport-wide sequence number `Seq' arrived.
-spec arrival(0..65535, 0..16#FFFFFFFF, integer(), state()) -> state().
arrival(_Seq, _Ssrc, _Now, #cc{twcc_rx = undefined} = Cc) ->
    Cc;
arrival(Seq, Ssrc, Now, #cc{twcc_rx = Rx} = Cc) ->
    Cc#cc{twcc_rx = webrtc_twcc_receiver:packet(Seq, Ssrc, Now, Rx)}.

%% @doc Congestion feedback from the peer: transport-wide feedback or
%% REMB. Other packets are ignored.
-spec rtcp(term(), integer(), state()) -> {[event()], state()}.
rtcp(#rtcp_twcc{} = Fb, Now, #cc{twcc_tx = Tx} = Cc) when Tx =/= undefined ->
    {Results, Tagged, Tx1} = webrtc_twcc_sender:tagged_feedback(Fb, Now, Tx),
    {Events, Gcc} = webrtc_gcc:feedback(Results, Now, Cc#cc.gcc),
    {Probed, Probe} = webrtc_cc_probe:feedback([{Id, S, A, Sz} || {{probe, Id}, S, A, Sz} <- Tagged], Now, Cc#cc.probe),
    {ProbeEvents, Gcc1} = lists:foldl(
        fun(Bps, {Ev, G}) -> {E, G1} = webrtc_gcc:probe_result(Bps, Now, G), {Ev ++ E, G1} end,
        {[], Gcc},
        Probed
    ),
    {Events ++ ProbeEvents, retarget(Now, follow(Now, Cc#cc{twcc_tx = Tx1, gcc = Gcc1, probe = Probe}))};
rtcp(#rtcp_remb{bitrate = Bps}, Now, Cc) ->
    {Events, Gcc} = webrtc_gcc:remb(Bps, Now, Cc#cc.gcc),
    {Events, retarget(Now, Cc#cc{gcc = Gcc})};
rtcp(_, _Now, Cc) ->
    {[], Cc}.

%% @doc A report block about stream `Key', with the round-trip time in
%% milliseconds when it could be computed.
-spec report(term(), #rtcp_rb{}, non_neg_integer() | undefined, integer(), state()) -> {[event()], state()}.
report(Key, #rtcp_rb{fraction_lost = F} = Rb, Rtt, Now, Cc) ->
    {E1, Cb} = webrtc_circuit_breaker:report(Key, Rb, Rtt, Now, Cc#cc.cb),
    G0 =
        case Rtt of
            undefined -> Cc#cc.gcc;
            _ -> webrtc_gcc:set_rtt(Rtt, Cc#cc.gcc)
        end,
    {E2, G1} = webrtc_gcc:loss_report(F, Now, G0),
    {E3, Cc1} = breakers(E1, Now, Cc#cc{cb = Cb, gcc = G1}),
    {E1 ++ E2 ++ E3, retarget(Now, Cc1)}.

%% Act on breaker events; returns new bandwidth events.
breakers(Events, Now, Cc0) ->
    lists:foldl(
        fun
            ({circuit_breaker, Key, congestion}, {Ev, Cc}) when not is_map_key(Key, Cc#cc.reduced) ->
                %% §4.3: first cut the rate by ten and look again.
                Sending = webrtc_gcc:sending_rate(Now, Cc#cc.gcc),
                Cap = max(1, Sending div 10),
                {E, G} = webrtc_gcc:set_limits(#{max_bitrate => Cap}, Cc#cc.gcc),
                Cb = webrtc_circuit_breaker:rearm_congestion(Key, Cc#cc.cb),
                {Ev ++ E, Cc#cc{gcc = G, cb = Cb, reduced = (Cc#cc.reduced)#{Key => Now}}};
            ({circuit_breaker, Key, Reason}, {Ev, #cc{halted = H} = Cc}) when not is_map_key(Key, H) ->
                {Ev, Cc#cc{halted = H#{Key => {Reason, Now}}}};
            (_, Acc) ->
                Acc
        end,
        {[], Cc0},
        Events
    ).

%% Lift the rate cut of streams whose congestion breaker stayed quiet
%% for the hold time.
lift(Now, #cc{reduced = R, hold = Hold} = Cc) ->
    Expired = [K || K := Since <- R, Now - Since >= Hold],
    case {Expired, maps:size(R) - length(Expired)} of
        {[], _} ->
            {[], Cc};
        {_, 0} ->
            {E, G} = webrtc_gcc:set_limits(#{max_bitrate => Cc#cc.max_bitrate}, Cc#cc.gcc),
            {E, Cc#cc{gcc = G, reduced = maps:without(Expired, R)}};
        {_, _} ->
            {[], Cc#cc{reduced = maps:without(Expired, R)}}
    end.

%% @doc `{true, Reason}' when a circuit breaker halted stream `Key'.
-spec halted(term(), state()) -> false | {true, atom()}.
halted(Key, #cc{halted = H}) ->
    case H of
        #{Key := {Reason, _}} -> {true, Reason};
        _ -> false
    end.

%% @doc Restart a stream halted by a circuit breaker, once the hold time
%% has passed.
-spec resume(term(), integer(), state()) -> {ok, state()} | {error, not_halted | {retry_after, pos_integer()}}.
resume(Key, Now, #cc{halted = H, hold = Hold} = Cc) ->
    case H of
        #{Key := {_, At}} when Now - At >= Hold -> {ok, Cc#cc{halted = maps:remove(Key, H)}};
        #{Key := {_, At}} -> {error, {retry_after, Hold - (Now - At)}};
        _ -> {error, not_halted}
    end.

%% @doc Returns the packets the pacer releases, followed by the probe
%% padding packets due (`{probe, Cluster, Size}': send one padding
%% packet of that size and report it with `sent_probe/5'), the
%% transport-wide feedback to send and events.
-spec handle_timeout(integer(), state()) -> {[term()], [#rtcp_twcc{}], [event()], state()}.
handle_timeout(Now, Cc000) ->
    Cc00 = follow(Now, Cc000),
    {Probes, Probe} = webrtc_cc_probe:handle_timeout(Now, Cc00#cc.probe),
    Cc0 = Cc00#cc{probe = Probe},
    {Pkts, P} = webrtc_pacer:handle_timeout(Now, Cc0#cc.pacer),
    {Fb, Rx} =
        case Cc0#cc.twcc_rx of
            undefined -> {[], undefined};
            R -> webrtc_twcc_receiver:handle_timeout(Now, R)
        end,
    {E1, G} = webrtc_gcc:handle_timeout(Now, Cc0#cc.gcc),
    {E2, Cb} = webrtc_circuit_breaker:handle_timeout(Now, Cc0#cc.cb),
    {E3, Cc1} = breakers(E2, Now, Cc0#cc{pacer = P, twcc_rx = Rx, gcc = G, cb = Cb}),
    {E4, Cc2} = lift(Now, Cc1),
    Cc = retarget(Now, Cc2),
    {[D || {_, _, D} <- Pkts] ++ Probes, Fb, E1 ++ E2 ++ E3 ++ E4, Cc}.

-spec next_timeout(state()) -> integer() | infinity.
next_timeout(#cc{} = Cc) ->
    lists:foldl(fun tmin/2, infinity, [
        webrtc_pacer:next_timeout(Cc#cc.pacer),
        case Cc#cc.twcc_rx of
            undefined -> infinity;
            R -> webrtc_twcc_receiver:next_timeout(R)
        end,
        webrtc_gcc:next_timeout(Cc#cc.gcc),
        webrtc_circuit_breaker:next_timeout(Cc#cc.cb),
        webrtc_cc_probe:next_timeout(Cc#cc.probe)
    ] ++ [Since + Cc#cc.hold || _ := Since <- Cc#cc.reduced]).

-spec target(state()) -> pos_integer().
target(#cc{gcc = G}) -> webrtc_gcc:target(G).

-spec stats(state()) -> map().
stats(#cc{} = Cc) ->
    #{
        target_bitrate => webrtc_gcc:target(Cc#cc.gcc),
        pacing => paced(Cc),
        unpaced => Cc#cc.unpaced,
        rtx_limited => Cc#cc.rtx_limited,
        pacer => webrtc_pacer:stats(Cc#cc.pacer),
        estimator => webrtc_gcc:info(Cc#cc.gcc),
        circuit_breakers => webrtc_circuit_breaker:stats(Cc#cc.cb),
        halted => maps:map(fun(_, {Reason, _}) -> Reason end, Cc#cc.halted),
        rate_cut => maps:keys(Cc#cc.reduced),
        probing => webrtc_cc_probe:info(Cc#cc.probe),
        twcc => #{
            send => Cc#cc.twcc_tx =/= undefined,
            receive_stats => case Cc#cc.twcc_rx of undefined -> undefined; R -> webrtc_twcc_receiver:stats(R) end
        }
    }.

%% The probe controller follows the estimate and what media sends.
follow(Now, #cc{gcc = G, probe = P} = Cc) ->
    Sending = case webrtc_cc_rate:rate(Now, Cc#cc.media_sent) of undefined -> 0; R -> R end,
    Cc#cc{probe = webrtc_cc_probe:update(Now, #{estimate => webrtc_gcc:target(G), sending => Sending,
                                                 delay_state => webrtc_gcc:delay_state(G)}, P)}.

retarget(Now, #cc{pacer = P, factor = F, gcc = G} = Cc) ->
    Rate = pacing_rate(F, webrtc_gcc:target(G)),
    case webrtc_pacer:rate(P) of
        Rate -> Cc;
        _ -> Cc#cc{pacer = webrtc_pacer:set_rate(Rate, Now, P)}
    end.

pacing_rate(Factor, Target) -> max(1, round(Factor * Target)).

tmin(infinity, B) -> B;
tmin(A, infinity) -> A;
tmin(A, B) -> min(A, B).
