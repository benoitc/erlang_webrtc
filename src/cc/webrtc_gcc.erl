%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Google Congestion Control (draft-ietf-rmcat-gcc-02), sender side,
%% as a sans-IO engine.
%%
%% Inputs:
%% <ul>
%% <li>`feedback/3': per-packet results of transport-wide feedback
%%     (`webrtc_twcc_sender:feedback/3'). They drive the delay-based
%%     controller (`webrtc_gcc_delay', `webrtc_gcc_aimd') with the
%%     acknowledged rate over 500 ms of arrivals as R_hat, and the
%%     loss-based controller.</li>
%% <li>`loss_report/3': the fraction lost of an RTCP receiver report,
%%     used by the loss-based controller while no transport-wide
%%     feedback has been received. With such a peer (RTP/AVPF without
%%     transport-cc, RFC 8834 §7.1) the first report seeds the estimate
%%     with the rate actually being sent, so a forwarded stream is not
%%     limited by the start guess; from then on the estimate is backed
%%     by input (pacing applies), drops on loss above 10% and, below 2%
%%     loss, never falls under the rate getting through.</li>
%% <li>`probe_result/3': the bitrate a probe cluster got through, which
%%     the delay-based estimate takes unless over-use is detected.</li>
%% <li>`remb/3': a receiver estimated maximum bitrate
%%     (draft-alvestrand-rmcat-remb), an upper bound of the
%%     estimate.</li>
%% <li>`set_rtt/2': round-trip time from RTCP reports. Without it the
%%     RTT is estimated from feedback (send time of the newest packet
%%     reported to the feedback arrival).</li>
%% <li>`sent/3': every packet sent, for the feedback timeout.</li>
%% </ul>
%%
%% Loss-based controller (§6), run once at least 20 packets have been
%% reported since the previous run (as libwebrtc does, so that a single
%% loss in a small report does not count as 20%), or one second has
%% passed. Only packets sent after the last decrease (of either
%% controller) count: losses of packets sent at the old rate say nothing
%% about the new one, and would cut the rate twice. Below 2% loss the
%% estimate As_hat grows by 5%, and keeps growing by 5% per feedback
%% report without loss until the next run (§6 runs the controller on
%% every report); between 2% and 10% it is held at the
%% current target, above 10% it becomes target x (1 - 0.5 p), at most
%% once per 300 ms + RTT. The target is min(A_hat, As_hat, REMB),
%% clamped to [min, max] bitrate.
%%
%% Lack of feedback (RFC 8836 §2 item 10): when packets were sent but no
%% feedback arrived for `feedback_timeout' ms (default 1500) after
%% feedback had been flowing, the target is cut by 20%, once per
%% timeout.
%%
%% Output: `target/1', and `{bandwidth_estimate, Bps}' events returned
%% by every call that may change it, when the target moved by more than
%% `change_threshold' (default 0.05) of the last reported value. No
%% estimate is reported before the first feedback, receiver report or
%% REMB.
-module(webrtc_gcc).

-export([
    new/1,
    feedback/3,
    loss_report/3,
    remb/3,
    probe_result/3,
    set_rtt/2,
    sent/3,
    handle_timeout/2,
    next_timeout/1,
    target/1,
    has_input/1,
    sending_rate/2,
    delay_state/1,
    set_limits/2,
    info/1
]).

-export_type([state/0, event/0]).

-type event() :: {bandwidth_estimate, pos_integer()}.

-define(LOSS_MIN_PACKETS, 20).

-record(gcc, {
    min :: pos_integer(),
    max :: pos_integer(),
    start :: pos_integer(),
    delay :: webrtc_gcc_delay:state(),
    aimd :: webrtc_gcc_aimd:state(),
    acked :: webrtc_cc_rate:rate(),
    delay_active = false :: boolean(),
    %% Receiver reports drive the loss-based estimate (no transport-cc).
    rr_active = false :: boolean(),
    sent_rate :: webrtc_cc_rate:rate(),
    loss_based :: pos_integer(),
    loss_rx = 0 :: non_neg_integer(),
    loss_lost = 0 :: non_neg_integer(),
    last_loss_decrease :: undefined | integer(),
    last_loss_eval :: undefined | integer(),
    last_loss_ratio = 0.0 :: float(),
    %% Send time (us) from which packets count for the loss ratio.
    loss_from = undefined :: undefined | integer(),
    remb :: undefined | pos_integer(),
    rtt = 100 :: pos_integer(),
    rtt_from_rr = false :: boolean(),
    target :: pos_integer(),
    reported :: undefined | pos_integer(),
    change_threshold :: float(),
    last_feedback :: undefined | integer(),
    last_sent :: undefined | integer(),
    last_cut :: undefined | integer(),
    feedback_timeout :: pos_integer()
}).

-opaque state() :: #gcc{}.

%% @doc Options: `start_bitrate' (default 300000), `min_bitrate'
%% (30000), `max_bitrate' (50000000), `startup_gain' (1.5),
%% `change_threshold' (0.05), `feedback_timeout' (1500).
-spec new(map()) -> state().
new(Opts) ->
    Min = maps:get(min_bitrate, Opts, 30000),
    Max = maps:get(max_bitrate, Opts, 50000000),
    Start = min(max(maps:get(start_bitrate, Opts, 300000), Min), Max),
    #gcc{
        min = Min,
        max = Max,
        start = Start,
        delay = webrtc_gcc_delay:new(),
        aimd = webrtc_gcc_aimd:new(#{
            start => Start, min => Min, max => Max, startup_gain => maps:get(startup_gain, Opts, 1.5)
        }),
        acked = webrtc_cc_rate:new(500),
        sent_rate = webrtc_cc_rate:new(1000),
        loss_based = Max,
        target = Start,
        change_threshold = maps:get(change_threshold, Opts, 0.05),
        feedback_timeout = maps:get(feedback_timeout, Opts, 1500)
    }.

-spec target(state()) -> pos_integer().
target(#gcc{target = T}) -> T.

%% @doc True once an estimate is backed by feedback (transport-wide
%% feedback, receiver reports or REMB).
-spec has_input(state()) -> boolean().
has_input(#gcc{delay_active = D, rr_active = RR, remb = R}) -> D orelse RR orelse R =/= undefined.

-spec feedback([webrtc_twcc_sender:result()], integer(), state()) -> {[event()], state()}.
feedback([], _Now, G) ->
    {[], G};
feedback(Results, Now, G0) ->
    %% `{S, A, Sz, ce}': received but CE marked, which counts as a loss
    %% for the loss-based estimate (RFC 3168 §5, RFC 8888 §6).
    Received = [{S, A, Sz} || {S, A, Sz} <- Results, A =/= lost] ++ [{S, A, Sz} || {S, A, Sz, ce} <- Results],
    G1 = (from_reports(G0))#gcc{delay_active = true, last_feedback = Now},
    G2 =
        case Received of
            [] -> G1;
            _ -> delay_based(Received, Now, G1)
        end,
    %% Send times come from the monotonic clock, which may be negative:
    %% until a decrease restarts the count, every packet counts.
    Marks = [{S, case R of {_, _, _, ce} -> lost; _ -> element(2, R) end} || R <- Results, S <- [element(1, R)]],
    Counted =
        case G2#gcc.loss_from of
            undefined -> [A || {_, A} <- Marks];
            From -> [A || {S, A} <- Marks, S >= From]
        end,
    Lost = length([lost || lost <- Counted]),
    G3 = loss_counts(length(Counted) - Lost, Lost, Now, G2),
    update_target(G3).

%% Receiver reports drove the loss-based estimate until now (one can
%% arrive before the first transport-wide feedback): from here the
%% feedback drives it, so the value seeded from the reports is released.
from_reports(#gcc{rr_active = true} = G) -> G#gcc{rr_active = false, loss_based = G#gcc.max};
from_reports(G) -> G.

delay_based(Received, Now, G) ->
    Acked = lists:foldl(fun({_, A, Sz}, R) -> webrtc_cc_rate:add(A div 1000, Sz, R) end, G#gcc.acked, Received),
    LastArr = lists:max([A || {_, A, _} <- Received]) div 1000,
    G1 = feedback_rtt(lists:max([S || {S, _, _} <- Received]), Now, G#gcc{acked = Acked}),
    {Signal, D} = webrtc_gcc_delay:batch([{S, A} || {S, A, _} <- Received], G1#gcc.delay),
    RHat = webrtc_cc_rate:rate(LastArr, Acked),
    Aimd = webrtc_gcc_aimd:update(Signal, RHat, G1#gcc.rtt, Now, G1#gcc.aimd),
    G2 = G1#gcc{delay = D, aimd = Aimd},
    case webrtc_gcc_aimd:last_decrease(Aimd) =:= webrtc_gcc_aimd:last_decrease(G1#gcc.aimd) of
        true -> G2;
        false -> loss_restart(Now, G2)
    end.

%% Count losses again from packets sent now.
loss_restart(Now, G) ->
    G#gcc{loss_from = Now * 1000, loss_rx = 0, loss_lost = 0, last_loss_eval = Now}.

feedback_rtt(_NewestSendUs, _Now, #gcc{rtt_from_rr = true} = G) ->
    G;
feedback_rtt(NewestSendUs, Now, #gcc{rtt = Rtt} = G) ->
    Sample = max(1, Now - NewestSendUs div 1000),
    G#gcc{rtt = max(1, round(0.875 * Rtt + 0.125 * Sample))}.

loss_counts(Rx, Lost, Now, G) ->
    Rx1 = G#gcc.loss_rx + Rx,
    Lost1 = G#gcc.loss_lost + Lost,
    N = Rx1 + Lost1,
    Last =
        case G#gcc.last_loss_eval of
            undefined -> Now;
            L -> L
        end,
    case N >= ?LOSS_MIN_PACKETS orelse (N > 0 andalso Now - Last >= 1000) of
        true ->
            P = Lost1 / N,
            loss_based(P, Now, G#gcc{loss_rx = 0, loss_lost = 0, last_loss_eval = Now, last_loss_ratio = P});
        false when Lost1 =:= 0, Rx > 0, G#gcc.last_loss_ratio < 0.02 ->
            G1 = G#gcc{loss_rx = Rx1, loss_lost = Lost1, last_loss_eval = Last},
            G1#gcc{loss_based = min(round(G1#gcc.loss_based * 1.05), G1#gcc.max)};
        false ->
            G#gcc{loss_rx = Rx1, loss_lost = Lost1, last_loss_eval = Last}
    end.

%% draft-ietf-rmcat-gcc-02 §6.
loss_based(P, _Now, #gcc{loss_based = As, max = Max} = G) when P < 0.02 ->
    G#gcc{loss_based = min(round(As * 1.05), Max)};
loss_based(P, _Now, #gcc{loss_based = As, target = T} = G) when P =< 0.10 ->
    G#gcc{loss_based = min(As, T)};
loss_based(P, Now, #gcc{loss_based = As, target = T, last_loss_decrease = Last, rtt = Rtt} = G) ->
    case Last =:= undefined orelse Now - Last >= 300 + Rtt of
        true ->
            New = max(round(min(As, T) * (1 - 0.5 * P)), G#gcc.min),
            loss_restart(Now, G#gcc{loss_based = New, last_loss_decrease = Now});
        false ->
            G#gcc{loss_based = min(As, T)}
    end.

%% @doc Fraction lost (0..255) of an RTCP report block for one of our
%% streams. Ignored once transport-wide feedback drives the estimate.
-spec loss_report(0..255, integer(), state()) -> {[event()], state()}.
loss_report(_Fraction, _Now, #gcc{delay_active = true} = G) ->
    {[], G};
loss_report(Fraction, Now, #gcc{rr_active = false} = G) ->
    Seed =
        case webrtc_cc_rate:rate(Now, G#gcc.sent_rate) of
            undefined -> G#gcc.start;
            0 -> G#gcc.start;
            R -> R
        end,
    S = min(max(Seed, G#gcc.min), G#gcc.max),
    loss_report(Fraction, Now, G#gcc{rr_active = true, loss_based = S, target = S});
loss_report(Fraction, Now, G) ->
    P = Fraction / 256,
    G1 = loss_based(P, Now, G),
    G2 =
        case P < 0.02 of
            %% The rate getting through without loss is a floor.
            true ->
                case webrtc_cc_rate:rate(Now, G1#gcc.sent_rate) of
                    undefined -> G1;
                    Sent -> G1#gcc{loss_based = min(max(G1#gcc.loss_based, Sent), G1#gcc.max)}
                end;
            false ->
                G1
        end,
    update_target(G2).

%% @doc The bitrate a probe cluster got through (`webrtc_cc_probe'):
%% the delay-based estimate jumps to it, unless the detector sees
%% over-use (libwebrtc's DelayBasedBwe does the same). The loss-based
%% estimate is lifted to it too, as libwebrtc's SetSendBitrate does: a
%% lower `max_bitrate' or a feedback timeout may have cut it.
-spec probe_result(pos_integer(), integer(), state()) -> {[event()], state()}.
probe_result(Bps, _Now, #gcc{delay_active = true, delay = D, aimd = A} = G) ->
    case maps:get(state, webrtc_gcc_delay:info(D)) of
        overuse ->
            {[], G};
        _ ->
            update_target(G#gcc{
                aimd = webrtc_gcc_aimd:set_rate(max(Bps, webrtc_gcc_aimd:rate(A)), A),
                loss_based = min(max(Bps, G#gcc.loss_based), G#gcc.max)
            })
    end;
probe_result(_Bps, _Now, G) ->
    {[], G}.

-spec remb(non_neg_integer(), integer(), state()) -> {[event()], state()}.
remb(Bps, _Now, G) ->
    update_target(G#gcc{remb = max(Bps, 1)}).

-spec set_rtt(non_neg_integer(), state()) -> state().
set_rtt(Ms, G) ->
    G#gcc{rtt = max(1, Ms), rtt_from_rr = true}.

%% @doc Bits per second sent over the last second (0 before a full second).
-spec sending_rate(integer(), state()) -> non_neg_integer().
sending_rate(Now, #gcc{sent_rate = R}) ->
    case webrtc_cc_rate:rate(Now, R) of
        undefined -> 0;
        Bps -> Bps
    end.

%% @doc The delay detector's signal: `normal', `overuse' or `underuse'.
-spec delay_state(state()) -> atom().
delay_state(#gcc{delay = D}) -> maps:get(state, webrtc_gcc_delay:info(D)).

-spec sent(non_neg_integer(), integer(), state()) -> state().
sent(Size, Now, G) ->
    G#gcc{last_sent = Now, sent_rate = webrtc_cc_rate:add(Now, Size, G#gcc.sent_rate)}.

%% @doc Change the bitrate limits (`min_bitrate', `max_bitrate').
-spec set_limits(map(), state()) -> {[event()], state()}.
set_limits(Opts, #gcc{} = G) ->
    Min = maps:get(min_bitrate, Opts, G#gcc.min),
    Max = max(Min, maps:get(max_bitrate, Opts, G#gcc.max)),
    update_target(G#gcc{
        min = Min,
        max = Max,
        aimd = webrtc_gcc_aimd:set_limits(Min, Max, G#gcc.aimd),
        loss_based = min(G#gcc.loss_based, Max)
    }).

-spec next_timeout(state()) -> integer() | infinity.
next_timeout(#gcc{last_feedback = undefined}) ->
    infinity;
next_timeout(#gcc{last_sent = undefined}) ->
    infinity;
next_timeout(#gcc{last_feedback = F, last_sent = S}) when S =< F ->
    infinity;
next_timeout(#gcc{last_feedback = F, last_cut = C, feedback_timeout = T}) ->
    case C of
        undefined -> F + T;
        _ -> max(F, C) + T
    end.

-spec handle_timeout(integer(), state()) -> {[event()], state()}.
handle_timeout(Now, G) ->
    case next_timeout(G) of
        infinity ->
            {[], G};
        At when Now >= At ->
            T = G#gcc.target,
            Cut = max(round(T * 0.8), G#gcc.min),
            Aimd = webrtc_gcc_aimd:set_rate(min(Cut, webrtc_gcc_aimd:rate(G#gcc.aimd)), G#gcc.aimd),
            update_target(G#gcc{aimd = Aimd, loss_based = min(G#gcc.loss_based, Cut), last_cut = Now});
        _ ->
            {[], G}
    end.

-spec info(state()) -> map().
info(#gcc{} = G) ->
    #{
        target => G#gcc.target,
        delay_based => case G#gcc.delay_active of true -> webrtc_gcc_aimd:rate(G#gcc.aimd); false -> undefined end,
        loss_based => G#gcc.loss_based,
        remb => G#gcc.remb,
        rtt => G#gcc.rtt,
        detector => webrtc_gcc_delay:info(G#gcc.delay),
        controller => webrtc_gcc_aimd:info(G#gcc.aimd)
    }.

update_target(#gcc{} = G) ->
    Bounds = [G#gcc.loss_based]
        ++ [webrtc_gcc_aimd:rate(G#gcc.aimd) || G#gcc.delay_active]
        ++ [R || R <- [G#gcc.remb], R =/= undefined]
        ++ [G#gcc.start || not has_input(G)],
    T = min(max(lists:min(Bounds), G#gcc.min), G#gcc.max),
    G1 = G#gcc{target = T},
    case has_input(G1) andalso changed(T, G1#gcc.reported, G1#gcc.change_threshold) of
        true -> {[{bandwidth_estimate, T}], G1#gcc{reported = T}};
        false -> {[], G1}
    end.

changed(_T, undefined, _) -> true;
changed(T, R, Th) -> abs(T - R) > Th * R.
