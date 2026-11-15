%% @doc RTCP transmission scheduler of a media session: when regular
%% reports go out (RFC 3550 §6.3 and Appendix A.7 with the RTP/AVPF rules
%% of RFC 4585 §3.5) and whether feedback can be sent now under the RTCP
%% bandwidth (RFC 4585 §3.5.2, RFC 8834 §5.1).
%%
%% The interval itself comes from `webrtc_rtcp_interval'; this module
%% keeps the scheduler state: the time of the last regular report (tp),
%% the next one (tn), the average compound size, the membership counts
%% and the feedback budget. It is a pure value: every call takes the
%% current time in milliseconds and returns the new state.
%%
%% ```
%% S0 = webrtc_rtcp_sched:new(Now, #{session_bandwidth => 2000000}),
%% Deadline = webrtc_rtcp_sched:next_timeout(S0),
%% %% at the deadline:
%% case webrtc_rtcp_sched:expire(Now, S0) of
%%     {send, S1} -> %% build the compound, then
%%                   webrtc_rtcp_sched:regular_sent(Now, Size, S1);
%%     {wait, S1} -> S1
%% end,
%% %% feedback to send:
%% case webrtc_rtcp_sched:feedback(Now, Size, S) of
%%     {now, S1} -> %% send it
%%     {later, S1} -> %% keep it; next_timeout/1 says when to retry
%% end.
%% '''
%%
%% Regular reports. The first one goes out after the AVPF initial
%% interval (Tmin 0 point to point, RFC 4585 §3.4 d), so the peer gets
%% an RTT and loss report early. Later ones use the RFC 3550 interval
%% computed from the RTCP bandwidth (5% of the session bandwidth), the
%% membership and the average compound size, randomised and reconsidered
%% at expiry (§6.3.6), and never closer than the local T_rr_interval
%% (`report_interval', RFC 4585 §3.5.3), dithered in [0.5, 1.5).
%%
%% Feedback (NACK, PLI, FIR, transport-wide congestion control). AVPF
%% point to point has no dithering (T_dither_max is 0, §3.5.2): feedback
%% goes out at once while the budget allows. The budget refills at the
%% RTCP bandwidth and holds one second of it (at least one full
%% datagram). Feedback that does not fit waits until it does, instead
%% of the next regular report as early mode would (§3.5.2 step 4):
%% waiting a regular interval would make retransmission requests
%% useless and starve congestion control.
%%
%% Sizes passed in are the SRTCP datagram sizes; 28 octets of IPv4 and
%% UDP header are added for the average (§6.3.3 counts lower layers).
%%
%% Options of `new/2':
%% <ul>
%% <li>`session_bandwidth' (bit/s, default 600000): both directions;
%% the RTCP bandwidth is 5% of it.</li>
%% <li>`report_interval' (ms, default 1000, 0 for none): the local
%% T_rr_interval, a floor on the regular interval.</li>
%% <li>`members' and `senders' (default 2 and 1).</li>
%% <li>`uniform': a zero-arity fun returning a float in [0, 1), the
%% randomisation source (default `webrtc_rtcp_interval:uniform/0').</li>
%% </ul>
-module(webrtc_rtcp_sched).

-export([
    new/2,
    next_timeout/1,
    expire/2,
    regular_sent/3,
    feedback/3,
    set_session_bandwidth/2,
    set_membership/5,
    info/1
]).

-export_type([state/0]).

%% IPv4 and UDP headers counted in the average size.
-define(LOWER_HEADERS, 28).
-define(MIN_SESSION_BW, 64000).
-define(MIN_BUDGET, 1500).

-record(sched, {
    tp :: undefined | integer(),
    tn :: integer() | infinity,
    initial = true :: boolean(),
    avg_size = 100.0 :: float(),
    members = 2 :: pos_integer(),
    senders = 1 :: non_neg_integer(),
    we_sent = false :: boolean(),
    session_bw :: pos_integer(),
    trr :: non_neg_integer(),
    tokens :: float(),
    tokens_at :: integer(),
    %% A feedback packet waits for the budget until then.
    retry_at = infinity :: integer() | infinity,
    uniform :: fun(() -> float())
}).

-opaque state() :: #sched{}.

-spec new(integer(), map()) -> state().
new(Now, Opts) ->
    S = #sched{
        tn = Now,
        members = maps:get(members, Opts, 2),
        senders = maps:get(senders, Opts, 1),
        session_bw = max(?MIN_SESSION_BW, maps:get(session_bandwidth, Opts, 600000)),
        trr = maps:get(report_interval, Opts, 1000),
        tokens = 0.0,
        tokens_at = Now,
        uniform = maps:get(uniform, Opts, fun webrtc_rtcp_interval:uniform/0)
    },
    S#sched{tn = Now + interval(S), tokens = budget(S)}.

%% @doc The earliest time something is due: the next regular report or
%% a feedback retry.
-spec next_timeout(state()) -> integer() | infinity.
next_timeout(#sched{tn = Tn, retry_at = R}) ->
    tmin(Tn, R).

%% @doc The regular report timer expired (Appendix A.7 OnExpire): `send'
%% when the reconsidered interval since the last report has elapsed,
%% otherwise `wait' with the timer moved.
-spec expire(integer(), state()) -> {send | wait, state()}.
expire(Now, #sched{tn = Tn} = S) when Tn =:= infinity; Now < Tn ->
    {wait, S};
expire(_Now, #sched{tp = undefined} = S) ->
    {send, S};
expire(Now, #sched{tp = Tp} = S) ->
    case Tp + interval(S) of
        T when T =< Now -> {send, S};
        T -> {wait, S#sched{tn = T}}
    end.

%% @doc A regular compound of `Size' octets went out at `Now'.
-spec regular_sent(integer(), non_neg_integer(), state()) -> state().
regular_sent(Now, Size, S0) ->
    S = (avg(Size, S0))#sched{tp = Now, initial = false},
    S#sched{tn = Now + interval(S)}.

%% @doc Can a feedback packet of `Size' octets go out now? `later'
%% sets the retry time returned by `next_timeout/1'.
-spec feedback(integer(), non_neg_integer(), state()) -> {now | later, state()}.
feedback(Now, Size, S0) ->
    S = refill(Now, S0),
    Need = float(min(Size, budget(S))),
    case S#sched.tokens >= Need of
        true ->
            {now, avg(Size, S#sched{tokens = S#sched.tokens - Need, retry_at = infinity})};
        false ->
            Rate = rtcp_bw(S) / 1000,
            Wait = ceil((Need - S#sched.tokens) / Rate),
            {later, S#sched{retry_at = Now + max(1, Wait)}}
    end.

%% @doc The session bandwidth changed (bit/s, both directions).
-spec set_session_bandwidth(non_neg_integer(), state()) -> state().
set_session_bandwidth(Bps, S) ->
    S#sched{session_bw = max(?MIN_SESSION_BW, Bps)}.

%% @doc New membership: `Members' participants, `Senders' of them sent
%% RTP, `WeSent' when we did since the last report. When members
%% leave, the timers move closer (reverse reconsideration, §6.3.4).
-spec set_membership(integer(), pos_integer(), non_neg_integer(), boolean(), state()) -> state().
set_membership(Now, Members, Senders, WeSent, #sched{members = Old, tn = Tn, tp = Tp} = S) ->
    S1 = S#sched{members = max(1, Members), senders = Senders, we_sent = WeSent},
    case Members < Old andalso is_integer(Tn) andalso is_integer(Tp) of
        true ->
            {Tn1, Tp1} = webrtc_rtcp_interval:reverse_reconsider(Now, Tn, Tp, max(1, Members), Old),
            S1#sched{tn = round(Tn1), tp = round(Tp1)};
        false ->
            S1
    end.

-spec info(state()) -> map().
info(#sched{} = S) ->
    #{
        next_report => S#sched.tn,
        last_report => S#sched.tp,
        avg_rtcp_size => round(S#sched.avg_size),
        rtcp_bandwidth => round(rtcp_bw(S) * 8),
        feedback_budget => round(S#sched.tokens),
        members => S#sched.members,
        senders => S#sched.senders
    }.

%%====================================================================
%% Internal
%%====================================================================

%% Milliseconds until the next regular report.
interval(#sched{} = S) ->
    U = (S#sched.uniform)(),
    Tmin = webrtc_rtcp_interval:min_interval(#{profile => avpf, initial => S#sched.initial, p2p => S#sched.members =< 2}),
    Params = #{
        members => S#sched.members,
        senders => S#sched.senders,
        rtcp_bw => rtcp_bw(S),
        we_sent => S#sched.we_sent,
        avg_rtcp_size => S#sched.avg_size,
        tmin => Tmin
    },
    T = round(webrtc_rtcp_interval:interval(Params, U) * 1000),
    case S#sched.initial orelse S#sched.trr =:= 0 of
        true -> T;
        false -> max(T, round(webrtc_rtcp_interval:trr_current(S#sched.trr, (S#sched.uniform)())))
    end.

%% Octets per second.
rtcp_bw(#sched{session_bw = Bw}) -> 0.05 * Bw / 8.

budget(S) -> max(float(?MIN_BUDGET), rtcp_bw(S)).

refill(Now, #sched{tokens = T, tokens_at = At} = S) when Now > At ->
    S#sched{tokens = min(budget(S), T + rtcp_bw(S) * (Now - At) / 1000), tokens_at = Now};
refill(_Now, S) ->
    S.

avg(Size, #sched{avg_size = A} = S) ->
    S#sched{avg_size = webrtc_rtcp_interval:avg_rtcp_size(A, Size + ?LOWER_HEADERS)}.

tmin(infinity, B) -> B;
tmin(A, infinity) -> A;
tmin(A, B) -> min(A, B).
