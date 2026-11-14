%% @doc RTCP transmission interval (RFC 3550 §6.2, §6.3 and Appendix
%% A.7) with the RTP/AVPF rules of RFC 4585 §3.4 and §3.5 and the reduced
%% minimum interval required by RFC 8834 §5.1.
%%
%% Everything here is a pure function. The randomisation factor is
%% passed in as `U', a float in [0, 1); `interval/1' draws it from
%% `crypto:strong_rand_bytes/1'.
%%
%% Parameters (`params()'):
%% <ul>
%% <li>`members', `senders': session membership counts;</li>
%% <li>`rtcp_bw': RTCP bandwidth in octets per second (5% of the session
%% bandwidth by default, RFC 3550 §6.2);</li>
%% <li>`we_sent': true when we sent RTP since the last two reports;</li>
%% <li>`avg_rtcp_size': average compound RTCP size in octets, including
%% UDP and IP headers;</li>
%% <li>`tmin': minimum interval in seconds, see `min_interval/1'.</li>
%% </ul>
-module(webrtc_rtcp_interval).

-export([
    interval/1,
    interval/2,
    deterministic/1,
    min_interval/1,
    timeout/1,
    trr_current/2,
    dither_max/2,
    avg_rtcp_size/2,
    uniform/0
]).

-export_type([params/0, min_opts/0]).

-type params() :: #{
    members := pos_integer(),
    senders := non_neg_integer(),
    rtcp_bw := number(),
    we_sent := boolean(),
    avg_rtcp_size := number(),
    tmin := number(),
    trr_interval => number()
}.
-type min_opts() :: #{
    profile => avp | avpf,
    initial => boolean(),
    p2p => boolean(),
    reduced => boolean(),
    session_bw_kbps => number()
}.

-define(RTCP_MIN_TIME, 5.0).
-define(SENDER_BW_FRACTION, 0.25).
-define(RCVR_BW_FRACTION, 0.75).
%% e - 3/2, compensates for timer reconsideration (§6.3.1).
-define(COMPENSATION, 1.21828).
%% Participant timeout multiplier (§6.3.5).
-define(TIMEOUT_M, 5).

%% @doc Randomised interval with a strong random factor.
-spec interval(params()) -> float() | infinity.
interval(Params) ->
    interval(Params, uniform()).

%% @doc Randomised interval of Appendix A.7 in seconds: the
%% deterministic interval times a factor uniformly spread over
%% [0.5, 1.5), divided by e - 3/2.
-spec interval(params(), float()) -> float() | infinity.
interval(Params, U) when is_float(U), U >= 0.0, U < 1.0 ->
    case deterministic(Params) of
        infinity -> infinity;
        T -> T * (U + 0.5) / ?COMPENSATION
    end.

%% @doc Deterministic interval Td (§6.3.1): when senders are at most a
%% quarter of the members, senders and receivers share 25% and 75% of
%% the RTCP bandwidth separately.
-spec deterministic(params()) -> float() | infinity.
deterministic(#{
    members := Members,
    senders := Senders,
    rtcp_bw := Bw0,
    we_sent := WeSent,
    avg_rtcp_size := Avg,
    tmin := Tmin
}) ->
    {Bw, N} =
        case Senders =< Members * ?SENDER_BW_FRACTION of
            true when WeSent -> {Bw0 * ?SENDER_BW_FRACTION, Senders};
            true -> {Bw0 * ?RCVR_BW_FRACTION, Members - Senders};
            false -> {Bw0, Members}
        end,
    case Bw > 0 of
        true -> max(float(Tmin), Avg * max(N, 1) / Bw);
        false -> infinity
    end.

%% @doc Minimum interval Tmin in seconds.
%%
%% RTP/AVP (RFC 3550 §6.2): 5 s, or with `reduced' the reduced minimum
%% of 360 / session bandwidth in kbit/s (required by RFC 8834 §5.1); the
%% first report uses half of it (Appendix A.7).
%%
%% RTP/AVPF (RFC 4585 §3.4 d, §3.5.1): before the first regular report
%% Tmin is 0 in a point-to-point session and 1 s otherwise; it is 0
%% after the first regular report.
-spec min_interval(min_opts()) -> float().
min_interval(Opts) ->
    Initial = maps:get(initial, Opts, false),
    case maps:get(profile, Opts, avp) of
        avpf ->
            case {Initial, maps:get(p2p, Opts, true)} of
                {true, true} -> 0.0;
                {true, false} -> 1.0;
                {false, _} -> 0.0
            end;
        avp ->
            Base =
                case Opts of
                    #{reduced := true, session_bw_kbps := Kbps} when Kbps > 0 ->
                        min(?RTCP_MIN_TIME, 360 / Kbps);
                    _ ->
                        ?RTCP_MIN_TIME
                end,
            case Initial of
                true -> Base / 2;
                false -> Base
            end
    end.

%% @doc Participant timeout in seconds (§6.3.5): M * Td with M = 5. Td is
%% computed with the fixed 5 s minimum even when the reduced minimum is
%% used for sending (RFC 8834 §5.1), or with `trr_interval' when an AVPF
%% session sets one (RFC 4585 §3.5.3). The `tmin' of `Params' is ignored.
-spec timeout(params()) -> float() | infinity.
timeout(Params) ->
    Tmin =
        case maps:get(trr_interval, Params, 0) of
            T when T > 0 -> T;
            _ -> ?RTCP_MIN_TIME
        end,
    case deterministic(Params#{tmin => Tmin}) of
        infinity -> infinity;
        Td -> ?TIMEOUT_M * Td
    end.

%% @doc AVPF dithered minimal interval between regular reports,
%% `RND * T_rr_interval' with RND in [0.5, 1.5) (RFC 4585 §3.5.3).
-spec trr_current(number(), float()) -> float().
trr_current(TrrInterval, U) when is_float(U), U >= 0.0, U < 1.0 ->
    TrrInterval * (U + 0.5).

%% @doc T_dither_max for early feedback (RFC 4585 §3.5.2 step 2b): 0 in a
%% point-to-point session, half the regular interval otherwise.
-spec dither_max(p2p | multiparty, number()) -> float().
dither_max(p2p, _Trr) -> 0.0;
dither_max(multiparty, Trr) -> 0.5 * Trr.

%% @doc Update the average compound RTCP size with a packet of `Size'
%% octets (§6.3.3): avg = 1/16 * size + 15/16 * avg.
-spec avg_rtcp_size(number(), non_neg_integer()) -> float().
avg_rtcp_size(Avg, Size) ->
    Size / 16 + Avg * 15 / 16.

%% @doc Uniform float in [0, 1) from a strong random source.
-spec uniform() -> float().
uniform() ->
    <<X:53, _:3>> = crypto:strong_rand_bytes(7),
    X / (1 bsl 53).
