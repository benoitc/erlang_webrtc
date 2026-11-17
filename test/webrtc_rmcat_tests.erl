%% The RFC 8867 test cases for congestion control of interactive media,
%% run on the simulator (webrtc_cc_sim) with the evaluation settings of
%% RFC 8867 §4: 50 ms one-way delay, packet delay variation as RFC 8868
%% §4.5 asks (NR-BPDV, 5 ms std, at most 3 std), a 300 ms tail-drop
%% queue, video from 150 kbps to 1.5 Mbps starting at 150 kbps, and 20
%% kbps audio on the same transport. The ECN cases (6.2) mark with
%% CoDel at its default 5 ms target (RFC 8289, one of the AQMs RFC 8868
%% suggests).
%%
%% The bounds follow each case's expected behavior and are fixed: after
%% a change of the available rate, a flow averages 0.7 to 1.05 of its
%% share within 10 s; the 95th percentile of the queue stays under 100
%% ms once converged; flows sharing the link reach a Jain index of 0.9;
%% media never drops below its minimum; TCP keeps a quarter of the link.
%% Capacity changes are applied to the bottleneck directly rather than
%% through UDP cross traffic (RFC 8867 §5.1 allows either). Every case
%% runs on six seeds (link jitter and flow variation).
-module(webrtc_rmcat_tests).
-include_lib("eunit/include/eunit.hrl").

-define(SIM, webrtc_cc_sim).
-define(MIN, 150000).
-define(MAX, 1500000).
-define(Q95, 100).

video(Extra) ->
    maps:merge(
        #{start_bitrate => ?MIN, min_bitrate => ?MIN, max_bitrate => ?MAX, audio => true}, Extra
    ).

jitter() -> #{std_ms => 5, n_std => 3}.

path(Opts) ->
    Delay = maps:get(delay_ms, Opts, 50),
    #{
        link => maps:merge(maps:with([ecn_ms], Opts), #{
            capacity => maps:get(capacity, Opts),
            delay_ms => Delay,
            queue_ms => maps:get(queue_ms, Opts, 300),
            jitter => jitter(),
            seed => maps:get(seed, Opts, 1)
        }),
        reverse_link => #{
            capacity => maps:get(reverse_capacity, Opts, 1 bsl 40),
            delay_ms => Delay,
            queue_ms => 300,
            jitter => jitter()
        }
    }.

run(Path, Rest) -> ?SIM:run(maps:merge(path(Path), Rest#{seed => maps:get(seed, Path, 1)})).

seeds() -> lists:seq(1, 6).

%% One test per seed.
seeded(Name, Timeout, Case) ->
    [
        {
            lists:flatten(io_lib:format("~s, seed ~b", [Name, S])),
            {timeout, Timeout, fun() -> Case(S) end}
        }
     || S <- seeds()
    ].

%% Average rate of flow N over [From, To] against Share.
share(Sim, N, From, To, Share) ->
    ?SIM:rate(Sim, N, From, To) / Share.

jain(Xs) ->
    S = lists:sum(Xs),
    S * S / (length(Xs) * lists:sum([X * X || X <- Xs])).

report(Name, Fmt, Args) ->
    ?debugFmt("RFC 8867 ~s: " ++ Fmt, [Name | Args]).

%% A phase of a capacity schedule: [From, To) ms with Avail bps per flow.
check_phases(Name, Sim, N, Phases) ->
    lists:foreach(
        fun({From, To, Avail}) ->
            Share = min(Avail, ?MAX),
            R = share(Sim, N, From + 10000, To, Share),
            Q = ?SIM:queue_percentile(Sim, 95, From + 10000, To),
            report(
                Name,
                "flow ~b, ~b to ~b s at ~b kbps: ~.2f of its share, queue p95 ~b ms",
                [N, From div 1000, To div 1000, Avail div 1000, R, Q]
            ),
            ?assert(R >= 0.7),
            ?assert(R =< 1.05),
            ?assert(Q < ?Q95)
        end,
        Phases
    ).

%%====================================================================
%% 5.1 Variable available capacity with a single flow
%%====================================================================

variable_capacity_single(Delay, Seed) ->
    Sim = run(#{capacity => 1000000, delay_ms => Delay, seed => Seed}, #{
        flows => [video(#{})],
        duration_ms => 100000,
        events => [
            {40000, {capacity, 2500000}}, {60000, {capacity, 600000}}, {80000, {capacity, 1000000}}
        ]
    }),
    check_phases("5.1", Sim, 1, [
        {0, 40000, 1000000 - 20000},
        {40000, 60000, 2500000},
        {60000, 80000, 600000 - 20000},
        {80000, 100000, 1000000 - 20000}
    ]).

variable_capacity_single_50ms_test_() ->
    seeded("5.1 50 ms", 120, fun(S) -> variable_capacity_single(50, S) end).
variable_capacity_single_100ms_test_() ->
    seeded("5.1 100 ms", 120, fun(S) -> variable_capacity_single(100, S) end).

%%====================================================================
%% 5.2 Variable available capacity with multiple flows
%%====================================================================

%% RFC 8867 §5.2 asks the flows to follow the capacity down and up
%% again; the split between them is not part of the expected behavior.
variable_capacity_multiple_test_() -> seeded("5.2", 120, fun variable_capacity_multiple/1).

variable_capacity_multiple(Seed) ->
    Sim = run(#{capacity => 4000000, seed => Seed}, #{
        flows => [video(#{}), video(#{})],
        duration_ms => 125000,
        events => [
            {25000, {capacity, 2000000}},
            {50000, {capacity, 3500000}},
            {75000, {capacity, 1000000}},
            {100000, {capacity, 2000000}}
        ]
    }),
    lists:foreach(
        fun({From, To, Cap}) ->
            Avail = min(Cap - 40000, 2 * ?MAX),
            Total =
                (?SIM:rate(Sim, 1, From + 10000, To) + ?SIM:rate(Sim, 2, From + 10000, To)) / Avail,
            Mins = [?SIM:min_after(maps:get(samples, Sim), N, From + 10000, To) || N <- [1, 2]],
            Q = ?SIM:queue_percentile(Sim, 95, From + 10000, To),
            report(
                "5.2",
                "~b to ~b s at ~b kbps: together ~.2f of the available rate, queue p95 ~b ms",
                [From div 1000, To div 1000, Cap div 1000, Total, Q]
            ),
            ?assert(Total >= 0.7 andalso Total =< 1.05),
            [?assert(M >= ?MIN) || M <- Mins],
            ?assert(Q < ?Q95)
        end,
        [
            {0, 25000, 4000000},
            {25000, 50000, 2000000},
            {50000, 75000, 3500000},
            {75000, 100000, 1000000},
            {100000, 125000, 2000000}
        ]
    ).

%%====================================================================
%% 5.3 Congested feedback link with bi-directional media
%%====================================================================

feedback_congestion_test_() -> seeded("5.3", 120, fun feedback_congestion/1).

feedback_congestion(Seed) ->
    Fwd = [{20000, {capacity, 1000000}}, {40000, {capacity, 500000}}, {60000, {capacity, 2000000}}],
    Bwd = [{35000, {reverse_capacity, 800000}}, {70000, {reverse_capacity, 2000000}}],
    Sim = run(#{capacity => 2000000, reverse_capacity => 2000000, seed => Seed}, #{
        flows => [video(#{}), video(#{dir => backward})],
        duration_ms => 100000,
        events => Fwd ++ Bwd
    }),
    check_phases("5.3 forward", Sim, 1, [
        {0, 20000, ?MAX},
        {20000, 40000, 980000},
        {40000, 60000, 480000},
        {60000, 100000, ?MAX}
    ]),
    %% The backward flow on its own link.
    lists:foreach(
        fun({From, To, Avail}) ->
            R = share(Sim, 2, From + 10000, To, min(Avail, ?MAX)),
            report("5.3 backward", "~b to ~b s at ~b kbps: ~.2f of its share", [
                From div 1000,
                To div 1000,
                Avail div 1000,
                R
            ]),
            ?assert(R >= 0.7 andalso R =< 1.05)
        end,
        [{0, 35000, ?MAX}, {35000, 70000, 780000}, {70000, 100000, ?MAX}]
    ).

%%====================================================================
%% 5.4 Competing media flows with the same congestion control
%%====================================================================

competing(Extra, Seed) ->
    run(
        #{capacity => 3500000, seed => Seed},
        maps:merge(
            #{
                flows => [video(#{}), video(#{start_ms => 20000}), video(#{start_ms => 40000})],
                duration_ms => 120000
            },
            Extra
        )
    ).

check_fair(Name, Sim, Ns, From, To, Capacity) ->
    Rates = [?SIM:rate(Sim, N, From, To) || N <- Ns],
    J = jain(Rates),
    Use = lists:sum(Rates) / Capacity,
    Q = ?SIM:queue_percentile(Sim, 95, From, To),
    report(
        Name,
        "~b to ~b s: rates ~w kbps, Jain ~.3f, ~.2f of the link, queue p95 ~b ms",
        [From div 1000, To div 1000, [round(R / 1000) || R <- Rates], J, Use, Q]
    ),
    ?assert(J >= 0.9),
    ?assert(Use >= 0.7),
    ?assert(Q < ?Q95).

competing_flows_test_() -> seeded("5.4", 120, fun competing_flows/1).

competing_flows(Seed) ->
    Sim = competing(#{}, Seed),
    %% Room for the second flow: both near their maximum.
    [?assert(share(Sim, N, 30000, 40000, ?MAX) >= 0.7) || N <- [1, 2]],
    check_fair("5.4", Sim, [1, 2, 3], 60000, 120000, 3500000).

%%====================================================================
%% 5.5 Round trip time fairness
%%====================================================================

rtt_fairness_test_() -> seeded("5.5", 120, fun rtt_fairness/1).

rtt_fairness(Seed) ->
    Delays = [10, 25, 50, 100, 150],
    Sim = run(#{capacity => 4000000, delay_ms => 0, seed => Seed}, #{
        flows => [
            video(#{start_ms => (I - 1) * 10000, delay_ms => D})
         || {I, D} <- lists:enumerate(Delays)
        ],
        duration_ms => 300000
    }),
    check_fair("5.5", Sim, [1, 2, 3, 4, 5], 100000, 300000, 4000000).

%%====================================================================
%% 5.6 Media flow competing with a long TCP flow
%%====================================================================

long_tcp(Queue, Seed) ->
    Sim = run(#{capacity => 2000000, queue_ms => Queue, seed => Seed}, #{
        flows => [video(#{start_ms => 5000})],
        tcp => [#{app => long}],
        duration_ms => 120000
    }),
    Media = ?SIM:rate(Sim, 1, 30000, 120000),
    Tcp = ?SIM:tcp_rate(Sim, 1, 30000, 120000),
    Min = ?SIM:min_after(maps:get(samples, Sim), 1, 10000, 120000),
    report("5.6", "queue ~b ms: media ~b kbps (min ~b), TCP ~b kbps", [
        Queue,
        round(Media / 1000),
        Min div 1000,
        round(Tcp / 1000)
    ]),
    ?assert(Min >= ?MIN),
    ?assert(Tcp >= 0.25 * 2000000),
    ?assert(Media + Tcp >= 0.7 * 2000000).

long_tcp_300ms_test_() -> seeded("5.6 300 ms", 120, fun(S) -> long_tcp(300, S) end).
long_tcp_1000ms_test_() -> seeded("5.6 1000 ms", 120, fun(S) -> long_tcp(1000, S) end).

%%====================================================================
%% 5.7 Media flows competing with short TCP flows
%%====================================================================

short_tcp_test_() -> seeded("5.7", 300, fun short_tcp/1).

short_tcp(Seed) ->
    Sim = run(#{capacity => 2000000, seed => Seed}, #{
        flows => [video(#{start_ms => 5000}), video(#{start_ms => 5000})],
        tcp => [
            #{
                app =>
                    {short, #{
                        start =>
                            case K =< 2 of
                                true -> on;
                                false -> off
                            end
                    }}
            }
         || K <- lists:seq(1, 10)
        ],
        duration_ms => 300000
    }),
    Rates = [?SIM:rate(Sim, N, 30000, 300000) || N <- [1, 2]],
    Tcp = lists:sum([?SIM:tcp_rate(Sim, K, 30000, 300000) || K <- lists:seq(1, 10)]),
    Mins = [?SIM:min_after(maps:get(samples, Sim), N, 10000, 300000) || N <- [1, 2]],
    report("5.7", "media ~w kbps (min ~w), TCP ~b kbps", [
        [round(R / 1000) || R <- Rates],
        [M div 1000 || M <- Mins],
        round(Tcp / 1000)
    ]),
    [?assert(M >= ?MIN) || M <- Mins],
    ?assert(jain(Rates) >= 0.9).

%%====================================================================
%% 5.8 Media pause and resume
%%====================================================================

pause_resume_test_() -> seeded("5.8", 120, fun pause_resume/1).

pause_resume(Seed) ->
    Sim = run(#{capacity => 3500000, seed => Seed}, #{
        flows => [video(#{}), video(#{pause => [{40000, 60000}]}), video(#{})],
        duration_ms => 120000
    }),
    %% While flow 2 is paused the others take its share.
    [?assert(share(Sim, N, 50000, 60000, ?MAX) >= 0.7) || N <- [1, 3]],
    %% From 10 s after the resume, all three share the link fairly.
    check_fair("5.8", Sim, [1, 2, 3], 70000, 120000, 3500000).

%%====================================================================
%% 6.2 ECN: 5.1 and 5.4 with RFC 8888 feedback and ECN marking
%%====================================================================

ecn_variable_capacity_test_() -> seeded("6.2 (5.1)", 120, fun ecn_variable_capacity/1).

ecn_variable_capacity(Seed) ->
    Sim = run(#{capacity => 1000000, ecn_ms => 5, seed => Seed}, #{
        flows => [video(#{feedback => ccfb})],
        duration_ms => 100000,
        events => [
            {40000, {capacity, 2500000}}, {60000, {capacity, 600000}}, {80000, {capacity, 1000000}}
        ]
    }),
    check_phases("6.2 (5.1)", Sim, 1, [
        {0, 40000, 980000},
        {40000, 60000, 2500000},
        {60000, 80000, 580000},
        {80000, 100000, 980000}
    ]).

ecn_competing_flows_test_() -> seeded("6.2 (5.4)", 120, fun ecn_competing_flows/1).

ecn_competing_flows(Seed) ->
    Sim = run(#{capacity => 3500000, ecn_ms => 5, seed => Seed}, #{
        flows => [
            video(#{feedback => ccfb}),
            video(#{feedback => ccfb, start_ms => 20000}),
            video(#{feedback => ccfb, start_ms => 40000})
        ],
        duration_ms => 120000
    }),
    check_fair("6.2 (5.4)", Sim, [1, 2, 3], 60000, 120000, 3500000).
