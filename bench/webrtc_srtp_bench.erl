%% @doc SRTP throughput benchmark: packets per second for protect and
%% unprotect with 1200-octet RTP payloads, for every supported profile.
%%
%% Not part of the test suites. Run it from the project root:
%%
%% ```
%% rebar3 compile
%% erlc -o /tmp bench/webrtc_srtp_bench.erl
%% erl -noshell -pa _build/default/lib/webrtc/ebin -pa /tmp \
%%     -eval 'webrtc_srtp_bench:run(), halt().'
%% '''
-module(webrtc_srtp_bench).

-export([run/0, run/1]).

%% Packets per batch. A batch (about 1.2 MB) stays in cache, as a packet
%% just read from a socket would; a fresh context is used per batch so
%% indices never repeat.
-define(BATCH, 1024).

-spec run() -> ok.
run() ->
    run(#{}).

%% Options: `payload' (default 1200), `rounds' (batches, default 200).
-spec run(map()) -> ok.
run(Opts) ->
    PayloadLen = maps:get(payload, Opts, 1200),
    Rounds = maps:get(rounds, Opts, 200),
    Payload = crypto:strong_rand_bytes(PayloadLen),
    Plain = [
        <<16#80, 96, Seq:16, (Seq * 960):32, 16#1234ABCD:32, Payload/binary>>
     || Seq <- lists:seq(0, ?BATCH - 1)
    ],
    io:format(
        "~s, ~b-octet payload, ~b packets per run~n",
        [erlang:system_info(system_version) -- "\n", PayloadLen, ?BATCH * Rounds]
    ),
    io:format("~-30s ~16s ~16s~n", ["profile", "protect pkt/s", "unprotect pkt/s"]),
    lists:foreach(
        fun(Profile) -> bench_profile(Profile, Plain, Rounds) end,
        webrtc_srtp:supported_profiles()
    ).

bench_profile(Profile, Plain, Rounds) ->
    #{master_key_len := KL, master_salt_len := SL} = webrtc_srtp_profile:params(Profile),
    Key = crypto:strong_rand_bytes(KL),
    Salt = crypto:strong_rand_bytes(SL),
    New = fun() -> webrtc_srtp:new(Profile, Key, Salt, #{}) end,
    %% Warm up and keep one protected batch for the unprotect runs.
    {Protected, _} = protect_batch(Plain, New()),
    PT = time_rounds(Rounds, fun() -> protect_only(Plain, New()) end),
    UT = time_rounds(Rounds, fun() -> unprotect_batch(Protected, New()) end),
    N = ?BATCH * Rounds,
    io:format("~-30s ~16b ~16b~n", [atom_to_list(Profile), rate(N, PT), rate(N, UT)]).

time_rounds(Rounds, Fun) ->
    lists:sum([element(1, timer:tc(Fun)) || _ <- lists:seq(1, Rounds)]).

rate(N, Micros) ->
    round(N * 1.0e6 / Micros).

protect_batch(Packets, Ctx) ->
    lists:mapfoldl(
        fun(P, C) ->
            {ok, S, C1} = webrtc_srtp:protect_rtp(P, C),
            {S, C1}
        end,
        Ctx,
        Packets
    ).

protect_only([P | Rest], Ctx) ->
    {ok, _, Ctx1} = webrtc_srtp:protect_rtp(P, Ctx),
    protect_only(Rest, Ctx1);
protect_only([], Ctx) ->
    Ctx.

unprotect_batch([S | Rest], Ctx) ->
    {ok, _, Ctx1} = webrtc_srtp:unprotect_rtp(S, Ctx),
    unprotect_batch(Rest, Ctx1);
unprotect_batch([], Ctx) ->
    Ctx.
