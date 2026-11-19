%% RFC 6051 ntp-64 header extension (RFC 8834 §5.2.1) against
%% GStreamer's rtphdrextntp64, an implementation independent of ours,
%% over plain RTP on UDP, driven by interop/gst/rtp_ntp.py:
%% GStreamer writes the extension and we read it, we write it and
%% GStreamer reads it.
-module(webrtc_sync_gst_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("webrtc_rtp.hrl").
-include_lib("webrtc/src/transport/webrtc_media.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([gst_sends_ntp64/1, erlang_sends_ntp64/1]).

-define(ID, 6).
-define(N, 20).

all() -> [gst_sends_ntp64, erlang_sends_ntp64].

init_per_suite(Config) ->
    Script = filename:join([root(), "interop", "gst", "rtp_ntp.py"]),
    Gi = "python3 -I -c \"import gi; gi.require_version('Gst', '1.0'); gi.require_version('GstRtp', '1.0'); "
         "from gi.repository import Gst; Gst.init(None); "
         "print(Gst.ElementFactory.find('rtphdrextntp64') is not None)\" 2>&1",
    case {os:find_executable("python3"), string:trim(os:cmd(Gi))} of
        {false, _} -> {skip, "python3 not installed"};
        {_, "True"} -> [{script, Script} | Config];
        {_, Out} -> {skip, "GStreamer Python bindings or rtphdrextntp64 missing: " ++ Out}
    end.

end_per_suite(_Config) ->
    ok.

%% GStreamer writes the x-ntp time of each packet; the value we read is
%% the one it printed for that RTP timestamp, and our receive mapping
%% gives it back.
gst_sends_ntp64(Config) ->
    {ok, S} = gen_udp:open(0, [binary, {ip, {127, 0, 0, 1}}, {active, true}]),
    {ok, Port} = inet:port(S),
    Out = run(Config, ["send", integer_to_list(Port), integer_to_list(?N)]),
    Sent = maps:from_list([{list_to_integer(T), list_to_integer(V)} || ["rtp", T, V] <- Out]),
    ?assertEqual(?N, map_size(Sent)),
    Pkts = recv_all(S, ?N),
    gen_udp:close(S),
    ?assertEqual(?N, length(Pkts)),
    R0 = #rcv{mid = <<"0">>, clock_rate = 48000},
    lists:foreach(
        fun(#rtp{ts = Ts, ssrc = Ssrc, ext = Ext} = P) ->
            {ok, <<Ntp:64>>} = webrtc_rtp_ext:find(?ID, Ext),
            ?assertEqual(maps:get(Ts, Sent), Ntp),
            M0 = #media{receivers = #{Ssrc => R0},
                        recv = #{<<"0">> => #{recv_extensions => #{<<"urn:ietf:params:rtp-hdrext:ntp-64">> => ?ID}}}},
            M1 = webrtc_media_sync:rtp_in(<<"0">>, P, 0, M0),
            ?assertEqual(webrtc_rtp_stats:ntp_to_us(Ntp), webrtc_media_sync:ntp_time(Ssrc, Ts, M1))
        end,
        Pkts
    ).

%% We write the extension with webrtc_rtp_ext:ntp64/1; GStreamer's reader
%% turns it into the same NTP time (to its nanosecond precision).
erlang_sends_ntp64(Config) ->
    Port = free_port(),
    Cmd = lists:flatten(io_lib:format("python3 -I ~s recv ~b ~b", [?config(script, Config), Port, ?N])),
    P = open_port({spawn, Cmd}, [{line, 4096}, exit_status, stderr_to_stdout]),
    ok = wait_ready(P),
    {ok, S} = gen_udp:open(0, [binary, {ip, {127, 0, 0, 1}}]),
    Base = webrtc_rtp_stats:ntp_from_us(erlang:system_time(microsecond)),
    Ntps = [Base + I * (20 bsl 32) div 1000 || I <- lists:seq(0, ?N - 1)],
    [begin
         Pkt = #rtp{pt = 111, seq = I, ts = I * 960, ssrc = 16#1234,
                    ext = [{?ID, webrtc_rtp_ext:ntp64(Ntp)}], payload = <<16#F8, 16#FF, 16#FE>>},
         ok = gen_udp:send(S, {127, 0, 0, 1}, Port, webrtc_rtp:encode(Pkt)),
         timer:sleep(20)
     end || {I, Ntp} <- lists:enumerate(0, Ntps)],
    gen_udp:close(S),
    {0, Lines} = collect(P, []),
    Read = [list_to_integer(V) || ["ntp", V] <- Lines],
    ct:log("GStreamer read ~p", [Read]),
    ?assertEqual(?N, length(Read)),
    %% GStreamer keeps nanoseconds: within one of them (4.3 units of 2^-32 s).
    [?assert(abs(R - W) =< 5) || {R, W} <- lists:zip(Read, Ntps)].

run(Config, Args) ->
    Cmd = lists:flatten(["python3 -I ", ?config(script, Config) | [[" ", A] || A <- Args]]),
    P = open_port({spawn, Cmd}, [{line, 4096}, exit_status, stderr_to_stdout]),
    {0, Lines} = collect(P, []),
    Lines.

collect(P, Acc) ->
    receive
        {P, {data, {eol, L}}} ->
            ct:log("~s", [L]),
            collect(P, Acc ++ [string:split(L, " ", all)]);
        {P, {exit_status, St}} ->
            {St, Acc}
    after 30000 ->
        {timeout, Acc}
    end.

wait_ready(P) ->
    receive
        {P, {data, {eol, "ready"}}} -> ok;
        {P, {data, {eol, L}}} -> ct:log("~s", [L]), wait_ready(P);
        {P, {exit_status, St}} -> ct:fail({exited, St})
    after 15000 ->
        ct:fail(not_ready)
    end.

recv_all(_S, 0) ->
    [];
recv_all(S, N) ->
    receive
        {udp, S, _, _, B} ->
            {ok, Pkt} = webrtc_rtp:decode(B, #{extensions => parse}),
            [Pkt | recv_all(S, N - 1)]
    after 5000 ->
        []
    end.

free_port() ->
    {ok, S} = gen_udp:open(0, [{ip, {127, 0, 0, 1}}]),
    {ok, P} = inet:port(S),
    gen_udp:close(S),
    P.

root() ->
    {ok, Cwd} = file:get_cwd(),
    up(Cwd).

up("/") -> error(no_project_root);
up(Dir) ->
    case filelib:is_regular(filename:join(Dir, "rebar.config")) andalso filelib:is_dir(filename:join(Dir, "interop")) of
        true -> Dir;
        false -> up(filename:dirname(Dir))
    end.
