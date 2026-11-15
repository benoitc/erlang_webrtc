%% @private The transport of one peer connection (one BUNDLE group): it
%% owns the UDP sockets and drives the sans-IO engines.
%%
%% ```
%% UDP -> webrtc_demux -> STUN/TURN      -> webrtc_ice_agent
%%                     -> DTLS           -> webrtc_dtls -> SCTP -> webrtc_dcep
%%                     -> SRTP/SRTCP     -> webrtc_media
%% '''
%%
%% Everything leaving the process goes through `webrtc_ice_agent:send/3'
%% on the selected pair. DTLS and media from addresses that ICE did not
%% validate are dropped (RFC 8445 §12.2, RFC 8826 §4.2).
%%
%% Control events go to the peer connection process as
%% `{webrtc_transport, self(), Event}'. Media and data channel messages
%% go straight to the application as `{webrtc, Pc, Event}', so the hot
%% path does not pass through the peer connection process.
%%
%% This module is the process: its API, the gen_server callbacks and the
%% single timer. `webrtc_transport_net' handles sockets, received
%% datagrams and ICE actions; `webrtc_transport_secure' handles DTLS,
%% SRTP, media actions and SCTP. All three share the state record of
%% `webrtc_transport.hrl'.
-module(webrtc_transport).
-behaviour(gen_server).

-include("webrtc_ice.hrl").
-include("webrtc_sdp.hrl").

-export([start_link/1, stop/1]).
-export([
    gather/1,
    set_remote_ice/3,
    add_remote_candidate/2,
    end_of_candidates/1,
    configure/2,
    restart_ice/3,
    send_rtp/4,
    send_rtp_packet/3,
    request_keyframe/2,
    request_pause/3,
    set_congestion_control/2,
    resume_stream/2,
    open_channel/3,
    send_data/4,
    close_channel/2,
    stats/1,
    set_app/2
]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).
%% Internal, for webrtc_transport_net and webrtc_transport_secure.
-export([to_pc/2, to_app/2, now_ms/0]).

-include("webrtc_transport.hrl").

%%====================================================================
%% API (called by webrtc_pc)
%%====================================================================

start_link(Opts) ->
    gen_server:start_link(?MODULE, Opts, []).

stop(T) ->
    gen_server:stop(T, normal, 5000).

gather(T) -> gen_server:call(T, gather).
set_remote_ice(T, Ufrag, Pwd) -> gen_server:call(T, {set_remote_ice, Ufrag, Pwd}).
add_remote_candidate(T, Cand) -> gen_server:call(T, {add_remote_candidate, Cand}).
end_of_candidates(T) -> gen_server:call(T, end_of_candidates).
configure(T, Negotiated) -> gen_server:call(T, {configure, Negotiated}).
restart_ice(T, U, P) -> gen_server:call(T, {restart_ice, U, P}).

%% Media sends are calls so the application gets errors and is paced by
%% the transport process.
send_rtp(T, Mid, Payload, Opts) -> gen_server:call(T, {send_rtp, Mid, Payload, Opts}).
send_rtp_packet(T, Mid, Pkt) -> gen_server:call(T, {send_rtp_packet, Mid, Pkt}).
request_keyframe(T, Mid) -> gen_server:call(T, {request_keyframe, Mid}).
request_pause(T, Key, Type) -> gen_server:call(T, {request_pause, Key, Type}).
set_congestion_control(T, Opts) -> gen_server:call(T, {set_congestion_control, Opts}).
resume_stream(T, Mid) -> gen_server:call(T, {resume_stream, Mid}).

open_channel(T, Label, Opts) -> gen_server:call(T, {open_channel, Label, Opts}).
send_data(T, Id, Type, Data) -> gen_server:call(T, {send_data, Id, Type, Data}).
close_channel(T, Id) -> gen_server:call(T, {close_channel, Id}).
stats(T) -> gen_server:call(T, stats).
set_app(T, Pid) -> gen_server:call(T, {set_app, Pid}).

%%====================================================================
%% gen_server
%%====================================================================

init(#{pc := Pc, app := App, cert := Cert} = Opts) ->
    %% The transport never outlives its peer connection, whatever the
    %% reason it went away.
    _ = monitor(process, Pc),
    IceOpts = (maps:with(
        [role, lite, remote_lite, ufrag, pwd, stun_servers, turn_servers, consent, nomination], Opts
    ))#{hidden_hosts => maps:get(mdns_host_candidates, Opts, false)},
    Addrs = maps:get(addresses, Opts, webrtc_transport_net:local_addresses(Opts)),
    Sockets = [S || A <- Addrs, {ok, S} <- [webrtc_transport_net:open_socket(A)]],
    case Sockets of
        [] ->
            {stop, no_usable_address};
        _ ->
            {ok, webrtc_transport_net:tcp_listen(maps:get(ice_tcp, Opts, false), #st{
                pc = Pc,
                app = App,
                sockets = Sockets,
                ice = webrtc_ice_agent:new(IceOpts),
                cert = Cert,
                media = webrtc_media:new(#{
                    cname => maps:get(cname, Opts, <<"webrtc">>),
                    cc => maps:get(congestion_control, Opts, #{}),
                    rtcp => #{report_interval => maps:get(rtcp_report_interval, Opts, 1000)}
                }),
                srtp_profiles = maps:get(srtp_profiles, Opts, [16#0007, 16#0008, 16#0001, 16#0002]),
                dtls_opts = maps:with([connection_id, resumption, ticket_lifetime], maps:get(dtls, Opts, #{})),
                filter = maps:get(outbound_filter, Opts, undefined),
                mdns = webrtc_mdns_client:new(
                    (maps:get(mdns, Opts, #{}))#{
                        hide_host => maps:get(mdns_host_candidates, Opts, false),
                        expose_public => maps:get(mdns_expose_public, Opts, true),
                        stun_servers => maps:get(stun_servers, Opts, [])
                    },
                    lists:usort([webrtc_transport_net:family(IP) || {_, {IP, _}} <- Sockets])
                )
            })}
    end.

handle_call(gather, _From, St) ->
    Tcp = [{Ref, Addr} || {Ref, _, Addr} <- St#st.tcp_listeners],
    %% TCP candidates first: gathering may complete within gather/3, and
    %% candidates after end-of-candidates are ignored (RFC 8838 §14).
    run(St, fun(Now, I) ->
        {I1, A1} = webrtc_ice_agent:tcp_listeners(Tcp, Now, I),
        {I2, A2} = webrtc_ice_agent:gather(St#st.sockets, Now, I1),
        {I2, A1 ++ A2}
    end, ok);
handle_call({set_remote_ice, U, P}, _From, St) ->
    run(St, fun(Now, I) -> webrtc_ice_agent:set_remote_credentials(U, P, Now, I) end, ok);
handle_call({add_remote_candidate, Cand}, _From, St) ->
    %% Host names are resolved first (draft-ietf-mmusic-mdns-ice-candidates).
    case webrtc_mdns_client:remote_candidate(Cand, St#st.mdns) of
        {add, Value, M} ->
            run(St#st{mdns = M}, fun(Now, I) -> webrtc_ice_agent:add_remote_candidate(Value, Now, I) end, ok);
        {Waiting, M} when Waiting =:= pending; Waiting =:= ignored ->
            {reply, ok, St#st{mdns = M}};
        {error, R, M} ->
            {reply, {error, R}, St#st{mdns = M}}
    end;
handle_call(end_of_candidates, _From, St) ->
    case webrtc_mdns_client:end_of_candidates(St#st.mdns) of
        {now, M} -> run(St#st{mdns = M}, fun(Now, I) -> webrtc_ice_agent:end_of_candidates(Now, I) end, ok);
        {deferred, M} -> {reply, ok, St#st{mdns = M}}
    end;
handle_call({restart_ice, U, P}, _From, St) ->
    {I1, Acts} = webrtc_ice_agent:restart(#{ufrag => U, pwd => P}, now_ms(), St#st.ice),
    %% The pair ICE selects next is a new path, even on the same
    %% addresses (connection ID rotation).
    Pair = case St#st.pair of undefined -> undefined; _ -> restart end,
    St0 = webrtc_transport_net:ice_actions(Acts, St#st{ice = I1, mdns = webrtc_mdns_client:restart(St#st.mdns), pair = Pair}),
    %% The candidates are kept across the restart but belong to the new
    %% ICE generation: signal them again (RFC 8445 §9, RFC 8838 §4.4).
    St1 = lists:foldl(fun webrtc_transport_net:local_candidate/2, St0, webrtc_ice_agent:local_candidates(I1)),
    to_pc({gathering_state, complete}, St1),
    {reply, ok, arm(St1)};
handle_call({configure, Neg}, _From, St) ->
    St1 = webrtc_transport_secure:configure_engines(Neg, St),
    {reply, ok, arm(St1)};
handle_call(Msg, _From, #st{finished = true} = St) when
    element(1, Msg) =:= send_rtp;
    element(1, Msg) =:= send_rtp_packet;
    element(1, Msg) =:= request_keyframe;
    element(1, Msg) =:= request_pause;
    element(1, Msg) =:= open_channel;
    element(1, Msg) =:= send_data;
    element(1, Msg) =:= close_channel;
    element(1, Msg) =:= resume_stream
->
    {reply, {error, closed}, St};
handle_call({send_rtp, Mid, Payload, Opts}, _From, St) ->
    media_send(fun(Now, M) -> webrtc_media:send(Mid, Payload, Opts, Now, M) end, St);
handle_call({send_rtp_packet, Mid, Pkt}, _From, St) ->
    media_send(fun(Now, M) -> webrtc_media:send_packet(Mid, Pkt, Now, M) end, St);
handle_call({request_keyframe, Mid}, _From, St) ->
    {Acts, M} = webrtc_media:request_keyframe(Mid, now_ms(), St#st.media),
    St1 = webrtc_transport_net:transmit(Acts, St#st{media = M}),
    {reply, ok, arm(St1)};
handle_call({request_pause, Key, Type}, _From, St) ->
    case webrtc_media:request_pause(Key, Type, now_ms(), St#st.media) of
        {ok, Acts, M} -> {reply, ok, arm(webrtc_transport_net:transmit(Acts, St#st{media = M}))};
        {error, _} = E -> {reply, E, St}
    end;
handle_call({resume_stream, Mid}, _From, St) ->
    case webrtc_media:resume(Mid, now_ms(), St#st.media) of
        {ok, M} -> {reply, ok, St#st{media = M}};
        {error, _} = E -> {reply, E, St}
    end;
handle_call({set_congestion_control, Opts}, _From, St) ->
    {Acts, M} = webrtc_media:set_congestion_control(Opts, now_ms(), St#st.media),
    St1 = webrtc_transport_secure:media_actions(Acts, St#st{media = M}),
    {reply, ok, arm(St1)};
handle_call({open_channel, Label, Opts}, From, #st{dcep = undefined} = St) ->
    {noreply, St#st{pending_channels = St#st.pending_channels ++ [{From, Label, Opts}]}};
handle_call({open_channel, Label, Opts}, _From, St) ->
    {Reply, St1} = webrtc_transport_secure:do_open_channel(Label, Opts, St),
    {reply, Reply, arm(St1)};
handle_call({send_data, Id, Type, Data}, _From, #st{dcep = D} = St) when D =/= undefined ->
    case webrtc_dcep:send(Id, Type, Data, now_ms(), D) of
        {ok, D1, Acts} -> {reply, ok, arm(webrtc_transport_secure:dcep_actions(Acts, St#st{dcep = D1}))};
        {error, _} = E -> {reply, E, St}
    end;
handle_call({send_data, _, _, _}, _From, St) ->
    {reply, {error, not_connected}, St};
handle_call({close_channel, Id}, _From, #st{dcep = D} = St) when D =/= undefined ->
    case webrtc_dcep:close_channel(Id, now_ms(), D) of
        {ok, D1, Acts} -> {reply, ok, arm(webrtc_transport_secure:dcep_actions(Acts, St#st{dcep = D1}))};
        {error, _} = E -> {reply, E, St}
    end;
handle_call({close_channel, _}, _From, St) ->
    {reply, {error, not_connected}, St};
handle_call({set_app, Pid}, _From, St) ->
    {reply, ok, St#st{app = Pid}};
handle_call(stats, _From, St) ->
    Stats = #{
        addresses => [A || {_, A} <- St#st.sockets],
        dropped => St#st.dropped,
        dropped_last => St#st.dropped_last,
        received => St#st.received,
        ice => webrtc_ice_agent:stats(St#st.ice),
        dtls => case St#st.dtls of undefined -> undefined; D -> webrtc_dtls:info(D) end,
        media => webrtc_media:stats(St#st.media),
        sctp => case St#st.dcep of undefined -> undefined; Dc -> webrtc_sctp_assoc:stats(webrtc_dcep:sctp(Dc)) end
    },
    {reply, Stats, St}.

handle_cast(_Msg, St) ->
    {noreply, St}.

handle_info({udp, Sock, IP, Port, Bin}, St) ->
    St1 = webrtc_transport_net:datagram(Sock, {IP, Port}, Bin, now_ms(), St),
    {noreply, arm(St1)};
handle_info({'DOWN', _Ref, process, Pc, _Reason}, #st{pc = Pc} = St) ->
    {stop, normal, St};
handle_info({delayed_send, Sock, Dest, Bin}, St) ->
    webrtc_transport_net:udp_send(Sock, Dest, Bin),
    {noreply, St};
handle_info({ice_tcp_accept, ListenRef, Sock}, St) ->
    {noreply, arm(webrtc_transport_net:tcp_accepted(ListenRef, Sock, St))};
handle_info({turn_stream, Ref, Result}, St) ->
    {noreply, arm(webrtc_transport_net:stream_opened(Ref, Result, St))};
handle_info({Tag, Sock, Data}, St) when Tag =:= tcp; Tag =:= ssl ->
    {noreply, arm(webrtc_transport_net:stream_data(Sock, Data, St))};
handle_info({Tag, Sock}, St) when Tag =:= tcp_closed; Tag =:= ssl_closed ->
    {noreply, arm(webrtc_transport_net:stream_closed(Sock, closed, St))};
handle_info({Tag, Sock, Reason}, St) when Tag =:= tcp_error; Tag =:= ssl_error ->
    {noreply, arm(webrtc_transport_net:stream_closed(Sock, Reason, St))};
handle_info({Tag, Sock}, St) when Tag =:= tcp_passive; Tag =:= ssl_passive ->
    {noreply, webrtc_transport_net:stream_passive(Sock, St)};
handle_info({udp_passive, Sock}, St) ->
    ok = inet:setopts(Sock, [{active, ?ACTIVE_N}]),
    {noreply, St};
handle_info({timeout, Ref, tick}, #st{timer = {Ref, _}} = St) ->
    St1 = tick(now_ms(), St#st{timer = undefined}),
    {noreply, arm(St1)};
handle_info({timeout, _Ref, tick}, St) ->
    {noreply, St};
handle_info(Other, St) ->
    %% Resolved host names: add the candidates, then a deferred
    %% end-of-candidates.
    case webrtc_mdns_client:handle_info(Other, St#st.mdns) of
        {ok, Values, Eoc, M} ->
            Add = fun(V, S) -> element(3, run(S, fun(Now, I) -> webrtc_ice_agent:add_remote_candidate(V, Now, I) end, ok)) end,
            St1 = lists:foldl(Add, St#st{mdns = M}, Values),
            {noreply, element(3, run(St1, fun(Now, I) -> eoc(Eoc, Now, I) end, ok))};
        ignore ->
            {noreply, St}
    end.

eoc(true, Now, I) -> webrtc_ice_agent:end_of_candidates(Now, I);
eoc(false, _Now, I) -> {I, []}.

terminate(_Reason, St0) ->
    ets:delete_object(webrtc_transports, {St0#st.pc, self()}),
    ok = webrtc_mdns_client:stop(St0#st.mdns),
    %% close_notify first (it needs the selected pair), then the ICE
    %% agent: it deletes TURN allocations with a zero lifetime Refresh
    %% (RFC 8656 §8) instead of leaving them until they expire.
    St1 =
        case St0#st.dtls of
            undefined -> St0;
            D -> webrtc_transport_secure:transmit_dtls(element(2, webrtc_dtls:close(D)), St0)
        end,
    {Ice, Acts} = webrtc_ice_agent:close(now_ms(), St1#st.ice),
    St2 = webrtc_transport_net:ice_actions([A || A <- Acts, element(1, A) =:= send orelse element(1, A) =:= close_stream],
                                           St1#st{ice = Ice}),
    _ = webrtc_transport_net:close_streams(St2),
    _ = [gen_tcp:close(L) || {_, L, _} <- St2#st.tcp_listeners],
    _ = [gen_udp:close(S) || {S, _} <- St1#st.sockets],
    ok.

%%====================================================================
%% Driving the engines
%%====================================================================

%% Run an ICE agent operation and execute its actions.
run(St, F, Reply) ->
    case F(now_ms(), St#st.ice) of
        {error, _} = E ->
            {reply, E, St};
        {I1, Acts} ->
            St1 = webrtc_transport_net:ice_actions(Acts, St#st{ice = I1}),
            {reply, Reply, arm(St1)}
    end.

tick(Now, St0) ->
    {I1, A1} = webrtc_ice_agent:handle_timeout(Now, St0#st.ice),
    St1 = webrtc_transport_net:ice_actions(A1, St0#st{ice = I1}),
    St2 =
        case St1#st.dtls of
            undefined -> St1;
            D ->
                {D1, A2} = webrtc_dtls:handle_timeout(Now, D),
                webrtc_transport_secure:dtls_actions(A2, St1#st{dtls = D1})
        end,
    {M1, A3} = webrtc_media:handle_timeout(Now, St2#st.media),
    St3 = webrtc_transport_secure:media_actions(A3, St2#st{media = M1}),
    case St3#st.dcep of
        undefined -> St3;
        Dc ->
            {Dc1, A4} = webrtc_dcep:handle_timeout(Now, Dc),
            webrtc_transport_secure:dcep_actions(A4, St3#st{dcep = Dc1})
    end.

media_send(F, St) ->
    case F(now_ms(), St#st.media) of
        {ok, Acts, M1} -> {reply, ok, arm(webrtc_transport_net:transmit(Acts, St#st{media = M1}))};
        {error, _} = E -> {reply, E, St}
    end.

%%====================================================================
%% Helpers
%%====================================================================

to_pc(E, #st{pc = Pc}) ->
    Pc ! {webrtc_transport, self(), E},
    ok.

to_app(E, #st{pc = Pc, app = App}) ->
    App ! {webrtc, Pc, E},
    ok.

%% One timer for all engines, at the earliest deadline.
arm(St) ->
    Next = lists:foldl(fun tmin/2, infinity, [
        webrtc_ice_agent:next_timeout(St#st.ice),
        case St#st.dtls of undefined -> infinity; D -> webrtc_dtls:next_timeout(D) end,
        webrtc_media:next_timeout(St#st.media),
        case St#st.dcep of undefined -> infinity; Dc -> webrtc_dcep:next_timeout(Dc) end
    ]),
    case {Next, St#st.timer} of
        {infinity, undefined} ->
            St;
        {infinity, {Ref, _}} ->
            _ = erlang:cancel_timer(Ref),
            St#st{timer = undefined};
        {T, {_, T}} ->
            St;
        {T, Old} ->
            _ = case Old of
                {Ref, _} -> _ = erlang:cancel_timer(Ref);
                undefined -> ok
            end,
            At = max(T, now_ms()),
            St#st{timer = {erlang:start_timer(At, self(), tick, [{abs, true}]), T}}
    end.

tmin(infinity, B) -> B;
tmin(A, infinity) -> A;
tmin(A, B) -> min(A, B).

now_ms() ->
    erlang:monotonic_time(millisecond).
