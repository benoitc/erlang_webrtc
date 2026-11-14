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
    set_congestion_control/2,
    resume_stream/2,
    open_channel/3,
    send_data/4,
    close_channel/2,
    stats/1,
    set_app/2
]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(ACTIVE_N, 100).
-define(MAX_EARLY_DTLS, 16).

-record(st, {
    pc :: pid(),
    app :: pid(),
    sockets = [] :: [{gen_udp:socket(), {inet:ip_address(), inet:port_number()}}],
    ice :: term(),
    dtls :: undefined | term(),
    dtls_role :: undefined | client | server,
    cert :: map(),
    remote_fps = [] :: list(),
    remote_tls_id :: undefined | binary(),
    %% DTLS datagrams received before the DTLS role is known.
    early_dtls = [] :: [binary()],
    media :: term(),
    data :: undefined | map(),
    dcep :: undefined | term(),
    %% Channels requested before SCTP is up: [{From, Label, Opts}].
    pending_channels = [] :: list(),
    timer :: undefined | {reference(), integer()},
    srtp_profiles :: [non_neg_integer()],
    connected = false :: boolean(),
    %% Optional outbound filter used by impairment tests:
    %% fun((Dest, Bin, FState) -> {[{DelayMs, Bin}], FState}).
    filter :: undefined | {fun(), term()},
    %% Host name candidates (mDNS, FQDN) being resolved.
    mdns :: webrtc_mdns_client:client()
}).

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
    IceOpts = maps:with(
        [role, lite, remote_lite, ufrag, pwd, stun_servers, turn_servers, consent, nomination], Opts
    ),
    Addrs = maps:get(addresses, Opts, local_addresses(Opts)),
    Sockets = [S || A <- Addrs, {ok, S} <- [open_socket(A)]],
    case Sockets of
        [] ->
            {stop, no_usable_address};
        _ ->
            {ok, #st{
                pc = Pc,
                app = App,
                sockets = Sockets,
                ice = webrtc_ice_agent:new(IceOpts),
                cert = Cert,
                media = webrtc_media:new(#{
                    cname => maps:get(cname, Opts, <<"webrtc">>),
                    cc => maps:get(congestion_control, Opts, #{})
                }),
                srtp_profiles = maps:get(srtp_profiles, Opts, [16#0007, 16#0008, 16#0001, 16#0002]),
                filter = maps:get(outbound_filter, Opts, undefined),
                mdns = webrtc_mdns_client:new(
                    (maps:get(mdns, Opts, #{}))#{hide_host => maps:get(mdns_host_candidates, Opts, false)},
                    lists:usort([family(IP) || {_, {IP, _}} <- Sockets])
                )
            }}
    end.

open_socket({IP, Port}) ->
    Family =
        case tuple_size(IP) of
            4 -> inet;
            8 -> inet6
        end,
    case gen_udp:open(Port, [binary, Family, {ip, IP}, {active, ?ACTIVE_N}, {recbuf, 1 bsl 20}, {sndbuf, 1 bsl 20}]) of
        {ok, S} ->
            {ok, {_, P}} = inet:sockname(S),
            {ok, {S, {IP, P}}};
        {error, _} = E ->
            E
    end.

%% Host candidates: every up, non-loopback interface address, unless
%% `loopback' is set (tests, local interop), and IPv6 link-local
%% addresses are skipped (RFC 8445 §5.1.1.1).
local_addresses(Opts) ->
    case maps:get(loopback, Opts, false) of
        true ->
            [{{127, 0, 0, 1}, 0}];
        false ->
            {ok, Ifs} = inet:getifaddrs(),
            lists:usort([
                {A, 0}
             || {_Name, Props} <- Ifs,
                lists:member(up, proplists:get_value(flags, Props, [])),
                not lists:member(loopback, proplists:get_value(flags, Props, [])),
                {addr, A} <- Props,
                usable(A)
            ])
    end.

family(IP) when tuple_size(IP) =:= 4 -> inet;
family(_) -> inet6.

usable({169, 254, _, _}) -> false;
usable({A, _, _, _, _, _, _, _}) when A band 16#FFC0 =:= 16#FE80 -> false;
usable(_) -> true.

handle_call(gather, _From, St) ->
    run(St, fun(Now, I) -> webrtc_ice_agent:gather(St#st.sockets, Now, I) end, ok);
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
    St0 = ice_actions(Acts, St#st{ice = I1, mdns = webrtc_mdns_client:restart(St#st.mdns)}),
    %% The candidates are kept across the restart but belong to the new
    %% ICE generation: signal them again (RFC 8445 §9, RFC 8838 §4.4).
    St1 = lists:foldl(fun local_candidate/2, St0, webrtc_ice_agent:local_candidates(I1)),
    to_pc({gathering_state, complete}, St1),
    {reply, ok, arm(St1)};
handle_call({configure, Neg}, _From, St) ->
    St1 = configure_engines(Neg, St),
    {reply, ok, arm(St1)};
handle_call({send_rtp, Mid, Payload, Opts}, _From, St) ->
    media_send(fun(Now, M) -> webrtc_media:send(Mid, Payload, Opts, Now, M) end, St);
handle_call({send_rtp_packet, Mid, Pkt}, _From, St) ->
    media_send(fun(Now, M) -> webrtc_media:send_packet(Mid, Pkt, Now, M) end, St);
handle_call({request_keyframe, Mid}, _From, St) ->
    {Acts, M} = webrtc_media:request_keyframe(Mid, now_ms(), St#st.media),
    St1 = transmit(Acts, St#st{media = M}),
    {reply, ok, arm(St1)};
handle_call({resume_stream, Mid}, _From, St) ->
    case webrtc_media:resume(Mid, now_ms(), St#st.media) of
        {ok, M} -> {reply, ok, St#st{media = M}};
        {error, _} = E -> {reply, E, St}
    end;
handle_call({set_congestion_control, Opts}, _From, St) ->
    {Acts, M} = webrtc_media:set_congestion_control(Opts, now_ms(), St#st.media),
    St1 = media_actions(Acts, St#st{media = M}),
    {reply, ok, arm(St1)};
handle_call({open_channel, Label, Opts}, From, #st{dcep = undefined} = St) ->
    {noreply, St#st{pending_channels = St#st.pending_channels ++ [{From, Label, Opts}]}};
handle_call({open_channel, Label, Opts}, _From, St) ->
    {Reply, St1} = do_open_channel(Label, Opts, St),
    {reply, Reply, arm(St1)};
handle_call({send_data, Id, Type, Data}, _From, #st{dcep = D} = St) when D =/= undefined ->
    case webrtc_dcep:send(Id, Type, Data, now_ms(), D) of
        {ok, D1, Acts} -> {reply, ok, arm(dcep_actions(Acts, St#st{dcep = D1}))};
        {error, _} = E -> {reply, E, St}
    end;
handle_call({send_data, _, _, _}, _From, St) ->
    {reply, {error, not_connected}, St};
handle_call({close_channel, Id}, _From, #st{dcep = D} = St) when D =/= undefined ->
    case webrtc_dcep:close_channel(Id, now_ms(), D) of
        {ok, D1, Acts} -> {reply, ok, arm(dcep_actions(Acts, St#st{dcep = D1}))};
        {error, _} = E -> {reply, E, St}
    end;
handle_call({close_channel, _}, _From, St) ->
    {reply, {error, not_connected}, St};
handle_call({set_app, Pid}, _From, St) ->
    {reply, ok, St#st{app = Pid}};
handle_call(stats, _From, St) ->
    Stats = #{
        addresses => [A || {_, A} <- St#st.sockets],
        ice => webrtc_ice_agent:stats(St#st.ice),
        dtls => case St#st.dtls of undefined -> undefined; D -> webrtc_dtls:info(D) end,
        media => webrtc_media:stats(St#st.media),
        sctp => case St#st.dcep of undefined -> undefined; Dc -> webrtc_sctp_assoc:stats(webrtc_dcep:sctp(Dc)) end
    },
    {reply, Stats, St}.

handle_cast(_Msg, St) ->
    {noreply, St}.

handle_info({udp, Sock, IP, Port, Bin}, St) ->
    St1 = datagram(Sock, {IP, Port}, Bin, now_ms(), St),
    {noreply, arm(St1)};
handle_info({'DOWN', _Ref, process, Pc, _Reason}, #st{pc = Pc} = St) ->
    {stop, normal, St};
handle_info({delayed_send, Sock, Dest, Bin}, St) ->
    udp_send(Sock, Dest, Bin),
    {noreply, St};
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

terminate(_Reason, St) ->
    ok = webrtc_mdns_client:stop(St#st.mdns),
    case St#st.dtls of
        undefined -> ok;
        D -> _ = transmit_dtls(element(2, webrtc_dtls:close(D)), St)
    end,
    _ = [gen_udp:close(S) || {S, _} <- St#st.sockets],
    ok.

%%====================================================================
%% Engines
%%====================================================================

%% Run an ICE agent operation and execute its actions.
run(St, F, Reply) ->
    case F(now_ms(), St#st.ice) of
        {error, _} = E ->
            {reply, E, St};
        {I1, Acts} ->
            St1 = ice_actions(Acts, St#st{ice = I1}),
            {reply, Reply, arm(St1)}
    end.

configure_engines(Neg, St0) ->
    #{dtls := #{role := Role, remote_fingerprints := FPs} = Dtls, media := Media, data := Data} = Neg,
    TlsId = maps:get(remote_tls_id, Dtls, undefined),
    %% RFC 8842 §5: changed fingerprints or tls-id mean a new DTLS
    %% association (JSEP only accepts that with an ICE restart).
    St00 =
        case St0#st.dtls =/= undefined andalso
                 (lists:sort(FPs) =/= lists:sort(St0#st.remote_fps) orelse
                      tls_id_changed(St0#st.remote_tls_id, TlsId)) of
            true -> end_association(dtls_identity_changed, St0);
            false -> St0
        end,
    St1 = St00#st{
        media = webrtc_media:configure(Media, St00#st.media),
        data = Data,
        remote_fps = FPs,
        remote_tls_id = TlsId
    },
    St2 =
        case St1#st.dtls of
            undefined when Role =/= undefined ->
                D = webrtc_dtls:new(#{
                    role => Role,
                    cert => St1#st.cert,
                    remote_fingerprints => FPs,
                    srtp_profiles => St1#st.srtp_profiles
                }),
                start_dtls_if_ready(St1#st{dtls = D, dtls_role = Role});
            _ ->
                St1
        end,
    case St2#st.connected andalso St2#st.dcep =:= undefined andalso Data =/= undefined of
        true -> start_sctp(St2);
        false -> St2
    end.

%% A peer that never sent a tls-id (older stacks) is compared on its
%% fingerprints only.
tls_id_changed(undefined, _) -> false;
tls_id_changed(_, undefined) -> false;
tls_id_changed(Old, New) -> Old =/= New.

%% Close the DTLS association and everything keyed or carried by it:
%% SRTP contexts and the SCTP association (its channels are reported
%% closed). ICE is kept.
end_association(Reason, #st{dtls = D} = St0) ->
    St1 =
        case D of
            undefined ->
                St0;
            _ ->
                {_, Acts} = webrtc_dtls:close(D),
                transmit_dtls(Acts, St0)
        end,
    St2 =
        case St1#st.dcep of
            undefined ->
                St1;
            Dc ->
                _ = [to_pc({datachannel, {channel_closed, Id}}, St1) || Id <- maps:keys(webrtc_dcep:channels(Dc))],
                to_pc({datachannel, {closed, Reason}}, St1),
                St1
        end,
    St2#st{
        dtls = undefined,
        dtls_role = undefined,
        dcep = undefined,
        connected = false,
        early_dtls = [],
        media = webrtc_media:clear_srtp(St2#st.media)
    }.

%% The client starts the handshake once ICE has a pair; buffered early
%% DTLS datagrams are replayed for the server.
start_dtls_if_ready(#st{dtls = undefined} = St) ->
    St;
start_dtls_if_ready(#st{dtls = D} = St) ->
    case webrtc_ice_agent:selected_pair(St#st.ice) of
        undefined ->
            St;
        _ ->
            Now = now_ms(),
            {D1, A} = webrtc_dtls:start(Now, D),
            St1 = dtls_actions(A, St#st{dtls = D1}),
            lists:foldl(
                fun(Bin, S) -> dtls_in(Bin, Now, S) end,
                St1#st{early_dtls = []},
                lists:reverse(St1#st.early_dtls)
            )
    end.

datagram(Sock, Src, Bin, Now, St) ->
    case webrtc_demux:classify(Bin) of
        C when C =:= stun; C =:= turn_channel ->
            {I1, Acts} = webrtc_ice_agent:handle_packet(Sock, Src, Bin, Now, St#st.ice),
            ice_actions(Acts, St#st{ice = I1});
        Class ->
            case webrtc_ice_agent:is_valid_remote(Sock, Src, St#st.ice) of
                true -> secure_datagram(Class, Bin, Now, St);
                false -> St
            end
    end.

secure_datagram(dtls, Bin, Now, St) ->
    dtls_in(Bin, Now, St);
secure_datagram(rtp, Bin, Now, St) ->
    {M1, Acts} = webrtc_media:handle_packet(Bin, Now, St#st.media),
    media_actions(Acts, St#st{media = M1});
secure_datagram(_, _Bin, _Now, St) ->
    St.

dtls_in(Bin, _Now, #st{dtls = undefined, early_dtls = E} = St) when length(E) < ?MAX_EARLY_DTLS ->
    St#st{early_dtls = [Bin | E]};
dtls_in(_Bin, _Now, #st{dtls = undefined} = St) ->
    St;
dtls_in(Bin, Now, #st{dtls = D} = St) ->
    {D1, Acts} = webrtc_dtls:handle_packet(Bin, Now, D),
    dtls_actions(Acts, St#st{dtls = D1}).

tick(Now, St0) ->
    {I1, A1} = webrtc_ice_agent:handle_timeout(Now, St0#st.ice),
    St1 = ice_actions(A1, St0#st{ice = I1}),
    St2 =
        case St1#st.dtls of
            undefined -> St1;
            D ->
                {D1, A2} = webrtc_dtls:handle_timeout(Now, D),
                dtls_actions(A2, St1#st{dtls = D1})
        end,
    {M1, A3} = webrtc_media:handle_timeout(Now, St2#st.media),
    St3 = media_actions(A3, St2#st{media = M1}),
    case St3#st.dcep of
        undefined -> St3;
        Dc ->
            {Dc1, A4} = webrtc_dcep:handle_timeout(Now, Dc),
            dcep_actions(A4, St3#st{dcep = Dc1})
    end.

%%====================================================================
%% Actions
%%====================================================================

ice_actions(Acts, St) ->
    lists:foldl(fun ice_action/2, St, Acts).

ice_action({send, Sock, {IP, Port}, Bin}, #st{filter = undefined} = St) ->
    _ = gen_udp:send(Sock, IP, Port, Bin),
    St;
ice_action({send, Sock, Dest, Bin}, #st{filter = {F, FS}} = St) ->
    %% Test hook (impairment): it runs in this process and must not
    %% block; a crashing filter lets the datagram through.
    {Out, FS1} =
        try F(Dest, Bin, FS) of
            {O, S1} when is_list(O) -> {O, S1}
        catch
            _:_ -> {[{0, Bin}], FS}
        end,
    lists:foreach(
        fun
            ({0, B}) -> udp_send(Sock, Dest, B);
            ({Delay, B}) -> erlang:send_after(Delay, self(), {delayed_send, Sock, Dest, B})
        end,
        Out
    ),
    St#st{filter = {F, FS1}};
ice_action({event, {data, _Via, Peer, Bin}}, St) ->
    %% Relayed non-STUN data: demultiplex as if received from Peer.
    secure_relayed(Peer, Bin, St);
ice_action({event, {selected_pair, L, R}}, St) ->
    to_pc({selected_pair, L, R}, St),
    start_dtls_if_ready(St);
ice_action({event, {local_candidate, C}}, St) ->
    local_candidate(C, St);
ice_action({event, {consent_lost, _, _} = E}, St) ->
    to_pc(E, St),
    St;
ice_action({event, E}, St) ->
    to_pc(E, St),
    St.

%% Signaled as a candidate-attribute value, with an mDNS name in place
%% of the host address when `mdns_host_candidates' is set.
local_candidate(C, St) ->
    {Value, M} = webrtc_mdns_client:local_candidate(C, St#st.mdns),
    to_pc({local_candidate, Value}, St),
    St#st{mdns = M}.

secure_relayed(_Peer, Bin, St) ->
    case webrtc_demux:classify(Bin) of
        dtls -> dtls_in(Bin, now_ms(), St);
        rtp ->
            {M1, Acts} = webrtc_media:handle_packet(Bin, now_ms(), St#st.media),
            media_actions(Acts, St#st{media = M1});
        _ -> St
    end.

udp_send(Sock, {IP, Port}, Bin) ->
    _ = gen_udp:send(Sock, IP, Port, Bin),
    ok.

%% Send a datagram on the selected pair.
send_out(Bin, St) ->
    case webrtc_ice_agent:send(Bin, now_ms(), St#st.ice) of
        {ok, I1, Acts} -> ice_actions(Acts, St#st{ice = I1});
        {error, _} -> St
    end.

transmit(Acts, St) ->
    lists:foldl(fun({send, B}, S) -> send_out(B, S) end, St, [A || {send, _} = A <- Acts]).

transmit_dtls(Acts, St) ->
    transmit(Acts, St).

dtls_actions(Acts, St) ->
    lists:foldl(fun dtls_action/2, St, Acts).

dtls_action({send, Bin}, St) ->
    send_out(Bin, St);
dtls_action({event, {connected, Info}}, St) ->
    St1 = setup_srtp(Info, St#st{connected = true}),
    to_pc({dtls_connected, Info}, St1),
    case St1#st.data of
        undefined -> St1;
        _ -> start_sctp(St1)
    end;
dtls_action({event, {data, Bin}}, #st{dcep = D} = St) when D =/= undefined ->
    {D1, Acts} = webrtc_dcep:handle_packet(Bin, now_ms(), D),
    dcep_actions(Acts, St#st{dcep = D1});
dtls_action({event, {data, _}}, St) ->
    St;
dtls_action({event, {closed, R}}, St) ->
    to_pc({dtls_closed, R}, St),
    St;
dtls_action({event, {failed, R}}, St) ->
    to_pc({dtls_failed, R}, St),
    St.

setup_srtp(#{srtp_profile := undefined}, St) ->
    St;
setup_srtp(#{srtp_profile := Id}, #st{dtls = D} = St) ->
    {ok, Profile} = webrtc_srtp:profile_from_id(Id),
    Len = webrtc_srtp:key_material_length(Profile),
    {ok, Material} = webrtc_dtls:export_keying_material(webrtc_srtp:exporter_label(), no_context, Len, D),
    St#st{media = webrtc_media:set_srtp(Profile, Material, St#st.dtls_role, now_ms(), St#st.media)}.

media_send(F, St) ->
    case F(now_ms(), St#st.media) of
        {ok, Acts, M1} -> {reply, ok, arm(transmit(Acts, St#st{media = M1}))};
        {error, _} = E -> {reply, E, St}
    end.

media_actions(Acts, St) ->
    lists:foldl(
        fun
            ({send, B}, S) -> send_out(B, S);
            ({event, E}, S) -> to_app(E, S), S
        end,
        St,
        Acts
    ).

%% RFC 8841: SCTP runs over the DTLS association once it is up.
start_sctp(#st{data = Data, dtls_role = Role} = St) ->
    LocalMax = maps:get(local_max_message_size, Data, 262144),
    D0 = webrtc_dcep:new(#{
        role => Role,
        max_message_size => maps:get(remote_max_message_size, Data, 65536),
        sctp => #{
            local_port => maps:get(local_port, Data, 5000),
            remote_port => maps:get(remote_port, Data, 5000),
            %% The limit we announced in SDP bounds incoming messages
            %% (RFC 8841 §6); the window holds at least two of them.
            max_message_size => LocalMax,
            receive_buffer => max(1048576, 2 * LocalMax),
            %% 1200 byte datagrams minus the DTLS record overhead (13 byte
            %% header, 8 byte explicit nonce, 16 byte tag), so SCTP
            %% packets never need IP fragmentation (RFC 8261 §5).
            mtu => 1200 - 37
        }
    }),
    {D1, Acts} = webrtc_dcep:connect(now_ms(), D0),
    St1 = dcep_actions(Acts, St#st{dcep = D1}),
    lists:foldl(
        fun({From, Label, Opts}, S) ->
            {Reply, S1} = do_open_channel(Label, Opts, S),
            gen_server:reply(From, Reply),
            S1
        end,
        St1#st{pending_channels = []},
        St1#st.pending_channels
    ).

do_open_channel(Label, Opts, #st{dcep = D} = St) ->
    case webrtc_dcep:open_channel(Label, Opts, now_ms(), D) of
        {ok, Id, D1, Acts} -> {{ok, Id}, dcep_actions(Acts, St#st{dcep = D1})};
        {error, _} = E -> {E, St}
    end.

dcep_actions(Acts, St) ->
    lists:foldl(fun dcep_action/2, St, Acts).

dcep_action({send, Bin}, #st{dtls = D} = St) ->
    case webrtc_dtls:send(Bin, D) of
        {ok, D1, Out} -> transmit(Out, St#st{dtls = D1});
        {error, _} -> St
    end;
dcep_action({event, {channel_message, _, _, _} = E}, St) ->
    to_app(E, St),
    St;
dcep_action({event, E}, St) ->
    to_pc({datachannel, E}, St),
    St.

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
