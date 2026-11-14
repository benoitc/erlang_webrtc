%% @private One peer connection (RTCPeerConnection): JSEP signaling,
%% transceivers, data channel bookkeeping and the connection state. The
%% transport process does the packet work. See `webrtc' for the API.
-module(webrtc_pc).
-behaviour(gen_server).

-include("webrtc_sdp.hrl").
-include("webrtc_ice.hrl").

-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-record(st, {
    app :: pid(),
    app_mon :: reference(),
    opts :: map(),
    cert :: map(),
    jsep :: term(),
    transport :: undefined | pid(),
    ice_role :: undefined | controlling | controlled,
    ice_state = new :: atom(),
    gathering = new :: atom(),
    dtls_state = new :: new | connected | failed | closed,
    connection = new :: atom(),
    configured = false :: boolean(),
    sctp_up = false :: boolean(),
    pending_channels = [] :: [{binary(), map()}],
    announced_tracks = [] :: [binary()],
    local_candidates = [] :: [#sdp_candidate{}],
    remote_candidates_sent = 0 :: non_neg_integer(),
    remote_ice :: undefined | {binary(), binary()},
    %% We started an ICE restart and wait for the peer's new credentials.
    local_restart = false :: boolean()
}).

start_link(Opts) ->
    gen_server:start_link(?MODULE, Opts, []).

%%====================================================================
%% gen_server
%%====================================================================

init(#{owner := App} = Opts) ->
    process_flag(trap_exit, true),
    Cert = maps:get(certificate, Opts, webrtc_dtls_cert:generate()),
    FP = webrtc_dtls_cert:fingerprint(sha256, maps:get(der, Cert)),
    Jsep = webrtc_jsep:new(#{
        ice_ufrag => ice_string(8),
        ice_pwd => ice_string(24),
        fingerprints => [FP],
        ice_lite => maps:get(ice_lite, Opts, false),
        max_message_size => maps:get(max_message_size, Opts, 262144)
    }),
    {ok, #st{app = App, app_mon = monitor(process, App), opts = Opts, cert = Cert, jsep = Jsep}}.

handle_call({add_transceiver, Kind, TOpts}, _From, St) ->
    case webrtc_jsep:add_transceiver(Kind, TOpts, St#st.jsep) of
        {ok, Id, J} ->
            notify(negotiation_needed, St),
            {reply, {ok, Id}, St#st{jsep = J}};
        {error, _} = E ->
            {reply, E, St}
    end;
handle_call({set_direction, Id, Dir}, _From, St) ->
    reply_jsep(webrtc_jsep:set_direction(Id, Dir, St#st.jsep), St);
handle_call({stop_transceiver, Id}, _From, St) ->
    reply_jsep(webrtc_jsep:stop_transceiver(Id, St#st.jsep), St);
handle_call(transceivers, _From, St) ->
    {reply, webrtc_jsep:transceivers(St#st.jsep), St};
handle_call({create_data_channel, Label, COpts}, _From, St) ->
    J = webrtc_jsep:add_data_channel(St#st.jsep),
    St1 = St#st{jsep = J},
    case St1#st.sctp_up of
        true ->
            {reply, webrtc_transport:open_channel(St1#st.transport, Label, COpts), St1};
        false ->
            case webrtc_jsep:negotiated(St#st.jsep) of
                #{data := #{}} -> ok;
                _ -> notify(negotiation_needed, St)
            end,
            {reply, ok, St1#st{pending_channels = St1#st.pending_channels ++ [{Label, COpts}]}}
    end;
handle_call({create_offer, Opts}, _From, St) ->
    J0 = St#st.jsep,
    J1 = webrtc_jsep:set_local_candidates(St#st.local_candidates, St#st.gathering =:= complete, J0),
    case webrtc_jsep:create_offer(Opts, J1) of
        {ok, Sdp, J2} -> {reply, {ok, webrtc_sdp:encode(Sdp)}, St#st{jsep = J2}};
        {error, _} = E -> {reply, E, St}
    end;
handle_call({create_answer, Opts}, _From, St) ->
    J1 = webrtc_jsep:set_local_candidates(St#st.local_candidates, St#st.gathering =:= complete, St#st.jsep),
    case webrtc_jsep:create_answer(Opts, J1) of
        {ok, Sdp, J2} -> {reply, {ok, webrtc_sdp:encode(Sdp)}, St#st{jsep = J2}};
        {error, _} = E -> {reply, E, St}
    end;
handle_call({set_local_description, Type, Sdp}, _From, St) ->
    case parse(Type, Sdp) of
        {ok, Parsed} ->
            case webrtc_jsep:set_local_description(Type, Parsed, St#st.jsep) of
                {ok, J} ->
                    St1 = signaling_changed(St#st{jsep = J}),
                    St2 = ensure_transport(Type, St1),
                    {reply, ok, after_negotiation(St2)};
                {error, _} = E ->
                    {reply, E, St}
            end;
        {error, _} = E ->
            {reply, E, St}
    end;
handle_call({set_remote_description, Type, Sdp}, _From, St) ->
    case parse(Type, Sdp) of
        {ok, Parsed} ->
            case webrtc_jsep:set_remote_description(Type, Parsed, St#st.jsep) of
                {ok, J} ->
                    St1 = signaling_changed(St#st{jsep = J}),
                    St2 = push_remote_ice(St1),
                    {reply, ok, after_negotiation(St2)};
                {error, _} = E ->
                    {reply, E, St}
            end;
        {error, _} = E ->
            {reply, E, St}
    end;
handle_call({add_ice_candidate, end_of_candidates}, _From, #st{transport = T} = St) when is_pid(T) ->
    {reply, webrtc_transport:end_of_candidates(T), St};
handle_call({add_ice_candidate, Cand}, _From, #st{transport = T} = St) when is_pid(T) ->
    {reply, webrtc_transport:add_remote_candidate(T, Cand), St};
handle_call({add_ice_candidate, _}, _From, St) ->
    %% RFC 9429 §4.1.17: candidates need a remote description.
    {reply, {error, no_remote_description}, St};
handle_call(restart_ice, _From, St) ->
    U = ice_string(8),
    P = ice_string(24),
    J = webrtc_jsep:restart_ice(U, P, St#st.jsep),
    case St#st.transport of
        undefined -> ok;
        T -> ok = webrtc_transport:restart_ice(T, U, P)
    end,
    notify(negotiation_needed, St),
    {reply, ok, St#st{jsep = J, local_candidates = [], gathering = new, local_restart = true}};
handle_call(transport_pid, _From, #st{transport = T} = St) when is_pid(T) ->
    {reply, {ok, T}, St};
handle_call(transport_pid, _From, St) ->
    {reply, {error, not_connected}, St};
handle_call(local_description, _From, St) ->
    {reply, encode_opt(webrtc_jsep:local_description(St#st.jsep)), St};
handle_call(remote_description, _From, St) ->
    {reply, encode_opt(webrtc_jsep:remote_description(St#st.jsep)), St};
handle_call(signaling_state, _From, St) ->
    {reply, webrtc_jsep:signaling_state(St#st.jsep), St};
handle_call(connection_state, _From, St) ->
    {reply, St#st.connection, St};
handle_call(get_stats, _From, St) ->
    Transport =
        case St#st.transport of
            undefined -> undefined;
            T -> webrtc_transport:stats(T)
        end,
    {reply, #{connection_state => St#st.connection, ice_state => St#st.ice_state, transport => Transport}, St};
handle_call({controlling_process, Pid}, _From, St) ->
    demonitor(St#st.app_mon, [flush]),
    case St#st.transport of
        undefined -> ok;
        T -> ok = webrtc_transport:set_app(T, Pid)
    end,
    {reply, ok, St#st{app = Pid, app_mon = monitor(process, Pid)}};
handle_call(close, _From, St) ->
    {stop, normal, ok, close_now(St)}.

handle_cast(_Msg, St) ->
    {noreply, St}.

handle_info({webrtc_transport, T, Event}, #st{transport = T} = St) ->
    {noreply, transport_event(Event, St)};
handle_info({'DOWN', Ref, process, _, _}, #st{app_mon = Ref} = St) ->
    {stop, normal, close_now(St)};
handle_info({'EXIT', T, Reason}, #st{transport = T} = St) ->
    notify({connection_state, failed}, St),
    {stop, {transport_exit, Reason}, St#st{transport = undefined}};
handle_info(_Other, St) ->
    {noreply, St}.

terminate(_Reason, St) ->
    _ = close_now(St),
    ok.

%%====================================================================
%% Negotiation glue
%%====================================================================

parse(rollback, _) -> {ok, undefined};
parse(_Type, Sdp) when is_binary(Sdp) ->
    case webrtc_sdp:parse(Sdp) of
        {ok, P} -> {ok, P};
        {error, R} -> {error, {bad_sdp, R}}
    end;
parse(_Type, _) ->
    {error, bad_sdp}.

encode_opt(undefined) -> undefined;
encode_opt(Sdp) -> webrtc_sdp:encode(Sdp).

reply_jsep({ok, J}, St) ->
    notify(negotiation_needed, St),
    {reply, ok, St#st{jsep = J}};
reply_jsep({error, _} = E, St) ->
    {reply, E, St}.

signaling_changed(St) ->
    notify({signaling_state, webrtc_jsep:signaling_state(St#st.jsep)}, St),
    St.

%% The transport starts with the first local description: the offerer is
%% the controlling ICE agent (RFC 8445 §6.1.1), a lite agent is always
%% controlled, and a full agent facing a lite peer controls.
ensure_transport(rollback, St) ->
    St;
ensure_transport(Type, #st{transport = undefined} = St) ->
    Lite = maps:get(ice_lite, St#st.opts, false),
    RemoteLite =
        case webrtc_jsep:remote_description(St#st.jsep) of
            undefined -> false;
            R -> webrtc_sdp_media:ice_lite(R)
        end,
    Role =
        if
            Lite -> controlled;
            RemoteLite -> controlling;
            Type =:= offer -> controlling;
            true -> controlled
        end,
    #sdp{media = [M | _]} = Local = webrtc_jsep:local_description(St#st.jsep),
    {ok, #{ufrag := U, pwd := P}} = webrtc_sdp_media:ice_credentials(M, Local),
    TOpts = maps:merge(
        maps:with([stun_servers, turn_servers, addresses, loopback, consent, nomination, outbound_filter], St#st.opts),
        #{
            pc => self(),
            app => St#st.app,
            cert => St#st.cert,
            role => Role,
            lite => Lite,
            remote_lite => RemoteLite,
            ufrag => U,
            pwd => P
        }
    ),
    {ok, T} = webrtc_transport:start_link(TOpts),
    ok = webrtc_transport:gather(T),
    push_remote_ice(St#st{transport = T, ice_role = Role});
ensure_transport(_Type, St) ->
    St.

%% Give the transport the remote credentials and the candidates found in
%% the remote description.
push_remote_ice(#st{transport = undefined} = St) ->
    St;
push_remote_ice(#st{transport = T} = St) ->
    case webrtc_jsep:remote_description(St#st.jsep) of
        undefined ->
            St;
        #sdp{media = Media} = R ->
            case [C || M <- Media, M#sdp_media.port =/= 0, {ok, C} <- [webrtc_sdp_media:ice_credentials(M, R)]] of
                [#{ufrag := U, pwd := P} | _] ->
                    St0 = maybe_remote_restart({U, P}, St),
                    ok = webrtc_transport:set_remote_ice(T, U, P),
                    Cands = lists:flatmap(fun webrtc_sdp_media:candidates/1, Media),
                    Sent = case St0#st.remote_ice =:= {U, P} of
                        true -> St0#st.remote_candidates_sent;
                        false -> 0
                    end,
                    New = lists:nthtail(min(Sent, length(Cands)), Cands),
                    _ = [ok = webrtc_transport:add_remote_candidate(T, C) || C <- New],
                    case lists:any(fun webrtc_sdp_media:end_of_candidates/1, Media) of
                        true -> ok = webrtc_transport:end_of_candidates(T);
                        false -> ok
                    end,
                    St0#st{remote_candidates_sent = length(Cands), remote_ice = {U, P}};
                [] ->
                    St
            end
    end.

%% New remote ICE credentials mean an ICE restart (RFC 8445 §9). When the
%% peer started it, restart our agent too with new credentials, which the
%% answer carries (RFC 9429 §5.3.1).
maybe_remote_restart(Creds, #st{remote_ice = Old} = St) when Old =:= undefined; Old =:= Creds ->
    St;
maybe_remote_restart(_Creds, #st{local_restart = true} = St) ->
    St#st{local_restart = false};
maybe_remote_restart(_Creds, #st{transport = T} = St) ->
    U = ice_string(8),
    P = ice_string(24),
    ok = webrtc_transport:restart_ice(T, U, P),
    St#st{jsep = webrtc_jsep:restart_ice(U, P, St#st.jsep), local_candidates = [], gathering = new}.

%% Once in stable state with both descriptions, configure the engines and
%% announce remote tracks.
after_negotiation(#st{transport = T} = St) when is_pid(T) ->
    case {webrtc_jsep:signaling_state(St#st.jsep), webrtc_jsep:negotiated(St#st.jsep)} of
        {stable, #{} = Neg} ->
            ok = webrtc_transport:configure(T, Neg),
            announce_tracks(Neg, St#st{configured = true});
        _ ->
            St
    end;
after_negotiation(St) ->
    St.

announce_tracks(#{media := Media}, St) ->
    New = [
        {Mid, K}
     || #{mid := Mid, kind := K, direction := D} <- Media,
        D =:= sendrecv orelse D =:= recvonly,
        not lists:member(Mid, St#st.announced_tracks)
    ],
    _ = [notify({track, Mid, K}, St) || {Mid, K} <- New],
    St#st{announced_tracks = St#st.announced_tracks ++ [Mid || {Mid, _} <- New]}.

%%====================================================================
%% Transport events and connection state (W3C RTCPeerConnectionState)
%%====================================================================

transport_event({local_candidate, #ice_cand{} = C}, St) ->
    Value = webrtc_ice_candidate:to_sdp(C),
    Mid = bundle_tag(St),
    notify({ice_candidate, Value, Mid}, St),
    {ok, SdpCand} = webrtc_sdp_candidate:parse(Value),
    St#st{local_candidates = St#st.local_candidates ++ [SdpCand]};
transport_event({gathering_state, G}, St) ->
    notify({ice_gathering_state, G}, St),
    case G of
        complete -> notify({ice_candidate, end_of_candidates, bundle_tag(St)}, St);
        _ -> ok
    end,
    St#st{gathering = G};
transport_event({connection_state, S}, St) ->
    notify({ice_connection_state, S}, St),
    update_connection(St#st{ice_state = S});
transport_event({dtls_connected, _Info}, St) ->
    update_connection(St#st{dtls_state = connected});
transport_event({dtls_failed, R}, St) ->
    notify({dtls_error, R}, St),
    update_connection(St#st{dtls_state = failed});
transport_event({dtls_closed, _R}, St) ->
    update_connection(St#st{dtls_state = closed});
transport_event({consent_lost, _, _}, St) ->
    update_connection(St#st{ice_state = failed});
transport_event({datachannel, {connected, _}}, St) ->
    _ = [webrtc_transport:open_channel(St#st.transport, L, O) || {L, O} <- St#st.pending_channels],
    St#st{sctp_up = true, pending_channels = []};
transport_event({datachannel, {channel_open, Id, Label, Proto, Opts}}, St) ->
    notify({datachannel_open, Id, Label, Proto, Opts}, St),
    St;
transport_event({datachannel, {channel_closed, Id}}, St) ->
    notify({datachannel_closed, Id}, St),
    St;
transport_event({datachannel, {buffered_amount_low, Id}}, St) ->
    notify({buffered_amount_low, Id}, St),
    St;
transport_event({datachannel, {closed, R}}, St) ->
    notify({sctp_closed, R}, St),
    St#st{sctp_up = false};
transport_event({datachannel, _Other}, St) ->
    St;
transport_event(_Other, St) ->
    St.

update_connection(St) ->
    New =
        case {St#st.ice_state, St#st.dtls_state} of
            {_, failed} -> failed;
            {failed, _} -> failed;
            {_, closed} -> closed;
            {closed, _} -> closed;
            {I, connected} when I =:= connected; I =:= completed -> connected;
            {disconnected, _} -> disconnected;
            {new, new} -> new;
            _ -> connecting
        end,
    case New =:= St#st.connection of
        true ->
            St;
        false ->
            notify({connection_state, New}, St),
            St#st{connection = New}
    end.

bundle_tag(St) ->
    case webrtc_jsep:local_description(St#st.jsep) of
        #sdp{media = [M | _]} -> webrtc_sdp_media:mid(M);
        _ -> <<"0">>
    end.

close_now(#st{transport = undefined} = St) ->
    St;
close_now(#st{transport = T} = St) ->
    unlink(T),
    _ = catch_stop(T),
    notify({connection_state, closed}, St),
    St#st{transport = undefined, jsep = webrtc_jsep:close(St#st.jsep), connection = closed}.

catch_stop(T) ->
    try webrtc_transport:stop(T) catch exit:_ -> ok end.

notify(Event, #st{app = App}) ->
    App ! {webrtc, self(), Event},
    ok.

%% ICE ufrag/pwd: ice-char = ALPHA / DIGIT / "+" / "/" (RFC 8839 §5.4),
%% ufrag at least 4 characters and pwd at least 22 (24 bits and 128 bits
%% of randomness).
ice_string(N) ->
    Alphabet = <<"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/">>,
    << <<(binary:at(Alphabet, B band 63))>> || <<B>> <= crypto:strong_rand_bytes(N) >>.
