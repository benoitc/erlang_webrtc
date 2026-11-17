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
    local_restart = false :: boolean(),
    %% A remote ICE restart accepted by JSEP but not applied to the
    %% transport until the exchange ends in stable state: our new
    %% credentials, and the local candidates to restore on rollback.
    ice_pending :: undefined | #{ufrag := binary(), pwd := binary(), candidates := list(), gathering := atom()},
    %% Remote candidates trickled after the remote description but before
    %% our local description started the transport (bounded).
    early_candidates = [] :: [binary() | end_of_candidates],
    %% Transports after the first, when the sections are not all
    %% bundled (RFC 9143): Key => #{pid, mids, remote, sent, cands, ice,
    %% dtls}. The first transport is `transport'.
    extra = #{} :: #{binary() => map()},
    %% Options every transport starts with (credentials apart).
    topts :: undefined | map(),
    %% Automatic ICE restart after consent trouble (RFC 8445 §8.1.1
    %% allows no second nomination, so recovery is a restart): the
    %% pending timer and the restarts made since ICE last connected.
    restart_timer :: undefined | reference(),
    auto_restarts = 0 :: non_neg_integer(),
    %% Helper process calling the `signaling' function.
    signaler :: undefined | pid()
}).

-define(MAX_EARLY_CANDIDATES, 64).
%% Restarts tried for one incident before ICE is reported failed.
-define(MAX_AUTO_RESTARTS, 3).
%% The ICE agent's limit (webrtc_ice_agent).
-define(MAX_ICE_SERVERS, 8).

start_link(Opts) ->
    gen_server:start_link(?MODULE, Opts, []).

%%====================================================================
%% gen_server
%%====================================================================

init(#{owner := App} = Opts0) ->
    process_flag(trap_exit, true),
    {Opts, ServerErrors} = ice_servers(Opts0),
    _ = [App ! {webrtc, self(), {ice_server_error, Url, Reason}} || {Url, Reason} <- ServerErrors],
    Cert = maps:get(certificate, Opts, webrtc_dtls_cert:generate()),
    FP = webrtc_dtls_cert:fingerprint(sha256, maps:get(der, Cert)),
    Jsep = webrtc_jsep:new(maps:merge(maps:with([codecs, extensions, bundle, cryptex, encrypt_header_extensions,
                                                 rtcp_mux_policy], Opts), #{
        ice_ufrag => ice_string(8),
        ice_pwd => ice_string(24),
        fingerprints => [FP],
        ice_lite => maps:get(ice_lite, Opts, false),
        max_message_size => maps:get(max_message_size, Opts, 262144)
    })),
    Signaler = case maps:get(signaling, Opts, undefined) of
        F when is_function(F, 2) -> spawn_link(fun() -> signaler(F) end);
        _ -> undefined
    end,
    {ok, #st{app = App, app_mon = monitor(process, App), opts = Opts, cert = Cert, jsep = Jsep, signaler = Signaler}}.

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
            {reply, webrtc_transport:open_channel(data_pid(St1), Label, COpts), St1};
        false ->
            case webrtc_jsep:negotiated(St#st.jsep) of
                #{data := #{}} -> ok;
                _ -> notify(negotiation_needed, St)
            end,
            %% A pre-negotiated channel already has its id (RFC 8832 §6).
            Reply = case COpts of
                #{negotiated := true, id := Id} -> {ok, Id};
                _ -> ok
            end,
            {reply, Reply, St1#st{pending_channels = St1#st.pending_channels ++ [{Label, COpts}]}}
    end;
handle_call({create_offer, Opts}, _From, St) ->
    reply_sdp(create(offer, Opts, St), St);
handle_call({create_answer, Opts}, _From, St) ->
    reply_sdp(create(answer, Opts, St), St);
handle_call({set_local_description, Type, Sdp}, _From, St) ->
    reply_set(set_local(Type, Sdp, St), St);
handle_call({set_remote_description, Type, Sdp}, _From, St) ->
    reply_set(set_remote(Type, Sdp, St), St);
handle_call({add_ice_candidate, Cand, Mid}, From, St) ->
    case extra_of_mid(Mid, St) of
        {ok, #{pid := T}} when Cand =:= end_of_candidates -> {reply, webrtc_transport:end_of_candidates(T), St};
        {ok, #{pid := T}} -> {reply, webrtc_transport:add_remote_candidate(T, Cand), St};
        error -> handle_call({add_ice_candidate, Cand}, From, St)
    end;
handle_call({add_ice_candidate, Cand}, _From, St) ->
    case webrtc_jsep:remote_view(St#st.jsep) of
        %% RFC 9429 §4.1.17: candidates need a remote description.
        undefined -> {reply, {error, no_remote_description}, St};
        _ -> add_candidate(Cand, St)
    end;
handle_call(restart_ice, _From, St) ->
    {reply, ok, restart_now(St)};
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
handle_call({get_stats, w3c}, _From, St) ->
    Transports =
        [{K, webrtc_transport:stats(T)} || {K, T} <- [{0, St#st.transport} || is_pid(St#st.transport)]] ++
            [{K, webrtc_transport:stats(P)} || K := #{pid := P} <- St#st.extra],
    Neg = case webrtc_jsep:negotiated(St#st.jsep) of #{media := Ms} -> Ms; _ -> [] end,
    {Ufrag, _} = webrtc_jsep:local_ice(St#st.jsep),
    {reply, webrtc_stats:report(#{
        timestamp => erlang:system_time(millisecond),
        certificate => maps:get(der, St#st.cert),
        ufrag => Ufrag,
        media => Neg,
        transports => Transports
    }), St};
handle_call(get_stats, _From, St) ->
    Transport =
        case St#st.transport of
            undefined -> undefined;
            T -> webrtc_transport:stats(T)
        end,
    Extra = #{K => webrtc_transport:stats(P) || K := #{pid := P} <- St#st.extra},
    {reply, #{connection_state => St#st.connection, ice_state => St#st.ice_state, transport => Transport,
              transports => Extra}, St};
handle_call({controlling_process, Pid}, _From, St) ->
    demonitor(St#st.app_mon, [flush]),
    case St#st.transport of
        undefined -> ok;
        T -> ok = webrtc_transport:set_app(T, Pid)
    end,
    _ = [ok = webrtc_transport:set_app(X, Pid) || _ := #{pid := X} <- St#st.extra],
    {reply, ok, St#st{app = Pid, app_mon = monitor(process, Pid)}};
handle_call(close, _From, St) ->
    {stop, normal, ok, close_now(St)}.

handle_cast(_Msg, St) ->
    {noreply, St}.

handle_info({webrtc_transport, T, Event}, #st{transport = T} = St) ->
    {noreply, transport_event(Event, St)};
handle_info({webrtc_transport, T, Event}, St) ->
    case [K || K := #{pid := P} <- St#st.extra, P =:= T] of
        [K] -> {noreply, extra_event(K, Event, St)};
        [] -> {noreply, St}
    end;
handle_info({'DOWN', Ref, process, _, _}, #st{app_mon = Ref} = St) ->
    {stop, normal, close_now(St)};
handle_info({'EXIT', T, Reason}, #st{transport = T} = St) ->
    ets:delete(webrtc_transports, self()),
    notify({connection_state, failed}, St),
    {stop, {transport_exit, Reason}, St#st{transport = undefined}};
handle_info({'EXIT', T, Reason}, St) ->
    case [K || K := #{pid := P} <- St#st.extra, P =:= T] of
        [_] ->
            notify({connection_state, failed}, St),
            {stop, {transport_exit, Reason}, St};
        [] ->
            {noreply, St}
    end;
handle_info({auto_restart, Ref}, #st{restart_timer = Ref} = St0) ->
    St = St0#st{restart_timer = undefined},
    Busy = St#st.local_restart orelse St#st.ice_pending =/= undefined,
    case troubled(St) of
        [_ | _] = Bad when not Busy, St#st.auto_restarts < ?MAX_AUTO_RESTARTS ->
            Reason = case lists:member(failed, Bad) of true -> consent_lost; false -> disconnected end,
            notify({ice_restart, Reason}, St),
            St1 = restart_ice_creds(St#st{auto_restarts = St#st.auto_restarts + 1}),
            {noreply, update_connection(auto_offer(St1))};
        _ ->
            {noreply, update_connection(St)}
    end;
handle_info(_Other, St) ->
    {noreply, St}.

%% New ICE credentials for every transport; the application sends the
%% offer (negotiation_needed).
restart_now(St) ->
    St1 = restart_ice_creds(St),
    notify(negotiation_needed, St1),
    St1.

restart_ice_creds(St) ->
    U = ice_string(8),
    P = ice_string(24),
    J = webrtc_jsep:restart_ice(U, P, St#st.jsep),
    case St#st.transport of
        undefined -> ok;
        T -> ok = webrtc_transport:restart_ice(T, U, P)
    end,
    St1 = restart_extra(St#st{jsep = J}),
    St1#st{local_candidates = [], gathering = new, local_restart = true}.

%% ICE states of every transport that call for a restart.
troubled(St) ->
    [S || S <- [St#st.ice_state | [I || _ := #{ice := I} <- St#st.extra]], S =:= disconnected orelse S =:= failed].

%% `ice_auto_restart': `disconnected' (default) restarts after
%% `ice_restart_delay' ms disconnected, `failed' once consent is lost,
%% `false' never. The controlling side restarts first; the controlled
%% side waits three times as long, so the peer's restart offer normally
%% comes first (no glare).
auto_restart(#st{opts = O} = St) ->
    Policy = maps:get(ice_auto_restart, O, disconnected),
    Bad = troubled(St),
    Delay = maps:get(ice_restart_delay, O, 2000) * case St#st.ice_role of controlled -> 3; _ -> 1 end,
    Due =
        case Policy of
            disconnected -> Bad =/= [];
            failed -> lists:member(failed, Bad);
            false -> false
        end,
    case {Due, St#st.restart_timer} of
        {true, undefined} ->
            Ref = make_ref(),
            erlang:send_after(Delay, self(), {auto_restart, Ref}),
            St#st{restart_timer = Ref};
        {false, _} when Bad =:= [] ->
            %% Connected again: the incident is over.
            Connected = lists:all(fun(S) -> S =:= connected orelse S =:= completed end,
                                  [St#st.ice_state | [I || _ := #{ice := I} <- St#st.extra]]),
            St#st{restart_timer = undefined, auto_restarts = case Connected of true -> 0; false -> St#st.auto_restarts end};
        _ ->
            St
    end.

%% While restarts remain, a failed ICE transport is only disconnected.
recovering(#st{opts = O, auto_restarts = N}) ->
    maps:get(ice_auto_restart, O, disconnected) =/= false andalso N < ?MAX_AUTO_RESTARTS.

terminate(_Reason, St) ->
    _ = close_now(St),
    ok.

%% The transport starts with our local description; until then trickled
%% candidates are kept (bounded).
add_candidate(end_of_candidates, #st{transport = T} = St) when is_pid(T) ->
    {reply, webrtc_transport:end_of_candidates(T), St};
add_candidate(Cand, #st{transport = T} = St) when is_pid(T) ->
    case restart_pending(St) of
        %% Candidates of the next ICE generation wait for it.
        true -> hold_candidate(Cand, St);
        false -> {reply, webrtc_transport:add_remote_candidate(T, Cand), St}
    end;
add_candidate(Cand, St) ->
    hold_candidate(Cand, St).

hold_candidate(_Cand, #st{early_candidates = E} = St) when length(E) >= ?MAX_EARLY_CANDIDATES ->
    {reply, {error, too_many_candidates}, St};
hold_candidate(Cand, St) ->
    {reply, ok, St#st{early_candidates = St#st.early_candidates ++ [Cand]}}.

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

reply_sdp({ok, Sdp, St1}, _St) -> {reply, {ok, Sdp}, St1};
reply_sdp({error, _} = E, St) -> {reply, E, St}.

reply_set({ok, St1}, _St) -> {reply, ok, St1};
reply_set({error, _} = E, St) -> {reply, E, St}.

create(Type, Opts, St) ->
    J1 = webrtc_jsep:set_local_candidates(St#st.local_candidates, St#st.gathering =:= complete, St#st.jsep),
    Made = case Type of
        offer -> webrtc_jsep:create_offer(Opts, J1);
        answer -> webrtc_jsep:create_answer(Opts, J1)
    end,
    case Made of
        {ok, Sdp, J2} -> {ok, webrtc_sdp:encode(Sdp), St#st{jsep = J2}};
        {error, _} = E -> E
    end.

set_local(Type, Sdp, St) ->
    case parse(Type, Sdp) of
        {ok, Parsed} ->
            case webrtc_jsep:set_local_description(Type, Parsed, St#st.jsep) of
                {ok, J} ->
                    St1 = signaling_changed(St#st{jsep = J}),
                    {ok, after_negotiation(sync_ice(local, Type, ensure_transport(Type, St1)))};
                {error, _} = E ->
                    E
            end;
        {error, _} = E ->
            E
    end.

set_remote(offer, Sdp, St0) ->
    case parse(offer, Sdp) of
        {ok, Parsed} ->
            St = yield_restart(St0),
            case webrtc_jsep:set_remote_description(offer, Parsed, St#st.jsep) of
                {ok, J} ->
                    St1 = signaling_changed(St#st{jsep = J}),
                    {ok, auto_answer(after_negotiation(sync_ice(remote, offer, St1)))};
                {error, _} = E ->
                    E
            end;
        {error, _} = E ->
            E
    end;
set_remote(Type, Sdp, St) ->
    case parse(Type, Sdp) of
        {ok, Parsed} ->
            case webrtc_jsep:set_remote_description(Type, Parsed, St#st.jsep) of
                {ok, J} ->
                    St1 = signaling_changed(St#st{jsep = J}),
                    {ok, after_negotiation(sync_ice(remote, Type, St1))};
                {error, _} = E ->
                    E
            end;
        {error, _} = E ->
            E
    end.

%% Option `signaling': the connection runs the offer and answer of ICE
%% restarts by itself and hands each description to the function,
%% called in order from a helper process (it may call back into either
%% peer connection).
signaling(#st{signaler = undefined}) -> false;
signaling(_) -> true.

signal(Type, Sdp, #st{signaler = S}) ->
    S ! {description, Type, Sdp},
    ok.

signaler(Fun) ->
    receive
        {description, Type, Sdp} ->
            try Fun(Type, Sdp) catch _:_ -> ok end,
            signaler(Fun);
        {notify, To, Msg} ->
            To ! Msg,
            signaler(Fun)
    end.

%% Our automatic restart: offer it ourselves when nothing else is
%% under negotiation, otherwise leave it to the application.
auto_offer(St) ->
    case signaling(St) andalso webrtc_jsep:signaling_state(St#st.jsep) =:= stable of
        true ->
            case create(offer, #{}, St) of
                {ok, Sdp, St1} ->
                    case set_local(offer, Sdp, St1) of
                        {ok, St2} -> ok = signal(offer, Sdp, St2), St2;
                        {error, _} -> notify(negotiation_needed, St), St
                    end;
                {error, _} ->
                    notify(negotiation_needed, St),
                    St
            end;
        false ->
            notify(negotiation_needed, St),
            St
    end.

%% A remote ICE restart offer is answered at once (RFC 9429 §5.3.1).
auto_answer(St) ->
    case signaling(St) andalso webrtc_jsep:signaling_state(St#st.jsep) =:= have_remote_offer
             andalso restart_pending(St) of
        true ->
            case create(answer, #{}, St) of
                {ok, Sdp, St1} ->
                    case set_local(answer, Sdp, St1) of
                        {ok, St2} -> ok = signal(answer, Sdp, St2), St2;
                        {error, _} -> St
                    end;
                {error, _} ->
                    St
            end;
        false ->
            St
    end.

%% Glare between two automatic restarts: the controlled side is the
%% polite peer and rolls its own offer back (RFC 9429 §4.1.8.2).
yield_restart(#st{local_restart = true, ice_role = controlled} = St) ->
    case signaling(St) andalso webrtc_jsep:signaling_state(St#st.jsep) =:= have_local_offer of
        true ->
            case set_local(rollback, undefined, St) of
                {ok, St1} -> St1;
                {error, _} -> St
            end;
        false ->
            St
    end;
yield_restart(St) ->
    St.

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
        case webrtc_jsep:remote_view(St#st.jsep) of
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
        maps:with(
            [stun_servers, turn_servers, addresses, loopback, consent, nomination, outbound_filter, congestion_control, mdns,
                rtcp_report_interval, ice_tcp,
                mdns_host_candidates, mdns_expose_public, dtls, srtp_profiles],
            St#st.opts
        ),
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
    true = ets:insert(webrtc_transports, {self(), T}),
    ok = webrtc_transport:gather(T),
    St1 = flush_candidates(push_remote_ice(St#st{transport = T, ice_role = Role, topts = maps:without([ufrag, pwd], TOpts)})),
    ensure_extra(St1);
ensure_transport(_Type, St) ->
    ensure_extra(St).

flush_candidates(#st{transport = T, early_candidates = Early} = St) ->
    _ = [
        case C of
            end_of_candidates -> webrtc_transport:end_of_candidates(T);
            _ -> webrtc_transport:add_remote_candidate(T, C)
        end
     || C <- Early
    ],
    St#st{early_candidates = []}.

%% Keep the transport's ICE in step with the descriptions. New remote
%% credentials mean an ICE restart (RFC 8445 §9); it reaches the
%% transport only once the exchange is in stable state, so a rolled back
%% offer or provisional answer leaves the live ICE generation untouched
%% (RFC 9429 §5.7). When the peer restarts, our answer carries new
%% credentials (RFC 9429 §5.3.1): they are chosen with the remote offer
%% and given to the transport with our answer.
sync_ice(_Side, rollback, #st{ice_pending = #{candidates := C, gathering := G}} = St) ->
    St#st{ice_pending = undefined, local_candidates = C, gathering = G, early_candidates = []};
sync_ice(_Side, rollback, St) ->
    St;
sync_ice(_Side, _Type, #st{transport = undefined} = St) ->
    St;
sync_ice(Side, Type, St0) ->
    St = push_extra(St0),
    sync_ice1(Side, Type, St).

sync_ice1(Side, _Type, St) ->
    case {Side, restart_pending(St), webrtc_jsep:signaling_state(St#st.jsep)} of
        {_, true, stable} -> flush_candidates(push_remote_ice(apply_restart(St)));
        {remote, true, _} -> defer_restart(St);
        {remote, false, _} -> push_remote_ice(St);
        {local, _, _} -> St
    end.

restart_pending(#st{remote_ice = undefined}) ->
    false;
restart_pending(#st{remote_ice = Old} = St) ->
    case remote_credentials(St) of
        undefined -> false;
        New -> New =/= Old
    end.

remote_credentials(St) ->
    case webrtc_jsep:remote_view(St#st.jsep) of
        undefined ->
            undefined;
        #sdp{media = Media} = R ->
            case [C || M <- Media, M#sdp_media.port =/= 0, {ok, C} <- [webrtc_sdp_media:ice_credentials(M, R)]] of
                [#{ufrag := U, pwd := P} | _] -> {U, P};
                [] -> undefined
            end
    end.

defer_restart(#st{ice_pending = undefined, local_restart = false} = St) ->
    U = ice_string(8),
    P = ice_string(24),
    St#st{
        jsep = webrtc_jsep:restart_ice(U, P, St#st.jsep),
        ice_pending = #{ufrag => U, pwd => P, candidates => St#st.local_candidates, gathering => St#st.gathering},
        local_candidates = [],
        gathering = new
    };
defer_restart(St) ->
    St.

apply_restart(#st{transport = T, ice_pending = #{ufrag := U, pwd := P}} = St) ->
    ok = webrtc_transport:restart_ice(T, U, P),
    St#st{ice_pending = undefined};
apply_restart(#st{local_restart = true} = St) ->
    %% Our own restart: the transport already has our new credentials.
    St#st{local_restart = false};
apply_restart(#st{transport = T} = St) ->
    U = ice_string(8),
    P = ice_string(24),
    ok = webrtc_transport:restart_ice(T, U, P),
    St#st{jsep = webrtc_jsep:restart_ice(U, P, St#st.jsep), local_candidates = [], gathering = new}.

%% Give the transport the remote credentials and the candidates found in
%% the remote description.
push_remote_ice(#st{transport = T} = St) ->
    case remote_credentials(St) of
        undefined ->
            St;
        {U, P} = Creds ->
            #sdp{media = Media} = webrtc_jsep:remote_view(St#st.jsep),
            ok = webrtc_transport:set_remote_ice(T, U, P),
            Cands = lists:flatmap(fun webrtc_sdp_media:candidates/1, Media),
            Sent =
                case St#st.remote_ice =:= Creds of
                    true -> St#st.remote_candidates_sent;
                    false -> 0
                end,
            New = lists:nthtail(min(Sent, length(Cands)), Cands),
            %% Candidates that cannot be used are ignored (RFC 8839 §5.1).
            _ = [webrtc_transport:add_remote_candidate(T, C) || C <- New],
            case lists:any(fun webrtc_sdp_media:end_of_candidates/1, Media) of
                true -> ok = webrtc_transport:end_of_candidates(T);
                false -> ok
            end,
            St#st{remote_candidates_sent = length(Cands), remote_ice = Creds}
    end.

%% With both descriptions, configure the engines and announce remote
%% tracks: in stable state, and with a provisional answer (media may
%% flow, RFC 9429 §4.1.10.1) unless it carries an ICE restart, which
%% waits for the final answer.
after_negotiation(#st{transport = T} = St) when is_pid(T) ->
    S = webrtc_jsep:signaling_state(St#st.jsep),
    Ready =
        S =:= stable orelse
            ((S =:= have_local_pranswer orelse S =:= have_remote_pranswer) andalso not restart_pending(St)),
    case {Ready, webrtc_jsep:negotiated(St#st.jsep)} of
        {true, #{} = Neg} ->
            ok = webrtc_transport:configure(T, view(Neg, primary_key(St))),
            _ = [ok = webrtc_transport:configure(P, view(Neg, K)) || K := #{pid := P} <- St#st.extra],
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

transport_event({local_candidate, Value}, St) when is_binary(Value) ->
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
    update_connection(auto_restart(St#st{ice_state = S}));
transport_event({dtls_connected, _Info}, St) ->
    update_connection(St#st{dtls_state = connected});
transport_event({dtls_failed, R}, St) ->
    notify({dtls_error, R}, St),
    update_connection(St#st{dtls_state = failed});
transport_event({dtls_closed, _R}, St) ->
    update_connection(St#st{dtls_state = closed});
transport_event({consent_lost, _, _}, St) ->
    update_connection(auto_restart(St#st{ice_state = failed}));
transport_event({ssrc_changed, Mid, Old, New}, St) ->
    %% RFC 3550 §8.2: later offers and answers carry the new SSRC.
    St#st{jsep = webrtc_jsep:change_ssrc(Mid, Old, New, St#st.jsep)};
transport_event({datachannel, {connected, _}}, St) ->
    lists:foreach(
        fun({L, O}) ->
            case webrtc_transport:open_channel(data_pid(St), L, O) of
                {ok, _} -> ok;
                {error, R} -> notify({datachannel_open_failed, L, R}, St)
            end
        end,
        St#st.pending_channels
    ),
    St#st{sctp_up = true, pending_channels = []};
transport_event({datachannel, {channel_open, Id, Label, Proto, Opts}}, St) ->
    notify({datachannel_open, Id, Label, Proto, Opts}, St),
    St;
transport_event({datachannel, {channel_closed, Id}}, St) ->
    notify({datachannel_closed, Id}, St),
    St;
transport_event({datachannel, {channel_error, Id, Reason}}, St) ->
    notify({datachannel_error, Id, Reason}, St),
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
    Ice = fun(failed) -> case recovering(St) of true -> disconnected; false -> failed end; (I) -> I end,
    States = [transport_state(Ice(St#st.ice_state), St#st.dtls_state)] ++
        [transport_state(Ice(I), D) || _ := #{ice := I, dtls := D} <- St#st.extra],
    %% W3C RTCPeerConnectionState over every transport.
    L = lists:usort(States),
    New =
        case [S || S <- [failed, closed, disconnected], lists:member(S, L)] of
            [S | _] -> S;
            [] when L =:= [connected] -> connected;
            [] when L =:= [new] -> new;
            [] -> connecting
        end,
    case New =:= St#st.connection of
        true ->
            St;
        false ->
            notify({connection_state, New}, St),
            St#st{connection = New}
    end.

transport_state(Ice, Dtls) ->
    case {Ice, Dtls} of
        {_, failed} -> failed;
        {failed, _} -> failed;
        {_, closed} -> closed;
        {closed, _} -> closed;
        {I, connected} when I =:= connected; I =:= completed -> connected;
        {disconnected, _} -> disconnected;
        {new, new} -> new;
        _ -> connecting
    end.

bundle_tag(St) ->
    case {primary_key(St), webrtc_jsep:local_description(St#st.jsep)} of
        {undefined, #sdp{media = [M | _]}} -> webrtc_sdp_media:mid(M);
        {undefined, _} -> <<"0">>;
        {K, _} -> K
    end.

close_now(#st{transport = undefined} = St) ->
    St;
close_now(#st{transport = T} = St) ->
    ets:delete(webrtc_transports, self()),
    ets:match_delete(webrtc_transports, {{self(), '_'}, '_'}),
    _ = [ok = stop_transport(P) || _ := #{pid := P} <- St#st.extra],
    ok = stop_transport(T),
    notify({connection_state, closed}, St),
    St#st{transport = undefined, jsep = webrtc_jsep:close(St#st.jsep), connection = closed}.

%% Stop the linked transport; one that does not stop in time (stuck in a
%% callback) is killed, so it can never survive with its sockets. The
%% link stays until the transport is gone.
stop_transport(T) ->
    try
        webrtc_transport:stop(T)
    catch
        exit:_ ->
            exit(T, kill),
            receive
                {'EXIT', T, _} -> ok
            after 5000 -> ok
            end
    end,
    receive
        {'EXIT', T, _} -> ok
    after 0 -> ok
    end.

%%====================================================================
%% Transports after the first (RFC 9143: sections not all bundled)
%%====================================================================

primary_key(St) ->
    case webrtc_jsep:transports(St#st.jsep) of
        [#{key := K} | _] -> K;
        [] -> undefined
    end.

%% Start the transports of the local description that have none yet.
ensure_extra(#st{transport = undefined} = St) ->
    St;
ensure_extra(#st{topts = TOpts} = St) ->
    Pc = self(),
    lists:foldl(
        fun(#{key := K, mids := Ms, ufrag := U, pwd := P}, Acc) ->
            case maps:is_key(K, Acc#st.extra) of
                true ->
                    Acc;
                false ->
                    {ok, T} = webrtc_transport:start_link(TOpts#{ufrag => U, pwd => P}),
                    true = ets:insert(webrtc_transports, [{{Pc, M}, T} || M <- Ms] ++ data_row(Pc, Ms, T, Acc)),
                    ok = webrtc_transport:gather(T),
                    X = #{pid => T, mids => Ms, remote => undefined, sent => 0, cands => [], ice => new, dtls => new,
                           local_restart => false},
                    push_extra(Acc#st{extra = (Acc#st.extra)#{K => X}})
            end
        end,
        St,
        case webrtc_jsep:transports(St#st.jsep) of
            [_ | Rest] -> Rest;
            [] -> []
        end
    ).

data_row(Pc, Mids, T, St) ->
    case data_mid(St) of
        undefined -> [];
        D -> [{{Pc, data}, T} || lists:member(D, Mids)]
    end.

data_mid(St) ->
    case webrtc_jsep:negotiated(St#st.jsep) of
        #{data := #{mid := D}} -> D;
        _ -> webrtc_jsep:data_mid(St#st.jsep)
    end.

%% The transport carrying SCTP.
data_pid(St) ->
    D = data_mid(St),
    case [P || _ := #{pid := P, mids := Ms} <- St#st.extra, lists:member(D, Ms)] of
        [P | _] -> P;
        [] -> St#st.transport
    end.

extra_of_mid(undefined, _St) ->
    error;
extra_of_mid(Mid, St) ->
    case [X || _ := #{mids := Ms} = X <- St#st.extra, lists:member(Mid, Ms)] of
        [X | _] -> {ok, X};
        [] -> error
    end.

%% Remote credentials and candidates of every extra transport, from its
%% sections of the remote description. New credentials restart it at
%% once with new local ones, which the next description carries.
push_extra(St) ->
    case webrtc_jsep:remote_view(St#st.jsep) of
        undefined ->
            St;
        #sdp{media = Media} = R ->
            maps:fold(
                fun(K, #{pid := T, mids := Ms} = X, Acc) ->
                    Secs = [M || M <- Media, lists:member(webrtc_sdp_media:mid(M), Ms), M#sdp_media.port =/= 0],
                    Order = [M || M <- Secs, webrtc_sdp_media:mid(M) =:= K] ++ Secs,
                    case [C || M <- Order, {ok, C} <- [webrtc_sdp_media:ice_credentials(M, R)]] of
                        [#{ufrag := U, pwd := P} | _] when map_get(local_restart, X), map_get(remote, X) =:= {U, P} ->
                            %% Our restart waits for its answer.
                            Acc;
                        [#{ufrag := U, pwd := P} | _] ->
                            Acc1 = extra_restart(K, X, {U, P}, Acc),
                            ok = webrtc_transport:set_remote_ice(T, U, P),
                            Cands = lists:flatmap(fun webrtc_sdp_media:candidates/1, Secs),
                            Sent = case maps:get(remote, X) =:= {U, P} of true -> maps:get(sent, X); false -> 0 end,
                            _ = [webrtc_transport:add_remote_candidate(T, C) || C <- lists:nthtail(min(Sent, length(Cands)), Cands)],
                            _ = [ok = webrtc_transport:end_of_candidates(T) || lists:any(fun webrtc_sdp_media:end_of_candidates/1, Secs)],
                            X1 = maps:get(K, Acc1#st.extra),
                            Acc1#st{extra = (Acc1#st.extra)#{K => X1#{remote => {U, P}, sent => length(Cands)}}};
                        [] ->
                            Acc
                    end
                end,
                St,
                St#st.extra
            )
    end.

extra_restart(_K, #{remote := undefined}, _Creds, St) -> St;
extra_restart(_K, #{remote := Creds}, Creds, St) -> St;
extra_restart(K, #{local_restart := true} = X, _New, St) ->
    %% The answer to our restart: the transport has its new credentials.
    St#st{extra = (St#st.extra)#{K => X#{local_restart := false}}};
extra_restart(K, #{pid := T} = X, _New, St) ->
    U = ice_string(8),
    P = ice_string(24),
    ok = webrtc_transport:restart_ice(T, U, P),
    St#st{jsep = webrtc_jsep:set_transport_credentials(K, U, P, St#st.jsep),
          extra = (St#st.extra)#{K => X#{cands => []}}}.

%% Our ICE restart restarts every transport.
restart_extra(St) ->
    maps:fold(
        fun(K, #{pid := T} = X, Acc) ->
            U = ice_string(8),
            P = ice_string(24),
            ok = webrtc_transport:restart_ice(T, U, P),
            Acc#st{jsep = webrtc_jsep:set_transport_credentials(K, U, P, Acc#st.jsep),
                   extra = (Acc#st.extra)#{K => X#{cands => [], local_restart => true}}}
        end,
        St,
        St#st.extra
    ).

%% What one transport is configured with: its ICE and DTLS parameters,
%% its media and, when it carries it, the data channel.
view(Neg, Key) ->
    case [T || #{key := K} = T <- maps:get(transports, Neg, []), K =:= Key] of
        [#{ice := Ice, dtls := Dtls}] ->
            Data =
                case maps:get(data, Neg) of
                    #{transport := Key} = D -> D;
                    #{transport := _} -> undefined;
                    D -> D
                end,
            Neg#{ice => Ice, dtls => Dtls, media => [M || M <- maps:get(media, Neg), maps:get(transport, M, Key) =:= Key],
                 data => Data};
        [] ->
            Neg
    end.

extra_event(K, Event, St) ->
    X = maps:get(K, St#st.extra),
    Put = fun(X1) -> St#st{extra = (St#st.extra)#{K => X1}} end,
    case Event of
        {local_candidate, Value} when is_binary(Value) ->
            notify({ice_candidate, Value, K}, St),
            {ok, C} = webrtc_sdp_candidate:parse(Value),
            Cands = maps:get(cands, X) ++ [C],
            St1 = Put(X#{cands => Cands}),
            St1#st{jsep = webrtc_jsep:set_local_candidates(K, Cands, false, St1#st.jsep)};
        {gathering_state, complete} ->
            notify({ice_candidate, end_of_candidates, K}, St),
            St#st{jsep = webrtc_jsep:set_local_candidates(K, maps:get(cands, X), true, St#st.jsep)};
        {connection_state, S} ->
            update_connection(auto_restart(Put(X#{ice => S})));
        {consent_lost, _, _} ->
            update_connection(auto_restart(Put(X#{ice => failed})));
        {dtls_connected, _} ->
            update_connection(Put(X#{dtls => connected}));
        {dtls_failed, R} ->
            notify({dtls_error, R}, St),
            update_connection(Put(X#{dtls => failed}));
        {dtls_closed, _} ->
            update_connection(Put(X#{dtls => closed}));
        {datachannel, _} ->
            %% SCTP runs on this transport.
            transport_event(Event, St);
        {ssrc_changed, _, _, _} ->
            transport_event(Event, St);
        _ ->
            St
    end.

%% With `signaling', candidates go through the helper so the peer
%% never gets one before the description it belongs to.
notify({ice_candidate, _, _} = Event, #st{app = App, signaler = S}) when is_pid(S) ->
    S ! {notify, App, {webrtc, self(), Event}},
    ok;
notify(Event, #st{app = App}) ->
    App ! {webrtc, self(), Event},
    ok.

%% `ice_servers' URIs resolved and added to `stun_servers' and
%% `turn_servers', within the ICE agent's limit of eight servers.
ice_servers(#{ice_servers := List} = Opts) ->
    {ok, Servers, Unsupported} = webrtc_ice_uri:servers(List),
    {Found, Errors} = webrtc_ice_resolve:resolve(Servers, maps:filter(fun(_, V) -> V =/= undefined end, #{
        timeout => maps:get(ice_server_timeout, Opts, undefined),
        resolver => maps:get(ice_resolver, Opts, undefined)
    })),
    Stun0 = maps:get(stun_servers, Opts, []),
    Turn0 = maps:get(turn_servers, Opts, []),
    Room = max(0, ?MAX_ICE_SERVERS - length(Stun0) - length(Turn0)),
    %% TURN first: a relay also gives the server reflexive address.
    {In, Out} = lists:split(min(Room, length(Found)), [E || {_, {turn, _}} = E <- Found] ++ [E || {_, {stun, _}} = E <- Found]),
    Dropped = lists:usort([{Url, too_many_servers} || {Url, _} <- Out]),
    {Opts#{stun_servers => Stun0 ++ [A || {_, {stun, A}} <- In], turn_servers => Turn0 ++ [T || {_, {turn, T}} <- In]},
     Unsupported ++ Errors ++ Dropped};
ice_servers(Opts) ->
    {Opts, []}.

%% ICE ufrag/pwd: ice-char = ALPHA / DIGIT / "+" / "/" (RFC 8839 §5.4),
%% ufrag at least 4 characters and pwd at least 22 (24 bits and 128 bits
%% of randomness).
ice_string(N) ->
    Alphabet = <<"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/">>,
    << <<(binary:at(Alphabet, B band 63))>> || <<B>> <= crypto:strong_rand_bytes(N) >>.
