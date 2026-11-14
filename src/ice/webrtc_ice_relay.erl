%% @private
%% @doc Relayed candidates of the ICE agent (RFC 8656, RFC 8445
%% §5.1.1.2, §7.2.1).
%%
%% Integration choice: the agent owns one `webrtc_turn_client' state per
%% (host socket, TURN server), keyed `{Socket, ServerAddr}'. A relayed
%% candidate is reached through the path `{relay, Socket, ServerAddr}':
%% checks and data sent from it are wrapped by the TURN client (Send
%% indication, or ChannelData once the selected pair has a channel) and
%% sent to the server over the host socket; data relayed by the server
%% is unwrapped and handed back to the agent with that path, so relayed
%% checks go through the normal check processing. Permissions are
%% created for every remote candidate address so the peer's checks
%% reach the relayed candidate.
-module(webrtc_ice_relay).

-include("webrtc_ice_int.hrl").

-export([
    allocate/6,
    send/5,
    turn_key/3,
    turn_packet/4,
    turn_timeout/2,
    permit/3,
    bind_channel/3,
    close/2
]).

%% @doc Start an allocation for the gathering job `Job'.
-spec allocate(term(), pos_integer(), tuple(), map(), integer(), #ice{}) -> {#ice{}, [term()]}.
allocate(Key, HostId, Job, Opts, Now, S) ->
    C0 = webrtc_turn_client:new(Opts),
    {C1, TActs} = webrtc_turn_client:allocate(Now, C0),
    Entry = #{client => C1, host => HostId, job => Job, relay => undefined},
    {S1, Acts, _} = turn_actions(Key, TActs, Now, S#ice{turn = (S#ice.turn)#{Key => Entry}}),
    {S1, Acts}.

%% @doc Send `Bin' to `To' through the allocation `Key'.
-spec send(term(), webrtc_ice_candidate:address(), binary(), integer(), #ice{}) -> {#ice{}, [term()]}.
send(Key, To, Bin, Now, S) ->
    case maps:find(Key, S#ice.turn) of
        {ok, #{client := C} = E} ->
            {C1, TActs} = webrtc_turn_client:send(To, Bin, Now, C),
            {S1, Acts, _} = turn_actions(Key, TActs, Now, S#ice{turn = (S#ice.turn)#{Key => E#{client => C1}}}),
            {S1, Acts};
        error ->
            {S, []}
    end.

-spec turn_key(term(), webrtc_ice_candidate:address(), #ice{}) -> {ok, term()} | error.
turn_key(Sock, From, #ice{turn = T}) ->
    case maps:is_key({Sock, From}, T) of
        true -> {ok, {Sock, From}};
        false -> error
    end.

%% @doc Datagram from a TURN server. Returns the relayed datagrams
%% `{Via, Peer, Data}' for the agent to process.
-spec turn_packet(term(), binary(), integer(), #ice{}) -> {#ice{}, [term()], [tuple()]}.
turn_packet(Key, Bin, Now, S) ->
    #{client := C} = E = maps:get(Key, S#ice.turn),
    {C1, TActs} = webrtc_turn_client:handle_packet(Bin, Now, C),
    turn_actions(Key, TActs, Now, S#ice{turn = (S#ice.turn)#{Key => E#{client => C1}}}).

-spec turn_timeout(integer(), #ice{}) -> {#ice{}, [term()], [tuple()]}.
turn_timeout(Now, S) ->
    maps:fold(
        fun(Key, #{client := C}, {SA, AA, DA}) ->
            case webrtc_turn_client:next_timeout(C) =< Now of
                true ->
                    case maps:find(Key, SA#ice.turn) of
                        {ok, #{client := C0} = E} ->
                            {C1, TActs} = webrtc_turn_client:handle_timeout(Now, C0),
                            SA1 = SA#ice{turn = (SA#ice.turn)#{Key => E#{client => C1}}},
                            {SB, AB, DB} = turn_actions(Key, TActs, Now, SA1),
                            {SB, AA ++ AB, DA ++ DB};
                        error ->
                            {SA, AA, DA}
                    end;
                false ->
                    {SA, AA, DA}
            end
        end,
        {S, [], []},
        S#ice.turn
    ).

turn_actions({Sock, Server} = Key, TActs, Now, S) ->
    lists:foldl(
        fun
            ({send, B}, {SA, AA, DA}) ->
                {SA, AA ++ [{send, Sock, Server, B}], DA};
            ({event, Ev}, {SA, AA, DA}) ->
                {SB, AB, DB} = turn_event(Key, Ev, Now, SA),
                {SB, AA ++ AB, DA ++ DB}
        end,
        {S, [], []},
        TActs
    ).

turn_event({Sock, Server} = Key, {allocated, #{relayed := {RIP, RPort}, mapped := Mapped}}, Now, S) ->
    case maps:find(Key, S#ice.turn) of
        {ok, #{host := HostId, job := {relay, _, _, Idx} = Job} = E} ->
            Host = webrtc_ice_checklist:local(HostId, S),
            HostLP = (Host#ice_cand.priority bsr 8) band 16#FFFF,
            Comp = Host#ice_cand.component,
            {SIP, _} = Server,
            {RelA, RelP} = case Mapped of
                {MA, MP} -> {MA, MP};
                undefined -> {undefined, undefined}
            end,
            Relay = #ice_cand{
                foundation = webrtc_ice_candidate:foundation(relay, RIP, SIP, udp),
                component = Comp,
                priority = webrtc_ice_candidate:priority(relay, max(0, HostLP - Idx), Comp),
                address = RIP,
                port = RPort,
                type = relay,
                related_address = RelA,
                related_port = RelP,
                base = {RIP, RPort},
                socket = Sock,
                server = Server
            },
            S1 = S#ice{gather_pending = lists:delete(Job, S#ice.gather_pending)},
            %% A relayed candidate identical to a host candidate is discarded.
            HostAddrs = [{A, P} || _ := #ice_cand{type = host, address = A, port = P} <- S1#ice.local],
            {S2, A1} =
                case lists:member({RIP, RPort}, HostAddrs) of
                    true ->
                        {S1, []};
                    false ->
                        {RId, SR} = webrtc_ice_gather:add_local(Relay, S1#ice.next_id, S1),
                        SR1 = SR#ice{turn = (SR#ice.turn)#{Key => E#{relay => RId}}},
                        {webrtc_ice_checklist:pair_new_local(RId, SR1), [{event, {local_candidate, Relay}}]}
                end,
            {S3, A2} =
                case Mapped of
                    undefined -> {S2, []};
                    _ -> webrtc_ice_gather:add_srflx(HostId, Host, Server, Idx, Mapped, S2)
                end,
            {S4, A3} = permit_all(Key, Now, S3),
            {S5, A4} = webrtc_ice_gather:maybe_complete(S4),
            {S5, A1 ++ A2 ++ A3 ++ A4, []};
        error ->
            {S, [], []}
    end;
turn_event(Key, {allocate_failed, Reason}, _Now, S) ->
    case maps:take(Key, S#ice.turn) of
        {#{job := {relay, HostId, #{address := Server}, Idx} = Job}, Turn} ->
            S1 = S#ice{turn = Turn, gather_pending = lists:delete(Job, S#ice.gather_pending)},
            %% A server out of resources can still give a server-reflexive
            %% candidate (RFC 8445 §5.1.1.2).
            Queue =
                case Reason of
                    {error, C} when C =:= 486; C =:= 508 -> [{srflx, HostId, Server, Idx}];
                    _ -> []
                end,
            {S2, A} = webrtc_ice_gather:maybe_complete(S1#ice{gather_queue = S1#ice.gather_queue ++ Queue}),
            {S2, A ++ [{event, {turn_error, Server, Reason}}], []};
        error ->
            {S, [], []}
    end;
turn_event(Key, {allocation_lost, _} = Lost, Now, S) ->
    drop_relay(Key, [{event, {turn_error, element(2, Key), Lost}}], Now, S);
turn_event(Key, closed, Now, S) ->
    drop_relay(Key, [], Now, S);
turn_event({Sock, Server}, {data, Peer, Data}, _Now, S) ->
    {S, [], [{{relay, Sock, Server}, Peer, Data}]};
turn_event(_Key, _Other, _Now, S) ->
    {S, [], []}.

drop_relay(Key, Extra, Now, S) ->
    case maps:take(Key, S#ice.turn) of
        {#{relay := RId}, Turn} ->
            {S1, A} = webrtc_ice_gather:remove_locals([R || R <- [RId], R =/= undefined], Now, S#ice{turn = Turn}),
            {S1, A ++ Extra, []};
        error ->
            {S, [], []}
    end.

%% @doc Create TURN permissions towards a new remote candidate, so the
%% peer's checks reach our relayed candidates (RFC 8445 §7.2.1).
-spec permit(#ice_cand{}, integer(), #ice{}) -> {#ice{}, [term()]}.
permit(#ice_cand{address = IP}, Now, S) ->
    lists:foldl(
        fun(Key, {SA, AA}) ->
            {SB, AB} = permit_one(Key, IP, Now, SA),
            {SB, AA ++ AB}
        end,
        {S, []},
        maps:keys(S#ice.turn)
    ).

permit_one(Key, IP, Now, S) ->
    #{client := C} = E = maps:get(Key, S#ice.turn),
    case webrtc_turn_client:relayed_address(C) of
        {RIP, _} ->
            case webrtc_ice_candidate:family(RIP) =:= webrtc_ice_candidate:family(IP) of
                true ->
                    {C1, TActs} = webrtc_turn_client:create_permission(IP, Now, C),
                    {S1, Acts, _} = turn_actions(Key, TActs, Now, S#ice{turn = (S#ice.turn)#{Key => E#{client => C1}}}),
                    {S1, Acts};
                false ->
                    {S, []}
            end;
        undefined ->
            {S, []}
    end.

permit_all(Key, Now, S) ->
    IPs = lists:usort([IP || _ := #ice_cand{address = IP} <- S#ice.remote]),
    lists:foldl(
        fun(IP, {SA, AA}) ->
            case maps:is_key(Key, SA#ice.turn) of
                true ->
                    {SB, AB} = permit_one(Key, IP, Now, SA),
                    {SB, AA ++ AB};
                false ->
                    {SA, AA}
            end
        end,
        {S, []},
        IPs
    ).

%% @doc Bind a TURN channel for the selected pair when its local
%% candidate is relayed.
-spec bind_channel(#pair{}, integer(), #ice{}) -> {#ice{}, [term()]}.
bind_channel(#pair{} = P, Now, S) ->
    case {webrtc_ice_checklist:pair_local(P, S), webrtc_ice_checklist:remote(P#pair.remote, S)} of
        {#ice_cand{type = relay, socket = Sock, server = Server}, #ice_cand{address = A, port = Po}} ->
            Key = {Sock, Server},
            case maps:find(Key, S#ice.turn) of
                {ok, #{client := C} = E} ->
                    {C1, TActs} = webrtc_turn_client:bind_channel({A, Po}, Now, C),
                    {S1, Acts, _} = turn_actions(Key, TActs, Now, S#ice{turn = (S#ice.turn)#{Key => E#{client => C1}}}),
                    {S1, Acts};
                error ->
                    {S, []}
            end;
        _ ->
            {S, []}
    end.

%% @doc Delete every allocation.
-spec close(integer(), #ice{}) -> {#ice{}, [term()]}.
close(Now, S) ->
    maps:fold(
        fun({Sock, Server}, #{client := C}, {SA, AA}) ->
            {_, TActs} = webrtc_turn_client:close(Now, C),
            {SA, AA ++ [{send, Sock, Server, B} || {send, B} <- TActs]}
        end,
        {S#ice{turn = #{}}, []},
        S#ice.turn
    ).
