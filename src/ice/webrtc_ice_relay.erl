%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
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
    stream_up/3,
    stream_down/4,
    send/5,
    turn_key/3,
    turn_packet/4,
    turn_timeout/2,
    permit/3,
    bind_channel/3,
    close/2,
    udp_socket_up/4,
    udp_socket_down/4
]).

%% @doc Start an allocation for the gathering job `Job'.
-spec allocate(term(), pos_integer(), tuple(), map(), integer(), #ice{}) -> {#ice{}, [term()]}.
allocate(Key, HostId, Job, Opts, Now, S) ->
    C0 = webrtc_turn_client:new(Opts),
    {relay, _, Cfg, _} = Job,
    {C1, TActs} = webrtc_turn_client:allocate(Now, C0),
    Entry = #{client => C1, host => HostId, job => Job, relay => undefined, transport => maps:get(transport, Cfg, udp)},
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
        {ok, #{host := HostId, job := {relay, _, _, Idx} = Job, transport := Transport} = E} ->
            Host = webrtc_ice_checklist:local(HostId, S),
            HostLP = (Host#ice_cand.priority bsr 8) band 16#FFFF,
            %% A relay reached over TCP or TLS comes after one over UDP
            %% (as browsers order them): its local preference is lower.
            Penalty = case Transport of udp -> 0; tcp -> 16#400; tls -> 16#800 end,
            Comp = Host#ice_cand.component,
            {SIP, _} = Server,
            {RelA, RelP} = case Mapped of
                {MA, MP} -> {MA, MP};
                undefined -> {undefined, undefined}
            end,
            Relay = #ice_cand{
                foundation = webrtc_ice_candidate:foundation(relay, RIP, SIP, Transport),
                component = Comp,
                priority = webrtc_ice_candidate:priority(relay, max(0, HostLP - Idx - Penalty), Comp),
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
turn_event(Key, {allocate_failed, Reason}, Now, S) ->
    case maps:take(Key, S#ice.turn) of
        {#{job := {relay, HostId, #{address := Server} = Cfg, Idx} = Job, transport := Tr}, Turn} ->
            case retry(Reason, Server, Cfg, Tr, webrtc_ice_gather:fallback(Server, S)) of
                {alternate, Alt} ->
                    %% RFC 8656 §7.4: the same job against the alternate.
                    Tried = [Server | maps:get(tried, Cfg, [])],
                    Next = {relay, HostId, Cfg#{address => Alt, tried => Tried}, Idx},
                    S1 = S#ice{turn = Turn, gather_pending = lists:delete(Job, S#ice.gather_pending),
                               gather_queue = [Next | S#ice.gather_queue]},
                    {S1, [], []};
                new_socket ->
                    %% RFC 8656 §7.4: 437 means another allocation holds
                    %% this 5-tuple; allocate again from a new local port.
                    #ice_cand{address = IP} = webrtc_ice_checklist:local(HostId, S),
                    Ref = {udp, S#ice.next_stream},
                    Next = {relay, HostId, Cfg#{retried => true}, Idx},
                    S1 = S#ice{turn = Turn, next_stream = S#ice.next_stream + 1,
                               streams = (S#ice.streams)#{Ref => {HostId, Next, webrtc_ice_gather:relay_opts(Cfg, S)}},
                               gather_pending = [Next | lists:delete(Job, S#ice.gather_pending)]},
                    {S1, [{open_udp, Ref, #{local => IP}}], []};
                no when Reason =:= timeout ->
                    {S1, A, D} = failed_job(Turn, Job, HostId, Server, Idx, Reason, Now, S),
                    {S1, [{event, {server_unreachable, Server}} | A], D};
                no ->
                    failed_job(Turn, Job, HostId, Server, Idx, Reason, Now, S)
            end;
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

%% What a failed allocation leads to: an alternate server (at most three
%% redirections, never back to one already tried), a new local port
%% once after a 437 on UDP, or nothing.
retry({try_alternate, Alt}, Server, Cfg, _Tr, _Fallback) ->
    Tried = [Server | maps:get(tried, Cfg, [])],
    case length(Tried) =< 3 andalso not lists:member(Alt, Tried) of
        true -> {alternate, Alt};
        false -> no
    end;
retry({error, 437}, _Server, Cfg, udp, _Fallback) ->
    case maps:get(retried, Cfg, false) of
        true -> no;
        false -> new_socket
    end;
%% No answer at all: the next address of the URI (RFC 5928 §3). A server
%% that answered with an error is not failed over (RFC 8656 §7.3).
retry(timeout, _Server, _Cfg, _Tr, {ok, Next}) ->
    {alternate, Next};
retry(_Reason, _Server, _Cfg, _Tr, _Fallback) ->
    no.

failed_job(Turn, Job, HostId, Server, Idx, Reason, _Now, S) ->
    S1 = S#ice{turn = Turn, gather_pending = lists:delete(Job, S#ice.gather_pending)},
    %% A server out of resources can still give a server-reflexive
    %% candidate (RFC 8445 §5.1.1.2).
    Queue =
        case Reason of
            {error, C} when C =:= 486; C =:= 508 -> [{srflx, HostId, Server, Idx}];
            _ -> []
        end,
    {S2, A} = webrtc_ice_gather:maybe_complete(S1#ice{gather_queue = S1#ice.gather_queue ++ Queue}),
    {S2, A ++ [{event, {turn_error, Server, Reason}}], []}.

%% @doc The owner opened the UDP socket asked with `{open_udp, Ref, _}'
%% (a retry after 437): allocate through it.
-spec udp_socket_up({udp, pos_integer()}, term(), integer(), #ice{}) -> {#ice{}, [term()]}.
udp_socket_up(Ref, Sock, Now, S) ->
    case maps:take(Ref, S#ice.streams) of
        {{HostId, {relay, _, #{address := Server}, _} = Job, Opts}, Streams} ->
            allocate({Sock, Server}, HostId, Job, Opts, Now, S#ice{streams = Streams});
        error ->
            {S, []}
    end.

%% @doc The owner could not open it: the job fails.
-spec udp_socket_down({udp, pos_integer()}, term(), integer(), #ice{}) -> {#ice{}, [term()]}.
udp_socket_down(Ref, Reason, _Now, S) ->
    case maps:take(Ref, S#ice.streams) of
        {{_HostId, {relay, _, #{address := Server}, _} = Job, _}, Streams} ->
            S1 = S#ice{streams = Streams, gather_pending = lists:delete(Job, S#ice.gather_pending)},
            {S2, A} = webrtc_ice_gather:maybe_complete(S1),
            {S2, A ++ [{event, {turn_error, Server, {socket, Reason}}}]};
        error ->
            {S, []}
    end.

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

%% @doc Delete every allocation; stream connections are closed once
%% the deletion is sent, pending ones at once.
-spec close(integer(), #ice{}) -> {#ice{}, [term()]}.
close(Now, S) ->
    {S1, Acts} = maps:fold(
        fun({Sock, Server}, #{client := C}, {SA, AA}) ->
            {_, TActs} = webrtc_turn_client:close(Now, C),
            Close = [{close_stream, Sock} || element(1, Sock) =:= stream],
            {SA, AA ++ [{send, Sock, Server, B} || {send, B} <- TActs] ++ Close}
        end,
        {S#ice{turn = #{}}, []},
        S#ice.turn
    ),
    {S1#ice{streams = #{}}, Acts ++ [{close_stream, Ref} || Ref <- maps:keys(S#ice.streams)]}.

%% @doc The stream connection of a relay job is up: allocate over it.
%% There is no retransmission on a reliable transport; a transaction
%% fails after 39.5 s (RFC 8489 §6.2.2).
-spec stream_up({stream, pos_integer()}, integer(), #ice{}) -> {#ice{}, [term()]}.
stream_up(Ref, Now, S) ->
    case maps:take(Ref, S#ice.streams) of
        {{HostId, {relay, _, #{address := Server}, _} = Job, Opts}, Streams} ->
            allocate({Ref, Server}, HostId, Job, Opts#{rc => 1, rm => 79, rto => 500}, Now, S#ice{streams = Streams});
        error ->
            {S, [{close_stream, Ref}]}
    end.

%% @doc The stream connection failed or closed: the job fails, or the
%% allocation over it is lost.
-spec stream_down({stream, pos_integer()}, term(), integer(), #ice{}) -> {#ice{}, [term()]}.
stream_down(Ref, Reason, Now, S) ->
    case maps:take(Ref, S#ice.streams) of
        {{HostId, {relay, _, #{address := Server} = Cfg, Idx} = Job, _}, Streams} ->
            S1 = S#ice{streams = Streams, gather_pending = lists:delete(Job, S#ice.gather_pending)},
            case webrtc_ice_gather:fallback(Server, S) of
                {ok, Next} ->
                    %% The connection to this address failed: the next one
                    %% of the URI (RFC 5928 §3).
                    {S1#ice{gather_queue = S1#ice.gather_queue ++ [{relay, HostId, Cfg#{address => Next}, Idx}]},
                     [{event, {turn_error, Server, {stream, Reason}}}]};
                none ->
                    {S2, A} = webrtc_ice_gather:maybe_complete(S1),
                    {S2, A ++ [{event, {turn_error, Server, {stream, Reason}}}, {event, {server_unreachable, Server}}]}
            end;
        error ->
            case [K || {R, _} = K <- maps:keys(S#ice.turn), R =:= Ref] of
                [{_, Server} = Key] ->
                    {S1, A, _} = drop_relay(Key, [{event, {turn_error, Server, {allocation_lost, {stream, Reason}}}}], Now, S),
                    {S1, A};
                [] ->
                    {S, []}
            end
    end.
