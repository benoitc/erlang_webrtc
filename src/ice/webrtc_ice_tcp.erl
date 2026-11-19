%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @private
%% @doc ICE-TCP (RFC 6544) of the ICE agent: TCP host candidates and the
%% connections of TCP candidate pairs.
%%
%% The owner gives TCP listening addresses (`listeners/3'). Each one
%% gives a passive host candidate (the listener) and an active host
%% candidate (port 9, RFC 6544 §4.5), both below the UDP host candidates
%% in priority (§4.2). An active candidate pairs with a remote passive
%% one and a passive with a remote active one (§6.2); simultaneous-open
%% is not gathered.
%%
%% A TCP pair has no path until it has a connection. For an active pair
%% the agent asks the owner to connect (`{connect, {tcp, N}, Params}');
%% the check goes out once `up/3' reports the connection. A passive pair
%% waits for the peer to connect (`accepted/5'); its checks arrive on
%% that connection and are answered there. Packets on a connection are
%% framed with a 16-bit length (RFC 4571) by the owner. Checks are not
%% retransmitted over TCP (RFC 6544 §7.1, RFC 8489 §6.2.2).
-module(webrtc_ice_tcp).

-include("webrtc_ice_int.hrl").

-export([
    listeners/3,
    pair_via/3,
    connect/3,
    up/3,
    accepted/5,
    down/4,
    base_of/2,
    close/1
]).

%% Inbound connections kept at once; more are refused.
-define(MAX_CONNS, 32).

%% @doc Add the TCP host candidates of `[{ListenRef, {IP, Port}}]'.
-spec listeners([{term(), webrtc_ice_candidate:address()}], integer(), #ice{}) -> {#ice{}, [term()]}.
listeners(Specs, _Now, S0) ->
    Indexed = lists:zip(lists:seq(0, length(Specs) - 1), Specs),
    lists:foldl(
        fun({Rank, {Listen, {IP, Port}}}, {SA, AA}) ->
            Passive = cand(passive, IP, Port, {tcp_listen, Listen}, Rank),
            Active = cand(active, IP, 9, {tcp_active, IP}, Rank),
            {SB, AB} = add(Passive, SA),
            {SC, AC} = add(Active, SB),
            {SC, AA ++ AB ++ AC}
        end,
        {S0, []},
        Indexed
    ).

cand(TcpType, IP, Port, Sock, Rank) ->
    #ice_cand{
        foundation = webrtc_ice_candidate:foundation(host, IP, undefined, tcp),
        component = 1,
        transport = tcp,
        tcptype = TcpType,
        priority = webrtc_ice_candidate:priority(host, webrtc_ice_candidate:tcp_local_preference(TcpType, Rank), 1),
        address = IP,
        port = Port,
        type = host,
        base = {IP, Port},
        socket = Sock
    }.

add(Cand, S) ->
    {Id, S1} = webrtc_ice_gather:add_local(Cand, S#ice.next_id, S),
    {webrtc_ice_checklist:pair_new_local(Id, S1), [{event, {local_candidate, Cand}}]}.

%% @doc The path of a pair: unchanged for UDP and relayed pairs, the
%% open connection of a TCP pair, `none' while it has none.
-spec pair_via(#pair{}, #ice_cand{}, #ice{}) -> term().
pair_via(#pair{local = LId} = P, #ice_cand{} = R, S) ->
    case webrtc_ice_checklist:pair_local(P, S) of
        #ice_cand{transport = tcp} ->
            To = webrtc_ice_candidate:transport_address(R),
            case [Ref || Ref := #{local := Lo, remote := Re, state := up} <- S#ice.tcp, Lo =:= LId, Re =:= To] of
                [Ref | _] -> Ref;
                [] -> none
            end;
        #ice_cand{} = L ->
            webrtc_ice_gather:via(L, S);
        undefined ->
            none
    end.

%% @doc A check is due on a TCP pair without a connection: an active
%% pair asks the owner to connect, a passive one cannot send and fails
%% until the peer connects. Returns the actions and whether the pair now
%% waits for its connection.
-spec connect({pos_integer(), pos_integer()}, integer(), #ice{}) -> {#ice{}, [term()]}.
connect(Id, _Now, S) ->
    #pair{local = LId, remote = RId} = P = webrtc_ice_checklist:pair(Id, S),
    L = webrtc_ice_checklist:local(LId, S),
    R = webrtc_ice_checklist:remote(RId, S),
    To = webrtc_ice_candidate:transport_address(R),
    Pending = [Ref || Ref := #{local := Lo, remote := Re} <- S#ice.tcp, Lo =:= LId, Re =:= To],
    case {L#ice_cand.tcptype, Pending} of
        {active, []} ->
            Ref = {tcp, S#ice.next_tcp},
            Conn = #{local => LId, remote => To, state => connecting, pair => Id},
            S1 = webrtc_ice_checklist:put_pair(P#pair{state = in_progress, txid = undefined}, S),
            {S1#ice{tcp = (S#ice.tcp)#{Ref => Conn}, next_tcp = S#ice.next_tcp + 1},
             [{connect, Ref, #{transport => ice_tcp, local => L#ice_cand.address, remote => To}}]};
        {active, _} ->
            %% Already connecting: the check goes out when it is up.
            {webrtc_ice_checklist:put_pair(P#pair{state = in_progress, txid = undefined}, S), []};
        _ ->
            {webrtc_ice_checklist:put_pair(P#pair{state = failed, txid = undefined}, S), []}
    end.

%% @doc An outgoing connection is up: its pair is checked now.
-spec up({tcp, term()}, integer(), #ice{}) -> {#ice{}, [term()]}.
up(Ref, _Now, S) ->
    case maps:find(Ref, S#ice.tcp) of
        {ok, #{pair := Id} = C} ->
            S1 = S#ice{tcp = (S#ice.tcp)#{Ref := C#{state := up}}},
            case webrtc_ice_checklist:pair(Id, S1) of
                #pair{} = P ->
                    S2 = webrtc_ice_checklist:put_pair(P#pair{state = waiting}, S1),
                    {webrtc_ice_checklist:trigger(Id, S2), []};
                undefined ->
                    {S1, []}
            end;
        error ->
            {S, [{close_stream, Ref}]}
    end.

%% @doc The peer connected to the listener `Listen' from `Peer'.
-spec accepted({tcp, term()}, term(), webrtc_ice_candidate:address(), integer(), #ice{}) ->
    {#ice{}, [term()]}.
accepted(Ref, Listen, Peer, _Now, S) ->
    Passive = [Id || Id := #ice_cand{socket = {tcp_listen, L}} <- S#ice.local, L =:= Listen],
    Inbound = [x || _ := #{pair := undefined} <- S#ice.tcp],
    case Passive of
        [LId | _] when length(Inbound) < ?MAX_CONNS, S#ice.state =/= closed ->
            {S#ice{tcp = (S#ice.tcp)#{Ref => #{local => LId, remote => Peer, state => up, pair => undefined}}}, []};
        _ ->
            {S, [{close_stream, Ref}]}
    end.

%% @doc A connection failed or closed: its pair has no path any more; a
%% pair still waiting for it fails.
-spec down({tcp, term()}, term(), integer(), #ice{}) -> {#ice{}, [term()]}.
down(Ref, _Reason, _Now, S) ->
    case maps:take(Ref, S#ice.tcp) of
        {#{pair := Id, state := connecting}, Conns} when Id =/= undefined ->
            S1 = S#ice{tcp = Conns},
            case webrtc_ice_checklist:pair(Id, S1) of
                #pair{} = P -> {webrtc_ice_checklist:put_pair(P#pair{state = failed}, S1), []};
                undefined -> {S1, []}
            end;
        {_, Conns} ->
            {S#ice{tcp = Conns}, []};
        error ->
            {S, []}
    end.

%% @doc The local candidate a connection belongs to.
-spec base_of({tcp, term()}, #ice{}) -> {ok, pos_integer()} | error.
base_of(Ref, #ice{tcp = Conns}) ->
    case Conns of
        #{Ref := #{local := LId}} -> {ok, LId};
        #{} -> error
    end.

%% @doc Close every connection.
-spec close(#ice{}) -> {#ice{}, [term()]}.
close(S) ->
    {S#ice{tcp = #{}}, [{close_stream, Ref} || Ref <- maps:keys(S#ice.tcp)]}.
