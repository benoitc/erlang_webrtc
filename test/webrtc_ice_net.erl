%% @doc Test-only in-memory network for sans-IO ICE engines.
%%
%% It routes the `{send, Socket, To, Bin}' actions of ICE agents between
%% agents, NATs, a fake STUN server and a fake TURN server, with a fake
%% clock, seeded loss and delay. Everything is deterministic for a given
%% seed.
%%
%% NAT types: `full_cone' (endpoint independent mapping and filtering),
%% `restricted' (address dependent filtering), `port_restricted'
%% (address and port dependent filtering) and `symmetric' (address and
%% port dependent mapping and filtering).
-module(webrtc_ice_net).

-include("webrtc_ice.hrl").
-include("webrtc_stun.hrl").

-export([
    new/1,
    add_nat/4,
    add_agent/5,
    add_stun_server/2,
    add_turn_server/3,
    link/3,
    call/3,
    gather/2,
    signal/3,
    run/2,
    run_until/3,
    now/1,
    agent/2,
    events/2,
    app_data/2,
    dropped_app/2,
    set_filter/2,
    set_loss/2,
    server/2,
    send_data/3,
    stats/1
]).

-define(MAX_STEPS, 2000000).

new(Opts) ->
    #{
        now => maps:get(start, Opts, 1000),
        rand => rand:seed_s(exsss, maps:get(seed, Opts, 1)),
        loss => maps:get(loss, Opts, 0.0),
        delay => maps:get(delay, Opts, 10),
        jitter => maps:get(jitter, Opts, 0),
        signal_delay => maps:get(signal_delay, Opts, 20),
        queue => [],
        seq => 0,
        agents => #{},
        nats => #{},
        servers => #{},
        filter => fun(_Net, _Src, _Dst, _Bin) -> pass end,
        sent => 0,
        lost => 0
    }.

set_filter(Net, F) -> Net#{filter => F}.
set_loss(Net, L) -> Net#{loss => L}.
now(#{now := T}) -> T.
stats(Net) -> maps:with([sent, lost, now], Net).

add_nat(Net = #{nats := N}, Name, Type, PublicIP) ->
    Net#{nats => N#{Name => #{type => Type, ip => PublicIP, next => 40000, map => #{}, rev => #{}, seen => #{}}}}.

%% Sockets: [{SockRef, {IP, Port}}]. Nat: NAT name or none.
add_agent(Net = #{agents := A}, Name, Opts, Socks, Nat) ->
    Agent = webrtc_ice_agent:new(Opts),
    Entry = #{agent => Agent, socks => maps:from_list(Socks), nat => Nat, peer => undefined,
              events => [], app => [], dropped => [], auto => true},
    Net#{agents => A#{Name => Entry}}.

add_stun_server(Net = #{servers := S}, {IP, _} = Addr) ->
    Net#{servers => S#{IP => {stun, Addr, undefined}}}.

add_turn_server(Net = #{servers := S}, {IP, _} = Addr, Opts) ->
    Net#{servers => S#{IP => {turn, Addr, webrtc_test_turn_server:new(Opts#{address => Addr})}}}.

server(#{servers := S}, IP) ->
    {_, _, St} = maps:get(IP, S),
    St.

%% Peers exchange credentials now and trickle candidates (and
%% end-of-candidates) through signaling when `Auto' is true.
link(Net, {A, B}, Auto) ->
    Net1 = set_peer(set_peer(Net, A, B, Auto), B, A, Auto),
    {UA, PA} = webrtc_ice_agent:local_credentials(agent(Net1, A)),
    {UB, PB} = webrtc_ice_agent:local_credentials(agent(Net1, B)),
    Now = now(Net1),
    Net2 = call(Net1, A, fun(Ag) -> webrtc_ice_agent:set_remote_credentials(UB, PB, Now, Ag) end),
    call(Net2, B, fun(Ag) -> webrtc_ice_agent:set_remote_credentials(UA, PA, Now, Ag) end).

set_peer(Net = #{agents := As}, Name, Peer, Auto) ->
    E = maps:get(Name, As),
    Net#{agents => As#{Name => E#{peer => Peer, auto => Auto}}}.

gather(Net, Name) ->
    #{socks := Socks} = maps:get(Name, maps:get(agents, Net)),
    Now = now(Net),
    call(Net, Name, fun(A) -> webrtc_ice_agent:gather(lists:sort(maps:to_list(Socks)), Now, A) end).

%% Deliver a signaling message to `Name' after the signaling delay.
signal(Net, Name, Fun) ->
    enqueue(maps:get(signal_delay, Net), {call, Name, Fun}, Net).

agent(#{agents := A}, Name) -> maps:get(agent, maps:get(Name, A)).
events(#{agents := A}, Name) -> lists:reverse(maps:get(events, maps:get(Name, A))).
app_data(#{agents := A}, Name) -> lists:reverse(maps:get(app, maps:get(Name, A))).
dropped_app(#{agents := A}, Name) -> lists:reverse(maps:get(dropped, maps:get(Name, A))).

%% Apply `Fun(Agent) -> {Agent, Actions}' and execute the actions.
call(Net = #{agents := As}, Name, Fun) ->
    E = #{agent := A} = maps:get(Name, As),
    case Fun(A) of
        {A1, Acts} when is_list(Acts) ->
            actions(Name, Acts, Net#{agents => As#{Name => E#{agent => A1}}});
        {ok, A1, Acts} ->
            actions(Name, Acts, Net#{agents => As#{Name => E#{agent => A1}}});
        {error, _} ->
            Net
    end.

send_data(Net, Name, Data) ->
    Now = now(Net),
    call(Net, Name, fun(A) -> webrtc_ice_agent:send(Data, Now, A) end).

%%--------------------------------------------------------------------
%% Actions
%%--------------------------------------------------------------------

actions(Name, Acts, Net) ->
    lists:foldl(fun(A, N) -> action(Name, A, N) end, Net, Acts).

action(Name, {send, Sock, To, Bin}, Net = #{agents := As}) ->
    #{socks := Socks, nat := Nat} = maps:get(Name, As),
    case maps:find(Sock, Socks) of
        {ok, Local} ->
            {Src, Net1} = outbound(Nat, Local, To, Net),
            transmit(Src, To, Bin, Net1);
        error ->
            Net
    end;
action(Name, {event, Ev}, Net = #{agents := As, now := Now}) ->
    E = #{events := Evs} = maps:get(Name, As),
    Net1 = Net#{agents => As#{Name => E#{events => [{Now, Ev} | Evs]}}},
    auto_signal(Name, E, Ev, Net1).

auto_signal(_Name, #{auto := false}, _Ev, Net) ->
    Net;
auto_signal(_Name, #{peer := undefined}, _Ev, Net) ->
    Net;
auto_signal(_Name, #{peer := Peer}, {local_candidate, C}, Net) ->
    signal(Net, Peer, fun(A, Now) -> webrtc_ice_agent:add_remote_candidate(C, Now, A) end);
auto_signal(_Name, #{peer := Peer}, {gathering_state, complete}, Net) ->
    signal(Net, Peer, fun(A, Now) -> webrtc_ice_agent:end_of_candidates(Now, A) end);
auto_signal(Name, _E, {data, Via, Peer, Data}, Net = #{agents := As}) ->
    E = #{app := App} = maps:get(Name, As),
    Net#{agents => As#{Name => E#{app => [{Via, Peer, Data} | App]}}};
auto_signal(_, _, _, Net) ->
    Net.

transmit(Src, Dst, Bin, Net = #{filter := F, loss := Loss, rand := R0, sent := Sent, lost := Lost}) ->
    {X, R1} = rand:uniform_s(R0),
    Net1 = Net#{rand => R1, sent => Sent + 1},
    case F(Net1, Src, Dst, Bin) of
        drop ->
            Net1#{lost => Lost + 1};
        pass when X < Loss ->
            Net1#{lost => Lost + 1};
        pass ->
            #{delay := D, jitter := J} = Net1,
            {Jit, R2} =
                case J of
                    0 -> {0, R1};
                    _ -> rand:uniform_s(J + 1, R1)
                end,
            enqueue(D + max(0, Jit - 1), {packet, Src, Dst, Bin}, Net1#{rand => R2})
    end.

enqueue(Delay, Item, Net = #{queue := Q, seq := Seq, now := Now}) ->
    Net#{queue => insert({Now + Delay, Seq, Item}, Q), seq => Seq + 1}.

insert(X, []) -> [X];
insert(X, [H | T]) when X < H -> [X, H | T];
insert(X, [H | T]) -> [H | insert(X, T)].

%%--------------------------------------------------------------------
%% NAT
%%--------------------------------------------------------------------

outbound(none, Local, _To, Net) ->
    {Local, Net};
outbound(Name, Local, To, Net = #{nats := Nats}) ->
    #{type := Type, ip := IP, next := Next, map := Map, rev := Rev, seen := Seen} = N = maps:get(Name, Nats),
    Key =
        case Type of
            symmetric -> {Local, To};
            _ -> Local
        end,
    {Port, N1} =
        case maps:find(Key, Map) of
            {ok, P} -> {P, N};
            error -> {Next, N#{next => Next + 1, map => Map#{Key => Next}, rev => Rev#{Next => Local}}}
        end,
    Seen1 = maps:update_with(Port, fun(L) -> lists:usort([To | L]) end, [To], maps:get(seen, N1)),
    _ = Seen,
    {{IP, Port}, Net#{nats => Nats#{Name => N1#{seen => Seen1}}}}.

inbound({DIP, DPort}, {SIP, _} = Src, #{nats := Nats}) ->
    case [N || _ := #{ip := IP} = N <- Nats, IP =:= DIP] of
        [#{type := Type, rev := Rev, seen := Seen}] ->
            case maps:find(DPort, Rev) of
                {ok, Local} ->
                    Peers = maps:get(DPort, Seen, []),
                    Allowed =
                        case Type of
                            full_cone -> true;
                            restricted -> lists:keymember(SIP, 1, Peers);
                            _ -> lists:member(Src, Peers)
                        end,
                    case Allowed of
                        true -> {nat, Local};
                        false -> drop
                    end;
                error ->
                    drop
            end;
        [] ->
            {direct, {DIP, DPort}}
    end.

%%--------------------------------------------------------------------
%% Delivery
%%--------------------------------------------------------------------

deliver(Src, {DIP, _} = Dst, Bin, Net = #{servers := Servers}) ->
    case maps:find(DIP, Servers) of
        {ok, {stun, Addr, _}} ->
            stun_server(Addr, Src, Bin, Net);
        {ok, {turn, Addr, St}} ->
            {St1, Out} = webrtc_test_turn_server:handle(Src, Dst, Bin, now(Net), St),
            server_out(Out, Net#{servers => Servers#{DIP => {turn, Addr, St1}}});
        error ->
            case inbound(Dst, Src, Net) of
                {Kind, Local} -> to_agent(Kind, Local, Src, Bin, Net);
                drop -> Net
            end
    end.

server_out(Out, Net) ->
    lists:foldl(fun({send, From, To, B}, N) -> transmit(From, To, B, N) end, Net, Out).

stun_server(Addr, Src, Bin, Net) ->
    case webrtc_stun:decode(Bin) of
        {ok, #stun{class = request, method = binding} = Req} ->
            Resp = webrtc_stun:encode(webrtc_stun:success(Req, [{xor_mapped_address, Src}]),
                                      #{fingerprint => true}),
            transmit(Addr, Src, Resp, Net);
        _ ->
            Net
    end.

%% Hosts behind a NAT are only reachable through it.
to_agent(Kind, Local, Src, Bin, Net = #{agents := As, now := Now}) ->
    Found = [{Name, Sock} || Name := #{socks := Socks, nat := Nat} <- As, Sock := L <- Socks, L =:= Local,
                             (Kind =:= nat) xor (Nat =:= none)],
    case Found of
        [{Name, Sock}] ->
            <<B, _/binary>> = <<Bin/binary, 0>>,
            case B < 4 orelse (B >= 64 andalso B =< 79) of
                true ->
                    call(Net, Name, fun(A) -> webrtc_ice_agent:handle_packet(Sock, Src, Bin, Now, A) end);
                false ->
                    E = maps:get(Name, As),
                    Key = case webrtc_ice_agent:is_valid_remote(Sock, Src, maps:get(agent, E)) of
                        true -> app;
                        false -> dropped
                    end,
                    Net#{agents => As#{Name => E#{Key => [{Sock, Src, Bin} | maps:get(Key, E)]}}}
            end;
        [] ->
            Net
    end.

%%--------------------------------------------------------------------
%% Event loop
%%--------------------------------------------------------------------

run(Net, Until) ->
    run_until(Net, fun(_) -> false end, Until).

%% Run until `Pred(Net)' holds or the clock reaches `Until'. Returns
%% {ok | timeout, Net}.
run_until(Net, Pred, Until) ->
    loop(Net, Pred, Until, 0).

loop(_Net, _Pred, _Until, Steps) when Steps > ?MAX_STEPS ->
    error(too_many_steps);
loop(Net, Pred, Until, Steps) ->
    case Pred(Net) of
        true ->
            {ok, Net};
        false ->
            case next_event(Net) of
                infinity ->
                    {timeout, Net#{now => max(now(Net), Until)}};
                T when T > Until ->
                    {timeout, Net#{now => max(now(Net), Until)}};
                T ->
                    loop(step(Net#{now => max(now(Net), T)}), Pred, Until, Steps + 1)
            end
    end.

next_event(Net = #{queue := Q, agents := As, servers := Ss}) ->
    QT = case Q of
        [{T, _, _} | _] -> T;
        [] -> infinity
    end,
    AT = [webrtc_ice_agent:next_timeout(A) || _ := #{agent := A} <- As],
    ST = [webrtc_test_turn_server:next_timeout(St) || _ := {turn, _, St} <- Ss],
    _ = Net,
    lists:min([QT | AT ++ ST]).

step(Net = #{queue := [{T, _, Item} | Rest], now := Now}) when T =< Now ->
    Net1 = Net#{queue => Rest},
    case Item of
        {packet, Src, Dst, Bin} ->
            deliver(Src, Dst, Bin, Net1);
        {call, Name, Fun} ->
            call(Net1, Name, fun(A) -> Fun(A, Now) end)
    end;
step(Net = #{now := Now, agents := As, servers := Ss}) ->
    Net1 = maps:fold(
        fun(Name, #{agent := A}, N) ->
            case webrtc_ice_agent:next_timeout(A) =< Now of
                true -> call(N, Name, fun(Ag) -> webrtc_ice_agent:handle_timeout(Now, Ag) end);
                false -> N
            end
        end,
        Net,
        As
    ),
    maps:fold(
        fun(IP, {turn, Addr, St}, N = #{servers := S2}) ->
                case webrtc_test_turn_server:next_timeout(St) =< Now of
                    true ->
                        {St1, Out} = webrtc_test_turn_server:handle_timeout(Now, St),
                        server_out(Out, N#{servers => S2#{IP => {turn, Addr, St1}}});
                    false ->
                        N
                end;
           (_, _, N) ->
                N
        end,
        Net1,
        Ss
    ).
