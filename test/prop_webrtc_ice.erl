%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% PropEr properties for ICE: candidate and pair priorities, the
%% candidate attribute codec, check ordering, and convergence of two
%% agents over lossy networks.
-module(prop_webrtc_ice).
-include_lib("proper/include/proper.hrl").
-include("webrtc_ice.hrl").

-define(C, webrtc_ice_candidate).
-define(MAXP, 16#7FFFFFFF).

%%--------------------------------------------------------------------
%% Priorities
%%--------------------------------------------------------------------

prio() -> integer(1, ?MAXP).

%% Both agents compute the same priority for a pair (RFC 8445 §6.1.2.3).
prop_pair_priority_agrees() ->
    ?FORALL({L, R}, {prio(), prio()},
            ?C:pair_priority(L, R, controlling) =:= ?C:pair_priority(R, L, controlled)).

%% The pair priority is ordered by the minimum candidate priority
%% first, then by the maximum, then by which side is larger, and it fits
%% in 64 bits.
prop_pair_priority_order() ->
    ?FORALL({G1, D1, G2, D2}, {prio(), prio(), prio(), prio()},
            begin
                P1 = ?C:pair_priority(G1, D1),
                P2 = ?C:pair_priority(G2, D2),
                K1 = {min(G1, D1), max(G1, D1), G1 > D1},
                K2 = {min(G2, D2), max(G2, D2), G2 > D2},
                P1 < (1 bsl 64) andalso
                    compare(P1, P2) =:= compare(K1, K2)
            end).

compare(A, B) when A < B -> lt;
compare(A, B) when A > B -> gt;
compare(_, _) -> eq.

%% The type preference dominates local preference and component.
prop_type_preference_dominates() ->
    Types = [host, prflx, srflx, relay],
    ?FORALL({T1, T2, L1, L2, C1, C2},
            {elements(Types), elements(Types), integer(0, 65535), integer(0, 65535),
             integer(1, 256), integer(1, 256)},
            ?IMPLIES(?C:type_preference(T1) > ?C:type_preference(T2),
                     ?C:priority(T1, L1, C1) > ?C:priority(T2, L2, C2))).

%% Local preferences are unique and every address gets one.
prop_local_preferences_unique() ->
    ?FORALL(IPs, non_empty(list(ip())),
            begin
                U = lists:usort(IPs),
                Prefs = ?C:local_preferences(U),
                Values = [P || {_, P} <- Prefs],
                lists:sort([IP || {IP, _} <- Prefs]) =:= U andalso
                    length(lists:usort(Values)) =:= length(Values)
            end).

ip() ->
    oneof([{10, 0, byte(), byte()}, {16#2001, 16#db8, 0, 0, 0, 0, byte(), byte()}]).

%%--------------------------------------------------------------------
%% Candidate attribute
%%--------------------------------------------------------------------

cand() ->
    ?LET({F, Comp, Prio, IP, Port, Type, Rel, Ext},
         {non_empty(list(elements("abcXYZ019+/"))), integer(1, 256), prio(), ip(), integer(0, 65535),
          elements([host, srflx, prflx, relay]), oneof([none, {ip(), integer(0, 65535)}]),
          list({elements([<<"generation">>, <<"network-id">>, <<"ufrag">>]), elements([<<"0">>, <<"abcd">>])})},
         begin
             C = #ice_cand{foundation = list_to_binary(lists:sublist(F, 32)), component = Comp, priority = Prio,
                           address = IP, port = Port, type = Type, extensions = Ext},
             case Rel of
                 none -> C;
                 {RA, RP} -> C#ice_cand{related_address = RA, related_port = RP}
             end
         end).

prop_sdp_roundtrip() ->
    ?FORALL(C, cand(), ?C:from_sdp(?C:to_sdp(C)) =:= {ok, C}).

%%--------------------------------------------------------------------
%% Check ordering
%%--------------------------------------------------------------------

%% With every pair Waiting, checks leave in decreasing pair priority.
prop_checks_by_priority() ->
    ?FORALL(Prios, ?SUCHTHAT(L, non_empty(list(prio())), length(lists:usort(L)) =:= length(L)),
            begin
                A0 = webrtc_ice_agent:new(#{role => controlling, seed => {1, 2, 3}}),
                {A1, _} = webrtc_ice_agent:gather([{s, {{10, 0, 0, 1}, 5000}}], 0, A0),
                Remotes = [#ice_cand{foundation = integer_to_binary(I), priority = P, address = {10, 1, 0, I},
                                     port = 6000, type = host}
                           || {I, P} <- lists:zip(lists:seq(1, length(Prios)), Prios)],
                A2 = lists:foldl(fun(C, A) -> element(1, webrtc_ice_agent:add_remote_candidate(C, 0, A)) end,
                                 A1, Remotes),
                {A3, _} = webrtc_ice_agent:set_remote_credentials(<<"abcd">>, <<"0123456789012345678901">>, 0, A2),
                Sent = first_sends(A3, length(Prios)),
                Local = hd(webrtc_ice_agent:local_candidates(A3)),
                Expected = [IP || #ice_cand{address = IP} <- lists:sort(
                    fun(X, Y) ->
                        ?C:pair_priority(Local#ice_cand.priority, X#ice_cand.priority) >=
                            ?C:pair_priority(Local#ice_cand.priority, Y#ice_cand.priority)
                    end,
                    Remotes)],
                Sent =:= Expected
            end).

first_sends(A, N) ->
    first_sends(A, N, []).

first_sends(_A, 0, Acc) ->
    lists:reverse(Acc);
first_sends(A, N, Acc) ->
    T = webrtc_ice_agent:next_timeout(A),
    {A1, Acts} = webrtc_ice_agent:handle_timeout(T, A),
    New = [IP || {send, _, {IP, _}, _} <- Acts],
    first_sends(A1, N - length(New), lists:reverse(New) ++ Acc).

%%--------------------------------------------------------------------
%% Convergence under loss
%%--------------------------------------------------------------------

%% Two agents conclude ICE on the same pair for any loss rate below 50%
%% applied to every packet. A transaction fails only when all its
%% requests or responses are lost; to make that event negligible
%% (0.74^40 at 49% loss) the agents use Rc = 40 with the retransmission
%% interval capped at one second, as RFC 8489 §6.2.1 allows Rc to be
%% configured. Consent freshness is a separate liveness check whose
%% single-shot requests can legitimately expire under such loss, so
%% the property is about ICE concluding, not about consent.
prop_lossy_network_connects() ->
    ?FORALL({Loss, Seed, Delay}, {float(0.0, 0.49), integer(1, 1000000), integer(1, 80)},
            begin
                Opts = #{rc => 40, max_rto => 1000, max_check_rto => 1000},
                N0 = webrtc_ice_net:new(#{loss => Loss, seed => Seed, delay => Delay}),
                N1 = webrtc_ice_net:add_agent(N0, a, Opts#{role => controlling, seed => {Seed, 1, 1}},
                                              [{sa, {{10, 0, 0, 1}, 5000}}], none),
                N2 = webrtc_ice_net:add_agent(N1, b, Opts#{role => controlled, seed => {Seed, 2, 2}},
                                              [{sb, {{10, 0, 1, 1}, 6000}}], none),
                N3 = webrtc_ice_net:gather(webrtc_ice_net:gather(webrtc_ice_net:link(N2, {a, b}, true), a), b),
                {Res, N4} = webrtc_ice_net:run_until(N3, fun concluded/1, 600000),
                ?WHENFAIL(io:format("loss ~p seed ~p: ~p at ~p~n", [Loss, Seed, Res, webrtc_ice_net:now(N4)]),
                          Res =:= ok andalso agree(N4))
            end).

concluded(N) ->
    lists:all(fun(X) -> webrtc_ice_agent:selected_pair(webrtc_ice_net:agent(N, X)) =/= undefined end, [a, b]).

agree(N) ->
    {AL, AR} = webrtc_ice_agent:selected_pair(webrtc_ice_net:agent(N, a)),
    {BL, BR} = webrtc_ice_agent:selected_pair(webrtc_ice_net:agent(N, b)),
    ?C:transport_address(AL) =:= ?C:transport_address(BR) andalso
        ?C:transport_address(AR) =:= ?C:transport_address(BL).
