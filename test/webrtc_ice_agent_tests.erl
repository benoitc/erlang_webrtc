%% Unit tests of the ICE agent driven directly, packet by packet: STUN
%% server behavior for checks (RFC 8445 §7.3, RFC 8489 §6.3), response
%% processing (§7.2.5), role conflicts, early checks, lite behavior,
%% scheduling and robustness against malformed input.
-module(webrtc_ice_agent_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_ice.hrl").
-include("webrtc_stun.hrl").

-define(AG, webrtc_ice_agent).
-define(U, <<"locl">>).
-define(P, <<"localpassword0123456789">>).
-define(RU, <<"remo">>).
-define(RP, <<"remotepassword012345678">>).
-define(L, {{10, 0, 0, 1}, 5000}).
-define(R, {{10, 0, 0, 2}, 6000}).

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

agent(Opts) ->
    A0 = ?AG:new(maps:merge(#{ufrag => ?U, pwd => ?P, role => controlled, seed => {1, 2, 3}}, Opts)),
    {A1, _} = ?AG:gather([{s, ?L}], 0, A0),
    A1.

with_remote(A) ->
    {A1, _} = ?AG:set_remote_credentials(?RU, ?RP, 0, A),
    A1.

check_attrs() ->
    [{username, <<?U/binary, ":", ?RU/binary>>}, {priority, 1862270975}, {ice_controlling, 5}].

encode(Attrs, Key) ->
    encode(Attrs, Key, true).

encode(Attrs, Key, FP) ->
    Opts = maps:merge(#{fingerprint => FP}, case Key of undefined -> #{}; _ -> #{integrity => {sha1, Key}} end),
    webrtc_stun:encode(webrtc_stun:request(binding, Attrs), Opts).

sends(Acts) ->
    [{S, To, element(2, webrtc_stun:decode(B)), B} || {send, S, To, B} <- Acts].

events(Acts) -> [E || {event, E} <- Acts].

%% The single response to a request.
response(Acts, TxId) ->
    [R] = [{M, B} || {_, _, #stun{txid = T, class = C} = M, B} <- sends(Acts), T =:= TxId, C =/= request],
    R.

error_code(#stun{} = M) ->
    {ok, {Code, _}} = webrtc_stun:get(error_code, M),
    Code.

deliver(Bin, A) ->
    deliver(Bin, ?R, 10, A).

deliver(Bin, From, Now, A) ->
    ?AG:handle_packet(s, From, Bin, Now, A).

txid(Bin) ->
    {ok, #stun{txid = T}} = webrtc_stun:decode(Bin),
    T.

%% Run the agent's timers until `Until', collecting actions.
tick(A, Until) ->
    tick(A, Until, []).

tick(A, Until, Acc) ->
    case ?AG:next_timeout(A) of
        T when T =< Until ->
            {A1, Acts} = ?AG:handle_timeout(T, A),
            tick(A1, Until, Acc ++ [{T, X} || X <- Acts]);
        _ ->
            {A, Acc}
    end.

%%--------------------------------------------------------------------
%% Answering checks
%%--------------------------------------------------------------------

valid_check_test() ->
    A = with_remote(agent(#{})),
    Bin = encode(check_attrs(), ?P),
    {A1, Acts} = deliver(Bin, A),
    {Resp, RBin} = response(Acts, txid(Bin)),
    ?assertEqual(success, Resp#stun.class),
    ?assertEqual({ok, ?R}, webrtc_stun:get(xor_mapped_address, Resp)),
    ?assertEqual(ok, webrtc_stun:check_integrity(RBin, ?P)),
    ?assert(lists:keymember(fingerprint, 1, Resp#stun.attrs)),
    %% The source becomes a peer-reflexive remote candidate with the
    %% PRIORITY of the request (RFC 8445 §7.3.1.3).
    [#ice_cand{type = prflx, priority = 1862270975, address = {10, 0, 0, 2}, port = 6000}] =
        ?AG:remote_candidates(A1),
    ?assert(?AG:is_valid_remote(s, ?R, A1)),
    ?assertNot(?AG:is_valid_remote(s, {{10, 0, 0, 3}, 6000}, A1)),
    ?assertNot(?AG:is_valid_remote(other, ?R, A1)),
    %% A triggered check follows on the next Ta tick.
    {_, Later} = tick(A1, 10),
    [{s, ?R, Check, CBin}] = sends([X || {_, X} <- Later]),
    ?assertEqual(request, Check#stun.class),
    ?assertEqual({ok, <<?RU/binary, ":", ?U/binary>>}, webrtc_stun:get(username, Check)),
    ?assertEqual(ok, webrtc_stun:check_integrity(CBin, ?RP)),
    ?assertMatch({ok, _}, webrtc_stun:get(ice_controlled, Check)),
    ?assertEqual(error, webrtc_stun:get(use_candidate, Check)),
    %% PRIORITY uses the peer-reflexive type preference (§7.1.1).
    ?assertEqual({ok, webrtc_ice_candidate:priority(prflx, 65535, 1)}, webrtc_stun:get(priority, Check)).

reject_test_() ->
    A = with_remote(agent(#{})),
    Cases = [
        {"no integrity", encode(check_attrs(), undefined), 400, false},
        {"no username", encode(tl(check_attrs()), ?P), 400, false},
        {"wrong ufrag", encode([{username, <<"zzzz:", ?RU/binary>>} | tl(check_attrs())], ?P), 401, false},
        {"username without colon", encode([{username, ?U} | tl(check_attrs())], ?P), 401, false},
        {"empty remote ufrag", encode([{username, <<?U/binary, ":">>} | tl(check_attrs())], ?P), 401, false},
        {"wrong password", encode(check_attrs(), <<"not the password at all">>), 401, false},
        {"unknown attribute", encode(check_attrs() ++ [{16#0031, <<1>>}], ?P), 420, true},
        {"no priority", encode([hd(check_attrs()), {ice_controlling, 5}], ?P), 400, true},
        {"no role", encode(lists:sublist(check_attrs(), 2), ?P), 400, true},
        {"both roles", encode(check_attrs() ++ [{ice_controlled, 6}], ?P), 400, true}
    ],
    [{Name, fun() ->
         {A1, Acts} = deliver(Bin, A),
         {Resp, RBin} = response(Acts, txid(Bin)),
         ?assertEqual(error, Resp#stun.class),
         ?assertEqual(Code, error_code(Resp)),
         ?assertEqual(Protected, webrtc_stun:has_integrity(Resp)),
         Protected andalso ?assertEqual(ok, webrtc_stun:check_integrity(RBin, ?P)),
         Code =:= 420 andalso ?assertEqual({ok, [16#0031]}, webrtc_stun:get(unknown_attributes, Resp)),
         %% Rejected checks teach nothing.
         ?assertEqual([], ?AG:remote_candidates(A1)),
         ?assertNot(?AG:is_valid_remote(s, ?R, A1))
     end} || {Name, Bin, Code, Protected} <- Cases].

no_fingerprint_dropped_test() ->
    A = with_remote(agent(#{})),
    {A1, Acts} = deliver(encode(check_attrs(), ?P, false), A),
    ?assertEqual([], Acts),
    ?assertEqual([], ?AG:remote_candidates(A1)).

indication_ignored_test() ->
    A = with_remote(agent(#{})),
    Ind = webrtc_stun:encode(webrtc_stun:indication(binding, []), #{fingerprint => true}),
    ?assertMatch({_, []}, deliver(Ind, A)).

%%--------------------------------------------------------------------
%% Role conflicts (RFC 8445 §7.3.1.1)
%%--------------------------------------------------------------------

conflict_check(Role, Attr, Tie) ->
    A = with_remote(agent(#{role => Role, tiebreaker => 100})),
    Bin = encode([{username, <<?U/binary, ":", ?RU/binary>>}, {priority, 1}, {Attr, Tie}], ?P),
    {A1, Acts} = deliver(Bin, A),
    {Resp, _} = response(Acts, txid(Bin)),
    {?AG:role(A1), Resp#stun.class, events(Acts)}.

role_conflict_test_() ->
    [
        %% Controlling, peer also controlling with a smaller tie-breaker: 487.
        ?_assertMatch({controlling, error, []}, conflict_check(controlling, ice_controlling, 50)),
        ?_assertMatch({controlling, error, []}, conflict_check(controlling, ice_controlling, 100)),
        %% Larger tie-breaker: switch to controlled and answer.
        ?_assertMatch({controlled, success, [{role_change, controlled} | _]},
                      conflict_check(controlling, ice_controlling, 200)),
        %% Controlled, peer also controlled with a smaller tie-breaker: switch.
        ?_assertMatch({controlling, success, [{role_change, controlling} | _]},
                      conflict_check(controlled, ice_controlled, 50)),
        ?_assertMatch({controlled, error, []}, conflict_check(controlled, ice_controlled, 200)),
        %% No conflict.
        ?_assertMatch({controlled, success, []}, conflict_check(controlled, ice_controlling, 1)),
        ?_assertMatch({controlling, success, []}, conflict_check(controlling, ice_controlled, 1))
    ].

role_conflict_code_test() ->
    A = with_remote(agent(#{role => controlling, tiebreaker => 100})),
    Bin = encode([{username, <<?U/binary, ":", ?RU/binary>>}, {priority, 1}, {ice_controlling, 1}], ?P),
    {_, Acts} = deliver(Bin, A),
    {Resp, RBin} = response(Acts, txid(Bin)),
    ?assertEqual(487, error_code(Resp)),
    ?assertEqual(ok, webrtc_stun:check_integrity(RBin, ?P)).

%%--------------------------------------------------------------------
%% Our checks and their responses (RFC 8445 §7.2.5)
%%--------------------------------------------------------------------

%% Agent with one remote host candidate; returns the agent after the
%% first check was sent, and that check.
first_check(Opts) ->
    A0 = with_remote(agent(Opts)),
    {A1, _} = ?AG:add_remote_candidate(remote_host(), 0, A0),
    {A2, Acts} = tick(A1, 0),
    [{s, ?R, Check, Bin}] = sends([X || {_, X} <- Acts]),
    {A2, Check, Bin}.

remote_host() ->
    #ice_cand{foundation = <<"9">>, priority = 2130706431, address = {10, 0, 0, 2}, port = 6000, type = host}.

success_for(#stun{} = Check, Mapped, Key) ->
    webrtc_stun:encode(webrtc_stun:success(Check, [{xor_mapped_address, Mapped}]),
                       #{integrity => {sha1, Key}, fingerprint => true}).

check_success_test() ->
    {A, Check, _} = first_check(#{}),
    {A1, Acts} = deliver(success_for(Check, ?L, ?RP), ?R, 30, A),
    ?assertEqual([{connection_state, connected}], events(Acts)),
    #{pairs := [#{state := succeeded, valid := true, rtt := 30}]} = ?AG:stats(A1),
    ?assert(?AG:is_valid_remote(s, ?R, A1)),
    {ok, A2, [{send, s, ?R, <<"data">>}]} = ?AG:send(<<"data">>, 40, A1),
    ?assertEqual(connected, ?AG:connection_state(A2)).

peer_reflexive_local_test() ->
    {A, Check, _} = first_check(#{}),
    Mapped = {{203, 0, 113, 9}, 40000},
    {A1, _} = deliver(success_for(Check, Mapped, ?RP), ?R, 30, A),
    #{pairs := Pairs} = ?AG:stats(A1),
    [#{local := #ice_cand{type = prflx, address = {203, 0, 113, 9}, priority = Prio, base = Base}}] =
        [P || #{valid := true} = P <- Pairs],
    ?assertEqual({ok, Prio}, webrtc_stun:get(priority, Check)),
    ?assertEqual(?L, Base),
    %% Peer-reflexive local candidates are not signaled.
    ?assertEqual([host], [T || #ice_cand{type = T} <- ?AG:local_candidates(A1)]).

spoofed_source_test() ->
    {A, Check, _} = first_check(#{}),
    %% A response from another address than the request destination
    %% fails the pair (RFC 8445 §7.2.5.2.1).
    {A1, _} = deliver(success_for(Check, ?L, ?RP), {{10, 0, 0, 66}, 6000}, 30, A),
    #{pairs := [#{state := failed, valid := false}]} = ?AG:stats(A1),
    ?assertNot(?AG:is_valid_remote(s, ?R, A1)),
    ?assertEqual({error, no_valid_pair}, ?AG:send(<<"x">>, 40, A1)).

forged_response_ignored_test() ->
    {A, Check, _} = first_check(#{}),
    %% Wrong key: discarded, the transaction keeps retransmitting.
    {A1, []} = deliver(success_for(Check, ?L, <<"forged password 1234567">>), ?R, 30, A),
    #{pairs := [#{state := in_progress}]} = ?AG:stats(A1),
    %% No integrity at all.
    Plain = webrtc_stun:encode(webrtc_stun:success(Check, [{xor_mapped_address, ?L}]), #{fingerprint => true}),
    {A2, []} = deliver(Plain, ?R, 30, A1),
    %% No fingerprint.
    NoFp = webrtc_stun:encode(webrtc_stun:success(Check, [{xor_mapped_address, ?L}]), #{integrity => {sha1, ?RP}}),
    {A3, []} = deliver(NoFp, ?R, 30, A2),
    %% Unknown transaction.
    Other = success_for(Check#stun{txid = <<7:96>>}, ?L, ?RP),
    {A4, []} = deliver(Other, ?R, 30, A3),
    {_, Later} = tick(A4, 600),
    ?assertMatch([{500, {send, s, ?R, _}}], Later).

error_response_fails_pair_test() ->
    {A, Check, _} = first_check(#{}),
    Err = webrtc_stun:encode(webrtc_stun:error_response(Check, 400, []),
                             #{integrity => {sha1, ?RP}, fingerprint => true}),
    {A1, _} = deliver(Err, ?R, 30, A),
    #{pairs := [#{state := failed}]} = ?AG:stats(A1).

role_conflict_response_test() ->
    {A, Check, _} = first_check(#{role => controlling}),
    {ok, _} = webrtc_stun:get(ice_controlling, Check),
    Err = webrtc_stun:encode(webrtc_stun:error_response(Check, 487, []),
                             #{integrity => {sha1, ?RP}, fingerprint => true}),
    {A1, Acts} = deliver(Err, ?R, 30, A),
    ?assertEqual(controlled, ?AG:role(A1)),
    ?assertEqual([{role_change, controlled}], events(Acts)),
    %% The pair is checked again with the new role.
    {_, Later} = tick(A1, 100),
    [{s, ?R, Retry, _}] = sends([X || {_, X} <- Later]),
    ?assertMatch({ok, _}, webrtc_stun:get(ice_controlled, Retry)),
    %% A new tie-breaker was chosen.
    ?assertNotEqual(webrtc_stun:get(ice_controlling, Check), webrtc_stun:get(ice_controlled, Retry)).

check_timeout_test() ->
    {A, _Check, _} = first_check(#{eoc_timeout => 60000}),
    {A1, Acts} = tick(A, 39499),
    Sends = [T || {T, {send, _, _, _}} <- Acts],
    ?assertEqual([500, 1500, 3500, 7500, 15500, 31500], Sends),
    #{pairs := [#{state := in_progress}]} = ?AG:stats(A1),
    {A2, _} = tick(A1, 39500),
    #{pairs := [#{state := failed}]} = ?AG:stats(A2),
    %% No end-of-candidates yet: still checking, waiting for more.
    ?assertEqual(checking, ?AG:connection_state(A2)),
    {A3, Acts3} = ?AG:end_of_candidates(39600, A2),
    ?assertEqual([{connection_state, failed}], events(Acts3)),
    ?assertEqual(failed, ?AG:connection_state(A3)).

%%--------------------------------------------------------------------
%% Checks received before the remote credentials (RFC 8445 §7.3)
%%--------------------------------------------------------------------

early_check_test() ->
    A = agent(#{}),
    Bin = encode(check_attrs() ++ [{use_candidate, true}], ?P),
    {A1, Acts} = deliver(Bin, A),
    {Resp, _} = response(Acts, txid(Bin)),
    ?assertEqual(success, Resp#stun.class),
    ?assertEqual([], sends([X || {_, X} <- element(2, tick(A1, 100))])),
    {A2, _} = ?AG:set_remote_credentials(?RU, ?RP, 100, A1),
    {A3, Later} = tick(A2, 100),
    [{s, ?R, Check, _}] = sends([X || {_, X} <- Later]),
    %% The triggered check succeeds and the USE-CANDIDATE received
    %% earlier nominates the pair.
    {A4, Acts4} = deliver(success_for(Check, ?L, ?RP), ?R, 120, A3),
    ?assertMatch([{selected_pair, #ice_cand{type = host}, #ice_cand{type = prflx}} | _], events(Acts4)),
    ?assertEqual(completed, ?AG:connection_state(A4)).

early_check_other_session_test() ->
    A = agent(#{}),
    Bin = encode([{username, <<?U/binary, ":oldu">>} | tl(check_attrs())], ?P),
    {A1, _} = deliver(Bin, A),
    {A2, _} = ?AG:set_remote_credentials(?RU, ?RP, 100, A1),
    ?assertEqual([], ?AG:remote_candidates(A2)).

%%--------------------------------------------------------------------
%% Nomination (controlled side, RFC 8445 §7.3.1.5)
%%--------------------------------------------------------------------

use_candidate_on_succeeded_pair_test() ->
    {A, Check, _} = first_check(#{}),
    {A1, _} = deliver(success_for(Check, ?L, ?RP), ?R, 30, A),
    Bin = encode(check_attrs() ++ [{use_candidate, true}], ?P),
    {A2, Acts} = deliver(Bin, ?R, 40, A1),
    ?assertMatch([{selected_pair, _, _}, {connection_state, completed}], events(Acts)),
    ?assertMatch({#ice_cand{type = host}, #ice_cand{type = host}}, ?AG:selected_pair(A2)).

use_candidate_ignored_when_controlling_test() ->
    A = with_remote(agent(#{role => controlling, tiebreaker => 1 bsl 63})),
    Bin = encode([{username, <<?U/binary, ":", ?RU/binary>>}, {priority, 1}, {ice_controlled, 1},
                  {use_candidate, true}], ?P),
    {A1, _} = deliver(Bin, A),
    {A2, Later} = tick(A1, 10),
    [{_, {send, s, ?R, CBin}}] = Later,
    {ok, C} = webrtc_stun:decode(CBin),
    {A3, Acts} = deliver(success_for(C, ?L, ?RP), ?R, 20, A2),
    ?assertEqual([{connection_state, connected}], events(Acts)),
    ?assertEqual(undefined, ?AG:selected_pair(A3)).

%%--------------------------------------------------------------------
%% Lite (RFC 8445 §2.5, §7.3.2)
%%--------------------------------------------------------------------

lite_test() ->
    A = with_remote(agent(#{lite => true})),
    {A1, Acts} = deliver(encode(check_attrs(), ?P), A),
    [{s, ?R, #stun{class = success}, _}] = sends(Acts),
    %% No triggered check from a lite agent.
    {A2, Later} = tick(A1, 5000),
    ?assertEqual([], [X || {_, {send, _, _, _} = X} <- Later]),
    ?assertEqual(checking, ?AG:connection_state(A2)),
    {A3, Acts3} = deliver(encode(check_attrs() ++ [{use_candidate, true}], ?P), ?R, 5000, A2),
    ?assertMatch([{selected_pair, _, _}, {connection_state, completed}], events(Acts3)),
    ?assertMatch({ok, _, [{send, s, ?R, <<"rtp">>}]}, ?AG:send(<<"rtp">>, 5001, A3)),
    %% A lite agent does not repair role conflicts.
    Ctl = encode([{username, <<?U/binary, ":", ?RU/binary>>}, {priority, 1}, {ice_controlled, 1}], ?P),
    {A4, Acts4} = deliver(Ctl, ?R, 5002, A3),
    ?assertMatch([{s, ?R, #stun{class = success}, _}], sends(Acts4)),
    ?assertEqual(controlled, ?AG:role(A4)).

%%--------------------------------------------------------------------
%% Checklist formation and scheduling
%%--------------------------------------------------------------------

remote(N) ->
    #ice_cand{foundation = integer_to_binary(N), priority = 2130706431 - N, address = {10, 0, 0, 100 + N},
              port = 6000, type = host}.

pacing_test() ->
    A0 = with_remote(agent(#{})),
    A1 = lists:foldl(fun(N, A) -> element(1, ?AG:add_remote_candidate(remote(N), 0, A)) end, A0, lists:seq(1, 3)),
    {_, Acts} = tick(A1, 120),
    %% One check per Ta (50 ms), highest priority first.
    ?assertEqual([{0, {10, 0, 0, 101}}, {50, {10, 0, 0, 102}}, {100, {10, 0, 0, 103}}],
                 [{T, IP} || {T, {send, s, {IP, _}, _}} <- Acts]).

freezing_test() ->
    A0 = agent(#{}),
    {A1, _} = ?AG:gather([{s2, {{10, 0, 0, 7}, 5000}}], 0, A0),
    %% Two remote candidates with the same foundation.
    R1 = remote(1),
    R2 = (remote(2))#ice_cand{foundation = <<"1">>},
    A2 = lists:foldl(fun(C, A) -> element(1, ?AG:add_remote_candidate(C, 0, A)) end, A1, [R1, R2]),
    #{pairs := Before} = ?AG:stats(A2),
    ?assertEqual([frozen, frozen, frozen, frozen], [S || #{state := S} <- Before]),
    A3 = with_remote(A2),
    #{pairs := After} = ?AG:stats(A3),
    %% One Waiting pair per foundation (RFC 8445 §6.1.2.6).
    ?assertEqual(2, length([x || #{state := waiting} <- After])),
    ?assertEqual(2, length([x || #{state := frozen} <- After])).

max_pairs_test() ->
    A0 = with_remote(agent(#{max_pairs => 3})),
    A1 = lists:foldl(fun(N, A) -> element(1, ?AG:add_remote_candidate(remote(N), 0, A)) end, A0, lists:seq(1, 6)),
    #{pairs := Pairs} = ?AG:stats(A1),
    ?assertEqual(3, length(Pairs)),
    %% The highest priority pairs are kept.
    ?assertEqual([{10, 0, 0, 101}, {10, 0, 0, 102}, {10, 0, 0, 103}],
                 [IP || #{remote := #ice_cand{address = IP}} <- Pairs]).

check_rto_test() ->
    A0 = with_remote(agent(#{})),
    A1 = lists:foldl(fun(N, A) -> element(1, ?AG:add_remote_candidate(remote(N), 0, A)) end, A0, lists:seq(1, 12)),
    {_, Acts} = tick(A1, 3000),
    [{0, {send, s, To, _}} | _] = Acts,
    %% RFC 8445 §14.3 gives 50 * 12 * 12 ms, capped at 2500 ms.
    ?assertEqual([2500], [T || {T, {send, s, To2, _}} <- Acts, To2 =:= To, T > 0]).

remote_candidate_family_test() ->
    A0 = with_remote(agent(#{})),
    V6 = (remote(1))#ice_cand{address = {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}},
    {A1, _} = ?AG:add_remote_candidate(V6, 0, A0),
    ?assertMatch(#{pairs := []}, ?AG:stats(A1)),
    {A2, _} = ?AG:add_remote_candidate((remote(2))#ice_cand{component = 2}, 0, A1),
    ?assertEqual(1, length(?AG:remote_candidates(A2))).

%%--------------------------------------------------------------------
%% Gathering
%%--------------------------------------------------------------------

stun_timeout_completes_gathering_test() ->
    A0 = ?AG:new(#{stun_servers => [{{192, 0, 2, 10}, 3478}]}),
    {A1, Acts} = ?AG:gather([{s, ?L}], 0, A0),
    ?assertEqual([{local_candidate, host}, {gathering_state, gathering}],
                 [case E of {local_candidate, C} -> {local_candidate, C#ice_cand.type}; _ -> E end
                  || E <- events(Acts)]),
    {_, Later} = tick(A1, 40000),
    Binding = [T || {T, {send, s, {{192, 0, 2, 10}, 3478}, _}} <- Later],
    ?assertEqual([0, 500, 1500, 3500, 7500, 15500, 31500], Binding),
    ?assertEqual([{39500, {event, {gathering_state, complete}}}],
                 [X || {_, {event, {gathering_state, _}}} = X <- Later]).

stun_srflx_test() ->
    Srv = {{192, 0, 2, 10}, 3478},
    A0 = ?AG:new(#{stun_servers => [Srv]}),
    {A1, _} = ?AG:gather([{s, ?L}], 0, A0),
    {A2, [{0, {send, s, Srv, Req}}]} = tick(A1, 0),
    {ok, M} = webrtc_stun:decode(Req),
    Resp = webrtc_stun:encode(webrtc_stun:success(M, [{xor_mapped_address, {{198, 51, 100, 5}, 7000}}]),
                              #{fingerprint => true}),
    %% A response from elsewhere is ignored.
    {A3, []} = ?AG:handle_packet(s, {{192, 0, 2, 11}, 3478}, Resp, 10, A2),
    {A4, Acts} = ?AG:handle_packet(s, Srv, Resp, 10, A3),
    [{local_candidate, #ice_cand{type = srflx, address = {198, 51, 100, 5}, port = 7000,
                                 related_address = {10, 0, 0, 1}, related_port = 5000}},
     {gathering_state, complete}] = events(Acts),
    ?assertEqual(complete, ?AG:gathering_state(A4)),
    %% A mapped address equal to the host address is redundant.
    A5 = ?AG:new(#{stun_servers => [Srv]}),
    {A6, _} = ?AG:gather([{s, ?L}], 0, A5),
    {A7, [{0, {send, s, Srv, Req2}}]} = tick(A6, 0),
    {ok, M2} = webrtc_stun:decode(Req2),
    Same = webrtc_stun:encode(webrtc_stun:success(M2, [{xor_mapped_address, ?L}]), #{fingerprint => true}),
    {_, Acts2} = ?AG:handle_packet(s, Srv, Same, 10, A7),
    ?assertEqual([{gathering_state, complete}], events(Acts2)).

%%--------------------------------------------------------------------
%% Consent revocation (RFC 7675 §5.2)
%%--------------------------------------------------------------------

forbidden_revokes_consent_test() ->
    {A, Check, _} = first_check(#{}),
    {A1, _} = deliver(success_for(Check, ?L, ?RP), ?R, 30, A),
    {A2, _} = deliver(encode(check_attrs() ++ [{use_candidate, true}], ?P), ?R, 40, A1),
    ?assertEqual(completed, ?AG:connection_state(A2)),
    {A3, Acts} = tick(A2, 7000),
    [{_, {send, s, ?R, CBin}} | _] = [X || {_, {send, _, _, _}} = X <- Acts],
    {ok, Consent} = webrtc_stun:decode(CBin),
    ?assertEqual(error, webrtc_stun:get(use_candidate, Consent)),
    Forbidden = webrtc_stun:encode(webrtc_stun:error_response(Consent, 403, []),
                                   #{integrity => {sha1, ?RP}, fingerprint => true}),
    {A4, Acts4} = deliver(Forbidden, ?R, 7001, A3),
    ?assertMatch([{consent_lost, _, _}, {connection_state, failed}], events(Acts4)),
    ?assertEqual({error, consent_lost}, ?AG:send(<<"x">>, 7002, A4)),
    ?assertNot(?AG:is_valid_remote(s, ?R, A4)).

%%--------------------------------------------------------------------
%% Robustness
%%--------------------------------------------------------------------

flips(Bin) ->
    [begin
         <<Pre:I, Bit:1, Post/bitstring>> = Bin,
         <<Pre:I, (1 - Bit):1, Post/bitstring>>
     end || I <- lists:seq(0, bit_size(Bin) - 1)].

truncations(Bin) ->
    [binary:part(Bin, 0, N) || N <- lists:seq(0, byte_size(Bin) - 1)].

survives(A, Inputs) ->
    lists:foreach(
        fun(In) ->
            {A1, Acts} = ?AG:handle_packet(s, ?R, In, 10, A),
            %% Whatever is sent back is well-formed STUN.
            [?assertMatch({ok, _}, webrtc_stun:decode(B)) || {send, _, _, B} <- Acts],
            _ = ?AG:handle_timeout(?AG:next_timeout(A1), A1),
            _ = ?AG:stats(A1)
        end,
        Inputs
    ).

malformed_check_test_() ->
    Valid = encode(check_attrs() ++ [{use_candidate, true}], ?P),
    Agents = [with_remote(agent(#{})), agent(#{}), with_remote(agent(#{lite => true})),
              with_remote(agent(#{role => controlling}))],
    [{timeout, 60, ?_test(survives(A, truncations(Valid) ++ flips(Valid)))} || A <- Agents].

malformed_response_test() ->
    {A, Check, _} = first_check(#{}),
    Valid = success_for(Check, ?L, ?RP),
    survives(A, truncations(Valid) ++ flips(Valid)).

garbage_test() ->
    A = with_remote(agent(#{})),
    R0 = rand:seed_s(exsss, {7, 7, 7}),
    {Inputs, _} = lists:foldl(
        fun(_, {Acc, R}) ->
            {Len, R1} = rand:uniform_s(120, R),
            {Bytes, R2} = lists:foldl(fun(_, {B, RR}) -> {X, RR1} = rand:uniform_s(256, RR), {<<B/binary, (X - 1)>>, RR1} end,
                                      {<<>>, R1}, lists:seq(1, Len)),
            %% Half of them look like STUN headers.
            In = case Len rem 2 of
                0 -> <<0, 1, (byte_size(Bytes)):16, 16#2112A442:32, 0:96, Bytes/binary>>;
                1 -> Bytes
            end,
            {[In | Acc], R2}
        end,
        {[], R0},
        lists:seq(1, 2000)
    ),
    survives(A, Inputs).

%%--------------------------------------------------------------------
%% Trickled pairs (RFC 8838 §12) and unfreezing (RFC 8445 §7.2.5.3.3)
%%--------------------------------------------------------------------

pair_state(A, IP) ->
    #{pairs := Pairs} = ?AG:stats(A),
    [St] = [St || #{state := St, remote := #ice_cand{address = I}} <- Pairs, I =:= IP],
    St.

trickle_states_test() ->
    A0 = with_remote(agent(#{})),
    %% Rule 1: the first pair of a foundation is Waiting.
    {A1, _} = ?AG:add_remote_candidate(remote(1), 0, A0),
    ?assertEqual(waiting, pair_state(A1, {10, 0, 0, 101})),
    %% Rule 3: same foundation, lower priority, nothing succeeded: Frozen.
    Low = (remote(5))#ice_cand{foundation = <<"1">>},
    {A2, _} = ?AG:add_remote_candidate(Low, 0, A1),
    ?assertEqual(frozen, pair_state(A2, {10, 0, 0, 105})),
    %% The first pair succeeds: its frozen sibling is unfrozen.
    {A3, Acts} = tick(A2, 0),
    [{s, {{10, 0, 0, 101}, 6000} = To, Check, _}] = sends([X || {_, X} <- Acts]),
    {A4, _} = deliver(success_for(Check, ?L, ?RP), To, 20, A3),
    ?assertEqual(succeeded, pair_state(A4, {10, 0, 0, 101})),
    ?assertEqual(waiting, pair_state(A4, {10, 0, 0, 105})),
    %% Rule 2: a succeeded pair with the foundation makes a new one Waiting.
    Lower = (remote(9))#ice_cand{foundation = <<"1">>},
    {A5, _} = ?AG:add_remote_candidate(Lower, 30, A4),
    ?assertEqual(waiting, pair_state(A5, {10, 0, 0, 109})).

%%--------------------------------------------------------------------
%% Nomination policy and failure (RFC 8445 §8.1.1, §7.2.5.3.4, RFC 8863)
%%--------------------------------------------------------------------

two_remotes(Opts) ->
    A0 = with_remote(agent(Opts#{role => controlling})),
    A1 = lists:foldl(fun(N, A) -> element(1, ?AG:add_remote_candidate(remote(N), 0, A)) end, A0, [1, 2]),
    {A2, Acts} = tick(A1, 50),
    [{_, {send, s, {{10, 0, 0, 101}, _}, _}}, {_, {send, s, {{10, 0, 0, 102}, _} = To2, B2}}] = Acts,
    %% Only the lower priority pair answers.
    {ok, C2} = webrtc_stun:decode(B2),
    {A3, _} = deliver(success_for(C2, ?L, ?RP), To2, 60, A2),
    {A3, To2}.

use_candidate_sends(Acts) ->
    [T || {T, {send, _, _, B}} <- Acts,
          {ok, M} <- [webrtc_stun:decode(B)], M#stun.class =:= request,
          webrtc_stun:get(use_candidate, M) =:= {ok, true}].

nomination_best_waits_test() ->
    {A, _} = two_remotes(#{nomination_timeout => 1000}),
    {_, Acts} = tick(A, 2000),
    %% The better pair is still in progress: nomination waits for the
    %% timeout after the first valid pair (at 60 ms).
    [First | _] = use_candidate_sends(Acts),
    ?assert(First >= 1060 andalso First =< 1110).

nomination_first_test() ->
    {A, _} = two_remotes(#{nomination => first}),
    {_, Acts} = tick(A, 2000),
    [First | _] = use_candidate_sends(Acts),
    ?assert(First =< 110).

nomination_failure_test() ->
    {A, _} = two_remotes(#{nomination => first}),
    %% The nomination check is never answered.
    {A1, _} = tick(A, 39000),
    ?assertEqual(connected, ?AG:connection_state(A1)),
    {A2, _} = tick(A1, 80000),
    ?assertEqual(failed, ?AG:connection_state(A2)),
    #{pairs := Pairs} = ?AG:stats(A2),
    ?assertEqual([], [P || #{valid := true} = P <- Pairs]).

%%--------------------------------------------------------------------
%% Consent responses must be authentic and symmetric
%%--------------------------------------------------------------------

forged_consent_response_test() ->
    {A, Check, _} = first_check(#{}),
    {A1, _} = deliver(success_for(Check, ?L, ?RP), ?R, 30, A),
    {A2, _} = deliver(encode(check_attrs() ++ [{use_candidate, true}], ?P), ?R, 40, A1),
    {A3, Acts} = tick(A2, 7000),
    [{_, {send, s, ?R, CBin}} | _] = [X || {_, {send, _, _, _}} = X <- Acts],
    {ok, Consent} = webrtc_stun:decode(CBin),
    Wrong = success_for(Consent, ?L, <<"not the remote password">>),
    {A4, []} = deliver(Wrong, ?R, 7001, A3),
    %% From another address: ignored as well.
    {A5, []} = deliver(success_for(Consent, ?L, ?RP), {{10, 0, 0, 77}, 6000}, 7002, A4),
    %% Without fresh responses consent expires 30 s after the last one.
    {A6, Later} = tick(A5, 30100),
    ?assertMatch([{consent_lost, _, _}], [E || {_, {event, {consent_lost, _, _} = E}} <- Later]),
    ?assertEqual(failed, ?AG:connection_state(A6)).
