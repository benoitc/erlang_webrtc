%% Host name ICE candidates end to end (draft-ietf-mmusic-mdns-ice-candidates,
%% RFC 8839 §5.1): Erlang peers on loopback where one side only learns
%% the other through `<uuid>.local' names (served by a fake responder or
%% by the peer's own responder) or a DNS name.
%%
%% Candidates are only relayed from B to A: B never learns A's
%% candidates, so the connection only comes up if A resolves B's names
%% and starts the checks.
-module(webrtc_mdns_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2, end_per_testcase/2]).
-export([
    remote_mdns_candidates/1,
    hidden_host_candidates/1,
    fqdn_candidates/1,
    pending_candidates_bounded/1
]).

-define(LO, {127, 0, 0, 1}).
-define(NAME, <<"3f2504e0-4f89-41d3-9a0c-0305e82c3301.local">>).
-define(UNKNOWN, <<"deadbeef-0000-4000-8000-000000000000.local">>).

all() ->
    [remote_mdns_candidates, hidden_host_candidates, fqdn_candidates, pending_candidates_bounded].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(webrtc),
    Config.

end_per_suite(_Config) ->
    ok.

init_per_testcase(_TC, Config) ->
    webrtc_test_signal:flush(),
    Config.

end_per_testcase(_TC, _Config) ->
    webrtc_test_signal:flush(),
    ok.

pc(Opts) ->
    {ok, Pc} = webrtc:new_peer_connection(Opts#{loopback => true}),
    Pc.

%% A offers, B answers; B's answer reaches A through Rewrite.
negotiate(A, B, Rewrite) ->
    {ok, Offer} = webrtc:create_offer(A, #{}),
    ok = webrtc:set_local_description(A, offer, Offer),
    ok = webrtc:set_remote_description(B, offer, Offer),
    {ok, Answer} = webrtc:create_answer(B, #{}),
    ok = webrtc:set_local_description(B, answer, Answer),
    ok = webrtc:set_remote_description(A, answer, rewrite_sdp(Answer, Rewrite)),
    Answer.

rewrite_sdp(Sdp, Rewrite) ->
    Lines = binary:split(Sdp, <<"\r\n">>, [global]),
    iolist_to_binary(lists:join(<<"\r\n">>, [
        case L of
            <<"a=candidate:", _/binary>> -> <<"a=", (Rewrite(binary:part(L, 2, byte_size(L) - 2)))/binary>>;
            _ -> L
        end
     || L <- Lines
    ])).

%% Relay B's candidates to A (rewritten), until both are connected.
%% `Extra' candidates go to A just before B's end-of-candidates. Returns
%% B's candidates as signaled.
relay(A, B, Rewrite, Extra) ->
    relay(A, B, Rewrite, Extra, [], [], erlang:monotonic_time(millisecond) + 15000).

relay(A, B, Rewrite, Extra, Seen, Done, Deadline) ->
    case lists:sort(Done) =:= lists:sort([A, B]) of
        true ->
            lists:reverse(Seen);
        false ->
            Left = max(0, Deadline - erlang:monotonic_time(millisecond)),
            receive
                {webrtc, B, {ice_candidate, end_of_candidates, _}} ->
                    [ok = webrtc:add_ice_candidate(A, C) || C <- Extra],
                    ok = webrtc:add_ice_candidate(A, end_of_candidates),
                    relay(A, B, Rewrite, Extra, Seen, Done, Deadline);
                {webrtc, B, {ice_candidate, C, _}} ->
                    ok = webrtc:add_ice_candidate(A, Rewrite(C)),
                    relay(A, B, Rewrite, Extra, [C | Seen], Done, Deadline);
                {webrtc, P, {connection_state, connected}} when P =:= A; P =:= B ->
                    relay(A, B, Rewrite, Extra, Seen, [P | Done], Deadline);
                {webrtc, P, {connection_state, failed}} when P =:= A; P =:= B ->
                    ct:fail({failed, P})
            after Left ->
                ct:fail({not_connected, Done})
            end
    end.

replace_ip(Name) ->
    fun(C) -> binary:replace(C, <<" 127.0.0.1 ">>, <<" ", Name/binary, " ">>, [global]) end.

data_works(A, B) ->
    {ok, {datachannel_open, Id, _, _, _}} =
        webrtc_test_signal:wait(A, fun({datachannel_open, _, L, _, _}) -> L =:= <<"m">>; (_) -> false end, 10000),
    ok = webrtc:send_data(A, Id, text, <<"over mdns">>),
    {ok, _} = webrtc_test_signal:wait(B, fun({channel_message, _, _, D}) -> D =:= <<"over mdns">>; (_) -> false end, 10000),
    ok.

host_candidate(Name) ->
    <<"candidate:1 1 udp 2122260223 ", Name/binary, " 9 typ host">>.

%%--------------------------------------------------------------------

%% B's host candidates reach A as mDNS names a fake responder resolves.
%% An unresolvable name and an end-of-candidates sent before the names
%% resolved do not get in the way.
remote_mdns_candidates(_Config) ->
    {_, Port} = Fake = webrtc_test_mdns:start(#{?NAME => ?LO}),
    A = pc(#{mdns => #{group => {?LO, Port}, listen => false}}),
    B = pc(#{}),
    ok = webrtc:create_data_channel(A, <<"m">>, #{}),
    _ = negotiate(A, B, replace_ip(?NAME)),
    _ = relay(A, B, replace_ip(?NAME), [host_candidate(?UNKNOWN)]),
    ok = data_works(A, B),
    webrtc:close(A),
    webrtc:close(B),
    webrtc_test_mdns:stop(Fake).

%% B hides its host addresses behind names it answers for itself
%% (draft §3.1); A resolves them.
hidden_host_candidates(_Config) ->
    GP = webrtc_test_mdns:free_port(),
    A = pc(#{mdns => #{group => {?LO, GP}, listen => false}}),
    B = pc(#{mdns_host_candidates => true, mdns => #{group => {?LO, GP}, listen => {?LO, GP}}}),
    ok = webrtc:create_data_channel(A, <<"m">>, #{}),
    Answer = negotiate(A, B, fun(C) -> C end),
    Signaled = relay(A, B, fun(C) -> C end, []),
    ct:log("answer:~n~s~ncandidates: ~p", [Answer, Signaled]),
    ?assertNotEqual([], Signaled),
    [?assertEqual(nomatch, binary:match(C, <<"127.0.0.1">>)) || C <- Signaled],
    [?assertNotEqual(nomatch, binary:match(C, <<".local ">>)) || C <- Signaled],
    ?assertEqual(nomatch, no_ip_in_candidates(Answer)),
    ok = data_works(A, B),
    webrtc:close(A),
    webrtc:close(B).

no_ip_in_candidates(Sdp) ->
    Cands = [L || <<"a=candidate:", _/binary>> = L <- binary:split(Sdp, <<"\r\n">>, [global])],
    case [L || L <- Cands, binary:match(L, <<"127.0.0.1">>) =/= nomatch] of
        [] -> nomatch;
        Leaked -> {leaked, Leaked}
    end.

%% A DNS name in place of the address (RFC 8839 §5.1).
fqdn_candidates(_Config) ->
    A = pc(#{}),
    B = pc(#{}),
    ok = webrtc:create_data_channel(A, <<"m">>, #{}),
    _ = negotiate(A, B, replace_ip(<<"localhost">>)),
    _ = relay(A, B, replace_ip(<<"localhost">>), []),
    ok = data_works(A, B),
    webrtc:close(A),
    webrtc:close(B).

%% Candidates waiting for their name are bounded; the extra ones are
%% refused and the peer connection keeps working.
pending_candidates_bounded(_Config) ->
    {_, Port} = Fake = webrtc_test_mdns:start(#{}),
    A = pc(#{mdns => #{group => {?LO, Port}, listen => false, max_pending => 4, schedule => [2000]}}),
    B = pc(#{}),
    ok = webrtc:create_data_channel(A, <<"m">>, #{}),
    _ = negotiate(A, B, fun(C) -> C end),
    Names = [iolist_to_binary(io_lib:format("~8.16.0b-0000-4000-8000-000000000000.local", [N])) || N <- lists:seq(1, 5)],
    Results = [webrtc:add_ice_candidate(A, host_candidate(N)) || N <- Names],
    ?assertEqual([ok, ok, ok, ok, {error, too_many_pending}], Results),
    ?assert(is_process_alive(A)),
    %% IP candidates are not held back by the pending names.
    ok = webrtc:add_ice_candidate(A, <<"candidate:2 1 udp 2122260223 127.0.0.1 9 typ host">>),
    webrtc:close(A),
    webrtc:close(B),
    webrtc_test_mdns:stop(Fake).
