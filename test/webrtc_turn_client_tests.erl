%% Tests for the sans-IO TURN client (RFC 8656) against the test TURN
%% server, and for ChannelData framing.
-module(webrtc_turn_client_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_stun.hrl").

-define(TC, webrtc_turn_client).
-define(SRV, {{198, 51, 100, 2}, 3478}).
-define(CLIENT, {{203, 0, 113, 1}, 40000}).
-define(PEER, {{192, 0, 2, 50}, 7000}).

%%--------------------------------------------------------------------
%% Harness: one client, the test server and peers, with a fake clock.
%%--------------------------------------------------------------------

world(ServerOpts) ->
    world(ServerOpts, #{}).

world(ServerOpts, ClientOpts) ->
    #{
        now => 0,
        client => ?TC:new(maps:merge(#{server => ?SRV, username => <<"user">>, password => <<"pass">>}, ClientOpts)),
        server => webrtc_test_turn_server:new(ServerOpts#{address => ?SRV}),
        events => [],
        peers => [],
        drop => fun(_) -> false end
    }.

%% Apply a client call and route everything until quiet.
do(W = #{client := C}, Fun) ->
    {C1, Acts} = Fun(C),
    route(Acts, W#{client => C1}).

route(Acts, W) ->
    lists:foldl(fun act/2, W, Acts).

act({event, E}, W = #{events := Es, now := Now}) ->
    W#{events => Es ++ [{Now, E}]};
act({send, Bin}, W = #{drop := Drop}) ->
    case Drop(Bin) of
        true -> W;
        false -> to_server(?CLIENT, ?SRV, Bin, W)
    end.

to_server(From, To, Bin, W = #{server := S, now := Now}) ->
    {S1, Out} = webrtc_test_turn_server:handle(From, To, Bin, Now, S),
    lists:foldl(
        fun
            ({send, _, ?CLIENT, B}, WA) ->
                case (maps:get(drop_in, WA, fun(_) -> false end))(B) of
                    true -> WA;
                    false -> do(WA, fun(C) -> ?TC:handle_packet(B, maps:get(now, WA), C) end)
                end;
            ({send, Relay, Peer, B}, WA = #{peers := Ps}) ->
                WA#{peers => Ps ++ [{Relay, Peer, B}]}
        end,
        W#{server => S1},
        Out
    ).

%% A peer sends to the relayed address.
from_peer(Peer, Data, W = #{client := C}) ->
    to_server(Peer, ?TC:relayed_address(C), Data, W).

advance(W, Until) ->
    #{client := C, now := Now} = W,
    case ?TC:next_timeout(C) of
        T when T =< Until ->
            W1 = do(W#{now => max(Now, T)}, fun(Cl) -> ?TC:handle_timeout(max(Now, T), Cl) end),
            #{server := S} = W1,
            {S1, _} = webrtc_test_turn_server:handle_timeout(max(Now, T), S),
            advance(W1#{server => S1}, Until);
        _ ->
            W#{now => Until}
    end.

events(#{events := E}) -> [Ev || {_, Ev} <- E].

allocated(ServerOpts) ->
    W = do(world(ServerOpts), fun(C) -> ?TC:allocate(0, C) end),
    ?assertEqual(allocated, ?TC:state(maps:get(client, W))),
    W.

server_log(#{server := S}) -> webrtc_test_turn_server:log(S).

%%--------------------------------------------------------------------
%% Allocation
%%--------------------------------------------------------------------

allocate_md5_test() ->
    W = allocated(#{}),
    [{allocated, #{relayed := {{198, 51, 100, 2}, 50000}, mapped := ?CLIENT, lifetime := 600}}] = events(W),
    [{allocate, First}, {allocate, Second}] = server_log(W),
    %% First request without credentials (RFC 8489 §9.2.3.1).
    ?assertNot(lists:member(username, First)),
    ?assert(lists:member(requested_transport, First)),
    ?assert(lists:member(software, First)),
    ?assertEqual([username, realm, nonce, message_integrity], [A || A <- Second, lists:member(A, [username, realm, nonce, message_integrity, message_integrity_sha256])]),
    ?assertEqual({{198, 51, 100, 2}, 50000}, ?TC:relayed_address(maps:get(client, W))),
    ?assertEqual(?CLIENT, ?TC:mapped_address(maps:get(client, W))).

allocate_sha256_test() ->
    W = allocated(#{sha256 => true}),
    [_, {allocate, Second}] = server_log(W),
    ?assert(lists:member(password_algorithms, Second)),
    ?assert(lists:member(password_algorithm, Second)),
    ?assert(lists:member(message_integrity_sha256, Second)),
    ?assertNot(lists:member(message_integrity, Second)),
    %% Later requests keep SHA-256.
    W1 = do(W, fun(C) -> ?TC:create_permission({192, 0, 2, 50}, 0, C) end),
    {create_permission, Attrs} = lists:last(server_log(W1)),
    ?assert(lists:member(message_integrity_sha256, Attrs)),
    ?assertEqual([{permission, {192, 0, 2, 50}, ok}], events(W1) -- events(W)).

wrong_password_test() ->
    W0 = world(#{}, #{password => <<"bad">>}),
    W = do(W0, fun(C) -> ?TC:allocate(0, C) end),
    ?assertEqual([{allocate_failed, {error, 401}}], events(W)),
    ?assertEqual(failed, ?TC:state(maps:get(client, W))),
    %% Exactly one retry with credentials.
    ?assertEqual(2, length(server_log(W))).

stale_nonce_test() ->
    W = allocated(#{stale_nonce => 1}),
    ?assertMatch([{allocated, _}], events(W)),
    ?assertEqual(3, length(server_log(W))).

allocate_errors_test_() ->
    [?_assertEqual([{allocate_failed, {error, Code}}],
                   events(do(world(#{reject_allocate => Code}), fun(C) -> ?TC:allocate(0, C) end)))
     || Code <- [403, 440, 441, 442, 486, 508]] ++
        [?_assertEqual([{allocate_failed, {error, 486}}],
                       events(do(world(#{max_allocations => 0}), fun(C) -> ?TC:allocate(0, C) end)))].

allocate_timeout_test() ->
    W0 = (world(#{}))#{drop => fun(_) -> true end},
    W1 = do(W0, fun(C) -> ?TC:allocate(0, C) end),
    W2 = advance(W1, 39499),
    ?assertEqual([], events(W2)),
    W3 = advance(W2, 39500),
    ?assertEqual([{allocate_failed, timeout}], events(W3)).

unauthenticated_success_discarded_test() ->
    W = allocated(#{}),
    #{client := C} = W,
    %% A forged, unprotected 437 to a refresh must not kill the allocation.
    {C1, [{send, Req}]} = advance_to_refresh(C),
    {ok, M} = webrtc_stun:decode(Req),
    Forged = webrtc_stun:encode(webrtc_stun:error_response(M, 437, []), #{fingerprint => true}),
    {C2, []} = ?TC:handle_packet(Forged, 540000, C1),
    ?assertEqual(allocated, ?TC:state(C2)),
    %% The real one, integrity protected, does.
    Key = webrtc_stun:long_term_key(<<"user">>, <<"example.org">>, <<"pass">>),
    Real = webrtc_stun:encode(webrtc_stun:error_response(M, 437, []), #{integrity => {sha1, Key}, fingerprint => true}),
    {C3, [{event, {allocation_lost, {error, 437}}}]} = ?TC:handle_packet(Real, 540000, C2),
    ?assertEqual(failed, ?TC:state(C3)).

advance_to_refresh(C) ->
    ?assertEqual(540000, ?TC:next_timeout(C)),
    ?TC:handle_timeout(540000, C).

%%--------------------------------------------------------------------
%% Refresh and deallocation (RFC 8656 §8)
%%--------------------------------------------------------------------

refresh_test() ->
    W = allocated(#{}),
    W1 = advance(W, 3600 * 1000),
    ?assertEqual(allocated, ?TC:state(maps:get(client, W1))),
    Refreshes = [x || {refresh, _} <- server_log(W1)],
    %% Every 540 s during an hour.
    ?assertEqual(6, length(Refreshes)),
    ?assertEqual(1, map_size(webrtc_test_turn_server:allocations(maps:get(server, W1)))).

short_lifetime_refresh_test() ->
    W = allocated(#{lifetime => 100}),
    ?assertEqual(50000, ?TC:next_timeout(maps:get(client, W))).

deallocate_test() ->
    W = allocated(#{}),
    W1 = do(W, fun(C) -> ?TC:close(10, C) end),
    ?assertEqual([closed], events(W1) -- events(W)),
    ?assertEqual(closed, ?TC:state(maps:get(client, W1))),
    {refresh, Attrs} = lists:last(server_log(W1)),
    ?assert(lists:member(lifetime, Attrs)),
    ?assertEqual(0, map_size(webrtc_test_turn_server:allocations(maps:get(server, W1)))),
    ?assertEqual(infinity, ?TC:next_timeout(maps:get(client, W1))).

expiry_without_refresh_test() ->
    W0 = allocated(#{}),
    W1 = W0#{drop => fun(_) -> true end},
    W2 = advance(W1, 700000),
    ?assertMatch([{allocation_lost, _}], events(W2) -- events(W0)).

%%--------------------------------------------------------------------
%% Permissions and data (RFC 8656 §9 to §11)
%%--------------------------------------------------------------------

send_creates_permission_test() ->
    W = allocated(#{}),
    W1 = do(W, fun(C) -> ?TC:send(?PEER, <<"hello">>, 10, C) end),
    ?assertEqual([{permission, {192, 0, 2, 50}, ok}], events(W1) -- events(W)),
    ?assertEqual([{{{198, 51, 100, 2}, 50000}, ?PEER, <<"hello">>}], maps:get(peers, W1)),
    ?assert(?TC:has_permission({192, 0, 2, 50}, maps:get(client, W1))),
    %% Data from the peer arrives in a Data indication.
    W2 = from_peer(?PEER, <<"back">>, W1),
    ?assertEqual([{data, ?PEER, <<"back">>}], events(W2) -- events(W1)),
    %% Another port of the same IP is allowed by the permission.
    W3 = from_peer({{192, 0, 2, 50}, 7001}, <<"port">>, W2),
    ?assertEqual([{data, {{192, 0, 2, 50}, 7001}, <<"port">>}], events(W3) -- events(W2)),
    %% Another IP is not.
    W4 = from_peer({{192, 0, 2, 51}, 7000}, <<"nope">>, W3),
    ?assertEqual(events(W3), events(W4)).

permission_refresh_test() ->
    W = do(allocated(#{}), fun(C) -> ?TC:create_permission({192, 0, 2, 50}, 0, C) end),
    W1 = advance(W, 1000000),
    Perms = [x || {create_permission, _} <- server_log(W1)],
    %% Installed at 0 then refreshed every 240 s.
    ?assertEqual(5, length(Perms)),
    W2 = from_peer(?PEER, <<"still">>, W1),
    ?assertEqual([{data, ?PEER, <<"still">>}], events(W2) -- events(W1)).

forbidden_permission_test() ->
    W = allocated(#{forbidden => [{192, 0, 2, 50}]}),
    W1 = do(W, fun(C) -> ?TC:send(?PEER, <<"x">>, 10, C) end),
    ?assertEqual([{permission, {192, 0, 2, 50}, {error, 403}}], events(W1) -- events(W)),
    ?assertEqual([], maps:get(peers, W1)),
    ?assertNot(?TC:has_permission({192, 0, 2, 50}, maps:get(client, W1))).

send_before_allocation_dropped_test() ->
    C = ?TC:new(#{server => ?SRV}),
    ?assertEqual({C, []}, ?TC:send(?PEER, <<"x">>, 0, C)).

data_indication_checks_test() ->
    W = allocated(#{}),
    #{client := C} = W,
    NoPeer = webrtc_stun:encode(webrtc_stun:indication(data, [{data, <<"x">>}]), #{}),
    ?assertMatch({_, []}, ?TC:handle_packet(NoPeer, 0, C)),
    NoPerm = webrtc_stun:encode(webrtc_stun:indication(data, [{xor_peer_address, ?PEER}, {data, <<"x">>}]), #{}),
    ?assertMatch({_, []}, ?TC:handle_packet(NoPerm, 0, C)),
    ?assertMatch({_, []}, ?TC:handle_packet(<<"garbage">>, 0, C)).

%%--------------------------------------------------------------------
%% Channels (RFC 8656 §12)
%%--------------------------------------------------------------------

channel_test() ->
    W = allocated(#{}),
    W1 = do(W, fun(C) -> ?TC:bind_channel(?PEER, 10, C) end),
    ?assertEqual([{channel, ?PEER, {ok, 16#4000}}], events(W1) -- events(W)),
    ?assertEqual({ok, 16#4000}, ?TC:channel(?PEER, maps:get(client, W1))),
    %% The binding installs the permission too.
    ?assert(?TC:has_permission({192, 0, 2, 50}, maps:get(client, W1))),
    {_, [{send, Frame}]} = ?TC:send(?PEER, <<"abcde">>, 20, maps:get(client, W1)),
    %% ChannelData: 4-byte header, padded to 4 bytes over UDP.
    ?assertEqual(<<16#40, 16#00, 0, 5, "abcde", 0, 0, 0>>, Frame),
    W2 = do(W1, fun(C) -> ?TC:send(?PEER, <<"abcde">>, 20, C) end),
    ?assertEqual([{{{198, 51, 100, 2}, 50000}, ?PEER, <<"abcde">>}], maps:get(peers, W2)),
    %% The server uses the channel towards the client.
    W3 = from_peer(?PEER, <<"via channel">>, W2),
    ?assertEqual([{data, ?PEER, <<"via channel">>}], events(W3) -- events(W2)),
    %% A second peer gets the next channel number.
    W4 = do(W3, fun(C) -> ?TC:bind_channel({{192, 0, 2, 60}, 1}, 30, C) end),
    ?assertEqual({ok, 16#4001}, ?TC:channel({{192, 0, 2, 60}, 1}, maps:get(client, W4))).

%% RFC 8656 §12: a ChannelBind whose response is lost may be installed
%% on the server; its number does not go to another peer, and the same
%% peer gets it back.
lost_channel_bind_test() ->
    Peer2 = {{192, 0, 2, 60}, 1},
    IsResponse = fun(B) ->
        case webrtc_stun:decode(B) of
            {ok, #stun{class = success, method = channel_bind}} -> true;
            _ -> false
        end
    end,
    W0 = (allocated(#{}))#{drop_in => IsResponse},
    W1 = advance(do(W0, fun(C) -> ?TC:bind_channel(?PEER, 0, C) end), 40000),
    ?assertMatch([{channel, ?PEER, timeout}], events(W1) -- events(W0)),
    W2 = W1#{drop_in => fun(_) -> false end},
    W3 = do(W2, fun(C) -> ?TC:bind_channel(Peer2, 40000, C) end),
    ?assertEqual([{channel, Peer2, {ok, 16#4001}}], events(W3) -- events(W2)),
    W4 = do(W3, fun(C) -> ?TC:bind_channel(?PEER, 40001, C) end),
    ?assertEqual([{channel, ?PEER, {ok, 16#4000}}], events(W4) -- events(W3)).

%% RFC 8656 §12.3: a 400 to ChannelBind means the bindings are out of
%% sync: the allocation is deleted and reported lost.
channel_out_of_sync_test() ->
    W0 = allocated(#{reject_channel_bind => 400}),
    W1 = do(W0, fun(C) -> ?TC:bind_channel(?PEER, 10, C) end),
    ?assertEqual([{allocation_lost, channel_out_of_sync}, closed], events(W1) -- events(W0)),
    ?assertEqual(closed, ?TC:state(maps:get(client, W1))).

channel_refresh_test() ->
    W = do(allocated(#{}), fun(C) -> ?TC:bind_channel(?PEER, 0, C) end),
    W1 = advance(W, 1200000),
    ?assertEqual(3, length([x || {channel_bind, _} <- server_log(W1)])),
    W2 = from_peer(?PEER, <<"late">>, W1),
    ?assertEqual([{data, ?PEER, <<"late">>}], events(W2) -- events(W1)).

channel_data_unknown_channel_test() ->
    W = allocated(#{}),
    ?assertMatch({_, []}, ?TC:handle_packet(webrtc_turn_channel:encode(16#4005, <<"x">>), 0, maps:get(client, W))).

channel_codec_test_() ->
    [
        ?_assertEqual(<<16#4F, 16#FF, 0, 0>>, webrtc_turn_channel:encode(16#4FFF, <<>>)),
        ?_assertEqual(<<16#40, 1, 0, 4, 1, 2, 3, 4>>, webrtc_turn_channel:encode(16#4001, <<1, 2, 3, 4>>)),
        ?_assertEqual({ok, 16#4001, <<1, 2, 3>>}, webrtc_turn_channel:decode(<<16#40, 1, 0, 3, 1, 2, 3, 0>>)),
        ?_assertEqual({ok, 16#4001, <<1, 2, 3>>}, webrtc_turn_channel:decode(<<16#40, 1, 0, 3, 1, 2, 3>>)),
        ?_assertEqual({error, truncated}, webrtc_turn_channel:decode(<<16#40, 1, 0, 4, 1, 2, 3>>)),
        ?_assertEqual({error, bad_channel}, webrtc_turn_channel:decode(<<16#50, 0, 0, 0>>)),
        ?_assertEqual({error, not_channel_data}, webrtc_turn_channel:decode(<<1, 2>>)),
        ?_assert(webrtc_turn_channel:is_channel_data(<<64, 0>>)),
        ?_assertNot(webrtc_turn_channel:is_channel_data(<<80, 0>>)),
        ?_assertError(function_clause, webrtc_turn_channel:encode(16#3FFF, <<>>)),
        ?_assertError(function_clause, webrtc_turn_channel:encode(16#5000, <<>>))
    ].

malformed_input_test() ->
    W = do(allocated(#{}), fun(C) -> ?TC:bind_channel(?PEER, 0, C) end),
    #{client := C} = W,
    Valid = webrtc_stun:encode(webrtc_stun:indication(data, [{xor_peer_address, ?PEER}, {data, <<"payload">>}]),
                               #{fingerprint => true}),
    Chan = webrtc_turn_channel:encode(16#4000, <<"payload">>),
    Inputs = [binary:part(B, 0, N) || B <- [Valid, Chan], N <- lists:seq(0, byte_size(B))] ++
        [flip(B, I) || B <- [Valid, Chan], I <- lists:seq(0, bit_size(B) - 1)],
    lists:foreach(fun(In) -> {_, _} = ?TC:handle_packet(In, 0, C) end, Inputs).

flip(Bin, I) ->
    <<Pre:I, Bit:1, Post/bitstring>> = Bin,
    <<Pre:I, (1 - Bit):1, Post/bitstring>>.

refresh_stale_nonce_test() ->
    %% The second authenticated request (the first Refresh) gets a 438.
    W = allocated(#{stale_nonce => 2}),
    W1 = advance(W, 600000),
    ?assertEqual(allocated, ?TC:state(maps:get(client, W1))),
    ?assertEqual(2, length([x || {refresh, _} <- server_log(W1)])),
    ?assertEqual(events(W), events(W1)).

auth_algorithm_test_() ->
    Cookie = fun(Bits) -> <<"obMatJos2", (base64:encode(<<Bits:24>>))/binary, "rest">> end,
    [
        ?_assertEqual({ok, undefined}, webrtc_turn_auth:pick_algorithm(<<"plain">>, undefined)),
        ?_assertEqual({ok, {sha256, <<>>}},
                      webrtc_turn_auth:pick_algorithm(Cookie(16#800000), [{sha256, <<>>}, {md5, <<>>}])),
        ?_assertEqual({ok, {md5, <<>>}}, webrtc_turn_auth:pick_algorithm(Cookie(16#800000), [{7, <<>>}, {md5, <<>>}])),
        ?_assertEqual({error, {unsupported, missing_password_algorithms}},
                      webrtc_turn_auth:pick_algorithm(Cookie(16#800000), undefined)),
        ?_assertEqual({error, {unsupported, userhash}}, webrtc_turn_auth:pick_algorithm(Cookie(16#400000), undefined)),
        ?_assertEqual({error, {unsupported, password_algorithms}},
                      webrtc_turn_auth:pick_algorithm(Cookie(16#800000), [{7, <<>>}])),
        ?_assertEqual(16#C00000, webrtc_turn_auth:nonce_features(Cookie(16#C00000))),
        ?_assertEqual(0, webrtc_turn_auth:nonce_features(<<"obMatJos2!!!!">>)),
        %% RFC 8489 §9.2.2 example key.
        ?_assertEqual({sha1, <<16#8493fbc53ba582fb4c044c456bdc40eb:128>>},
                      webrtc_turn_auth:integrity(<<"user">>, <<"realm">>, <<"pass">>, undefined)),
        ?_assertMatch({sha256, <<_:256>>}, webrtc_turn_auth:integrity(<<"u">>, <<"r">>, <<"p">>, {sha256, <<>>}))
    ].

challenge_with_cookie_without_algorithms_test() ->
    C0 = ?TC:new(#{server => ?SRV, username => <<"u">>, password => <<"p">>}),
    {C1, [{send, Req}]} = ?TC:allocate(0, C0),
    {ok, M} = webrtc_stun:decode(Req),
    Nonce = <<"obMatJos2", (base64:encode(<<16#800000:24>>))/binary, "x">>,
    Err = webrtc_stun:encode(webrtc_stun:error_response(M, 401, [{realm, <<"r">>}, {nonce, Nonce}]), #{}),
    %% RFC 8489 §9.2.5: no retry.
    ?assertMatch({_, [{event, {allocate_failed, {unsupported, missing_password_algorithms}}}]},
                 ?TC:handle_packet(Err, 10, C1)).
