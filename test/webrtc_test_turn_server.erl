%% @doc Test-only TURN server (RFC 8656 server side, UDP) used by the
%% in-memory network. Long-term credentials with a nonce, optional
%% PASSWORD-ALGORITHMS (SHA-256), allocations, permissions, channels,
%% Send/Data indications and ChannelData.
%%
%% Options: `address', `realm', `users' (#{User => Password}),
%% `sha256' (offer PASSWORD-ALGORITHMS), `stale_nonce' (number of
%% authenticated requests after which the nonce goes stale once),
%% `max_allocations', `forbidden' (peer IPs refused with 403),
%% `lifetime' (default 600 s), `reject_allocate' (error code).
-module(webrtc_test_turn_server).

-include("webrtc_stun.hrl").

-export([new/1, handle/5, handle_timeout/2, next_timeout/1, allocations/1, log/1]).

new(Opts) ->
    #{
        address => maps:get(address, Opts),
        realm => maps:get(realm, Opts, <<"example.org">>),
        users => maps:get(users, Opts, #{<<"user">> => <<"pass">>}),
        sha256 => maps:get(sha256, Opts, false),
        stale_nonce => maps:get(stale_nonce, Opts, infinity),
        max_allocations => maps:get(max_allocations, Opts, 100),
        forbidden => maps:get(forbidden, Opts, []),
        lifetime => maps:get(lifetime, Opts, 600),
        reject_allocate => maps:get(reject_allocate, Opts, undefined),
        nonce => nonce(1, Opts),
        nonce_gen => 1,
        auth_count => 0,
        next_port => 50000,
        allocs => #{},
        log => []
    }.

nonce(N, Opts) ->
    case maps:get(sha256, Opts, false) of
        %% RFC 8489 §9.2.1 nonce cookie with the "password algorithms" bit.
        true -> <<"obMatJos2", (base64:encode(<<16#800000:24>>))/binary, "n", (integer_to_binary(N))/binary>>;
        false -> <<"nonce", (integer_to_binary(N))/binary>>
    end.

allocations(#{allocs := A}) -> A.
log(#{log := L}) -> lists:reverse(L).

%%--------------------------------------------------------------------

handle(Src, Dst, Bin, Now, S = #{address := Addr}) when Dst =:= Addr ->
    from_client(Src, Bin, Now, S);
handle(Src, Dst, Bin, Now, S) ->
    from_peer(Src, Dst, Bin, Now, S).

from_client(Src, <<B, _/binary>> = Bin, Now, S) when B >= 64, B =< 79 ->
    case {maps:find(Src, maps:get(allocs, S)), webrtc_turn_channel:decode(Bin)} of
        {{ok, #{chans := Ch, relay := Relay} = A}, {ok, N, Data}} ->
            case maps:find(N, Ch) of
                {ok, {Peer, _}} ->
                    case permitted(Peer, A, Now) of
                        true -> {S, [{send, Relay, Peer, Data}]};
                        false -> {S, []}
                    end;
                error ->
                    {S, []}
            end;
        _ ->
            {S, []}
    end;
from_client(Src, Bin, Now, S) ->
    case webrtc_stun:decode(Bin) of
        {ok, #stun{class = indication, method = send} = M} ->
            send_indication(Src, M, Now, S);
        {ok, #stun{class = request, method = binding} = M} ->
            %% TURN servers are STUN servers too.
            reply(Src, webrtc_stun:success(M, [{xor_mapped_address, Src}]), undefined, S);
        {ok, #stun{class = request} = M} ->
            request(Src, M, Bin, Now, log_req(M, S));
        _ ->
            {S, []}
    end.

log_req(#stun{method = M, attrs = A}, S = #{log := L}) ->
    S#{log => [{M, [K || {K, _} <- A]} | L]}.

send_indication(Src, M, Now, S) ->
    case {maps:find(Src, maps:get(allocs, S)), webrtc_stun:get(xor_peer_address, M), webrtc_stun:get(data, M)} of
        {{ok, #{relay := Relay} = A}, {ok, Peer}, {ok, Data}} ->
            case permitted(Peer, A, Now) of
                true -> {S, [{send, Relay, Peer, Data}]};
                false -> {S, []}
            end;
        _ ->
            {S, []}
    end.

permitted({IP, _}, #{perms := P}, Now) ->
    case maps:find(IP, P) of
        {ok, Exp} -> Now < Exp;
        error -> false
    end.

reply(Src, Msg, Key, S = #{address := Addr}) ->
    Opts =
        case Key of
            undefined -> #{fingerprint => true};
            {Alg, K} -> #{integrity => {Alg, K}, fingerprint => true}
        end,
    {S, [{send, Addr, Src, webrtc_stun:encode(Msg, Opts)}]}.

challenge(Src, M, Code, S) ->
    Attrs = [{realm, maps:get(realm, S)}, {nonce, maps:get(nonce, S)}] ++
        [{password_algorithms, [{sha256, <<>>}, {md5, <<>>}]} || maps:get(sha256, S)],
    reply(Src, webrtc_stun:error_response(M, Code, Attrs), undefined, S).

%% Long-term credential check (RFC 8489 §9.2.4).
auth(M, Bin, S) ->
    case {webrtc_stun:get(username, M), webrtc_stun:get(nonce, M), webrtc_stun:has_integrity(M)} of
        {{ok, U}, {ok, N}, true} ->
            case maps:find(U, maps:get(users, S)) of
                {ok, P} ->
                    {Alg, MI} =
                        case webrtc_stun:get(password_algorithm, M) of
                            {ok, {sha256, _}} -> {sha256, sha256};
                            {ok, {md5, _}} -> {md5, sha256};
                            _ when map_get(sha256, S) -> {none, none};
                            _ -> {md5, sha1}
                        end,
                    case Alg of
                        none ->
                            {error, 400};
                        _ ->
                            Key = webrtc_stun:long_term_key(Alg, U, maps:get(realm, S), P),
                            case webrtc_stun:check_integrity(Bin, Key) of
                                ok when N =/= map_get(nonce, S) -> {error, 438};
                                ok -> {ok, U, {MI, Key}};
                                {error, _} -> {error, 401}
                            end
                    end;
                error ->
                    {error, 401}
            end;
        _ ->
            {error, 401}
    end.

request(Src, M, Bin, Now, S) ->
    case auth(M, Bin, S) of
        {error, 401} ->
            challenge(Src, M, 401, S);
        {error, 438} ->
            challenge(Src, M, 438, S);
        {error, Code} ->
            reply(Src, webrtc_stun:error_response(M, Code, []), undefined, S);
        {ok, User, Key} ->
            Count = maps:get(auth_count, S) + 1,
            case Count =:= maps:get(stale_nonce, S) of
                true ->
                    Gen = maps:get(nonce_gen, S) + 1,
                    S1 = S#{auth_count => Count, nonce_gen => Gen,
                            nonce => nonce(Gen, #{sha256 => maps:get(sha256, S)})},
                    challenge(Src, M, 438, S1);
                false ->
                    method(M#stun.method, Src, M, User, Key, Now, S#{auth_count => Count})
            end
    end.

method(allocate, Src, M, User, Key, Now, S = #{allocs := As}) ->
    Transport = webrtc_stun:get(requested_transport, M, undefined),
    TxId = M#stun.txid,
    if
        is_map_key(Src, As), map_get(txid, map_get(Src, As)) =:= TxId ->
            %% Retransmission of the request that created the allocation.
            #{relay := R0, expires := E0} = maps:get(Src, As),
            reply(Src, webrtc_stun:success(M, [{xor_relayed_address, R0}, {xor_mapped_address, Src},
                                               {lifetime, (E0 - Now) div 1000}]), Key, S);
        is_map_key(Src, As) ->
            reply(Src, webrtc_stun:error_response(M, 437, []), Key, S);
        Transport =/= 17 ->
            reply(Src, webrtc_stun:error_response(M, 442, []), Key, S);
        map_size(As) >= map_get(max_allocations, S) ->
            reply(Src, webrtc_stun:error_response(M, 486, []), Key, S);
        map_get(reject_allocate, S) =/= undefined ->
            reply(Src, webrtc_stun:error_response(M, map_get(reject_allocate, S), []), Key, S);
        true ->
            {IP, _} = maps:get(address, S),
            Port = maps:get(next_port, S),
            Relay = {IP, Port},
            Life = min(webrtc_stun:get(lifetime, M, maps:get(lifetime, S)), 3600),
            A = #{user => User, txid => TxId, relay => Relay, expires => Now + Life * 1000, perms => #{}, chans => #{}},
            S1 = S#{allocs => As#{Src => A}, next_port => Port + 1},
            reply(Src, webrtc_stun:success(M, [{xor_relayed_address, Relay}, {xor_mapped_address, Src},
                                               {lifetime, Life}]), Key, S1)
    end;
method(Other, Src, M, User, Key, Now, S = #{allocs := As}) ->
    case maps:find(Src, As) of
        {ok, #{user := User} = A} ->
            alloc_method(Other, Src, M, A, Key, Now, S);
        {ok, _} ->
            reply(Src, webrtc_stun:error_response(M, 441, []), Key, S);
        error ->
            reply(Src, webrtc_stun:error_response(M, 437, []), Key, S)
    end.

alloc_method(refresh, Src, M, A, Key, Now, S = #{allocs := As}) ->
    case webrtc_stun:get(lifetime, M, maps:get(lifetime, S)) of
        0 ->
            reply(Src, webrtc_stun:success(M, [{lifetime, 0}]), Key, S#{allocs => maps:remove(Src, As)});
        L ->
            Life = min(L, 3600),
            A1 = A#{expires => Now + Life * 1000},
            reply(Src, webrtc_stun:success(M, [{lifetime, Life}]), Key, S#{allocs => As#{Src => A1}})
    end;
alloc_method(create_permission, Src, M, #{perms := P} = A, Key, Now, S = #{allocs := As}) ->
    IPs = [IP || {xor_peer_address, {IP, _}} <- M#stun.attrs],
    case IPs =/= [] andalso [IP || IP <- IPs, lists:member(IP, maps:get(forbidden, S))] =:= [] of
        true ->
            P1 = lists:foldl(fun(IP, Acc) -> Acc#{IP => Now + 300000} end, P, IPs),
            reply(Src, webrtc_stun:success(M, []), Key, S#{allocs => As#{Src => A#{perms => P1}}});
        false when IPs =:= [] ->
            reply(Src, webrtc_stun:error_response(M, 400, []), Key, S);
        false ->
            reply(Src, webrtc_stun:error_response(M, 403, []), Key, S)
    end;
alloc_method(channel_bind, Src, M, #{chans := Ch, perms := P} = A, Key, Now, S = #{allocs := As}) ->
    case {webrtc_stun:get(channel_number, M), webrtc_stun:get(xor_peer_address, M)} of
        {{ok, N}, {ok, {IP, _} = Peer}} ->
            Conflict = [X || X := {Pe, _} <- Ch, (X =:= N) xor (Pe =:= Peer)],
            case webrtc_turn_channel:valid_number(N) andalso Conflict =:= [] of
                true ->
                    A1 = A#{chans => Ch#{N => {Peer, Now + 600000}}, perms => P#{IP => Now + 300000}},
                    reply(Src, webrtc_stun:success(M, []), Key, S#{allocs => As#{Src => A1}});
                false ->
                    reply(Src, webrtc_stun:error_response(M, 400, []), Key, S)
            end;
        _ ->
            reply(Src, webrtc_stun:error_response(M, 400, []), Key, S)
    end;
alloc_method(_, Src, M, _A, Key, _Now, S) ->
    reply(Src, webrtc_stun:error_response(M, 400, []), Key, S).

from_peer(Src, Dst, Data, Now, S = #{allocs := As, address := Addr}) ->
    case [{C, A} || C := #{relay := R} = A <- As, R =:= Dst] of
        [{Client, A}] ->
            case permitted(Src, A, Now) of
                true ->
                    Msg =
                        case [N || N := {Pe, _} <- maps:get(chans, A), Pe =:= Src] of
                            [N | _] ->
                                webrtc_turn_channel:encode(N, Data);
                            [] ->
                                webrtc_stun:encode(
                                    webrtc_stun:indication(data, [{xor_peer_address, Src}, {data, Data}]),
                                    #{fingerprint => true}
                                )
                        end,
                    {S, [{send, Addr, Client, Msg}]};
                false ->
                    {S, []}
            end;
        [] ->
            {S, []}
    end.

handle_timeout(Now, S = #{allocs := As}) ->
    {S#{allocs => maps:filter(fun(_, #{expires := E}) -> E > Now end, As)}, []}.

next_timeout(#{allocs := As}) ->
    lists:min([infinity | [E || _ := #{expires := E} <- As]]).
