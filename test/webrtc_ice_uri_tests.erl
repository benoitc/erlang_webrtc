%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% STUN and TURN server URIs (RFC 7064, RFC 7065) and their resolution
%% (RFC 5928 §3, RFC 8489 §8.1), with a fake resolver.
-module(webrtc_ice_uri_tests).
-include_lib("eunit/include/eunit.hrl").

-define(U, webrtc_ice_uri).
-define(R, webrtc_ice_resolve).

uri(S) ->
    {ok, U} = ?U:parse(S),
    maps:with([scheme, host, port, transport], U).

%% The examples of RFC 7064 §3.2 and RFC 7065 §3, with the defaults:
%% port 3478, 5349 with TLS; UDP for turn, TLS over TCP for turns.
rfc_examples_test_() ->
    [
        ?_assertEqual(#{scheme => stun, host => "example.org", port => 3478, transport => udp}, uri("stun:example.org")),
        ?_assertEqual(#{scheme => stuns, host => "example.org", port => 5349, transport => tls}, uri("stuns:example.org")),
        ?_assertEqual(#{scheme => stun, host => "example.org", port => 8000, transport => udp}, uri("stun:example.org:8000")),
        ?_assertEqual(#{scheme => turn, host => "example.org", port => 3478, transport => udp}, uri("turn:example.org")),
        ?_assertEqual(#{scheme => turns, host => "example.org", port => 5349, transport => tls}, uri("turns:example.org")),
        ?_assertEqual(#{scheme => turn, host => "example.org", port => 8000, transport => udp}, uri("turn:example.org:8000")),
        ?_assertEqual(#{scheme => turn, host => "example.org", port => 3478, transport => udp},
                      uri("turn:example.org?transport=udp")),
        ?_assertEqual(#{scheme => turn, host => "example.org", port => 3478, transport => tcp},
                      uri("turn:example.org?transport=tcp")),
        ?_assertEqual(#{scheme => turns, host => "example.org", port => 5349, transport => tls},
                      uri("turns:example.org?transport=tcp"))
    ].

%% RFC 3986 hosts: IPv4, IPv6 in brackets, registered names
%% (case-insensitive, percent-encoding decoded); the scheme is
%% case-insensitive too.
hosts_test_() ->
    [
        ?_assertMatch(#{host := {192, 0, 2, 1}, port := 3479}, uri(<<"stun:192.0.2.1:3479">>)),
        ?_assertMatch(#{host := {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}, port := 3478}, uri(<<"turn:[2001:db8::1]">>)),
        ?_assertMatch(#{host := {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}, port := 5000}, uri(<<"turn:[2001:db8::1]:5000">>)),
        ?_assertMatch(#{host := "example.org"}, uri(<<"turn:Ex%61mple.ORG">>)),
        ?_assertMatch(#{scheme := turn}, uri(<<"TURN:example.org">>)),
        ?_assertMatch(#{explicit_port := false}, element(2, ?U:parse(<<"stun:example.org">>))),
        ?_assertMatch(#{explicit_port := true}, element(2, ?U:parse(<<"stun:example.org:3478">>)))
    ].

refused_test_() ->
    [?_assertMatch({error, _}, ?U:parse(U)) || U <- [
        <<"example.org">>,
        <<"http://example.org">>,
        <<"stun:">>,
        <<"stun:example.org:0">>,
        <<"stun:example.org:65536">>,
        <<"stun:example.org:abc">>,
        <<"stun:example.org:">>,
        <<"stun:example.org?transport=udp">>,
        <<"turn:example.org?transport=">>,
        <<"turn:example.org?foo=bar">>,
        <<"turn:[2001:db8::1">>,
        <<"turn:[not-v6]">>,
        <<"turn:exa mple.org">>,
        <<"turn:ex%zzample.org">>
    ]].

%% TURN over DTLS (RFC 7350) and unknown transports parse but are not
%% supported.
unsupported_transport_test_() ->
    [
        ?_assertEqual({error, {unsupported_transport, <<"udp">>}}, ?U:parse(<<"turns:example.org?transport=udp">>)),
        ?_assertEqual({error, {unsupported_transport, <<"sctp">>}}, ?U:parse(<<"turn:example.org?transport=sctp">>))
    ].

%% The W3C RTCIceServer list: TURN needs credentials; URIs that cannot
%% be used are set apart to be reported, malformed ones refuse the list.
servers_test_() ->
    Turn = #{urls => [<<"turn:example.org">>], username => <<"u">>, credential => <<"p">>},
    [
        ?_assertMatch({ok, [#{url := <<"stun:example.org">>}], []}, ?U:servers([#{urls => <<"stun:example.org">>}])),
        ?_assertMatch({ok, [#{username := <<"u">>, credential := <<"p">>}], []}, ?U:servers([Turn])),
        ?_assertMatch({error, {missing_credentials, _}}, ?U:servers([#{urls => [<<"turn:example.org">>]}])),
        ?_assertMatch({error, {bad_uri, _, _}}, ?U:servers([#{urls => [<<"turn:">>]}])),
        ?_assertMatch({error, missing_urls}, ?U:servers([#{}])),
        ?_assertMatch({ok, [], [{<<"stuns:example.org">>, unsupported_scheme},
                                {<<"turns:example.org?transport=udp">>, {unsupported_transport, _}}]},
                      ?U:servers([#{urls => [<<"stuns:example.org">>, <<"turns:example.org?transport=udp">>],
                                    username => <<"u">>, credential => <<"p">>}]))
    ].

%%====================================================================
%% Resolution
%%====================================================================

%% A fake DNS: Records maps {Type, Name} to the answer; anything else is
%% not found.
dns(Records) ->
    fun(Type, Name) ->
        case maps:find({Type, Name}, Records) of
            {ok, R} -> {ok, R};
            error when Type =:= srv -> {ok, []};
            error -> {error, nxdomain}
        end
    end.

resolve(Urls, Records) ->
    {ok, Servers, []} = ?U:servers([#{urls => Urls, username => <<"u">>, credential => <<"p">>}]),
    ?R:resolve(Servers, #{resolver => dns(Records)}).

%% An IP address needs no lookup.
literal_test() ->
    ?assertEqual({[{<<"stun:192.0.2.1">>, {stun, {{192, 0, 2, 1}, 3478}}, []}], []}, resolve([<<"stun:192.0.2.1">>], #{})).

%% A name with a port: A and AAAA, no SRV; per family the first address
%% is the server and the others its fallbacks (RFC 8489 §8.1).
explicit_port_test() ->
    Dns = #{{inet, "s.example"} => [{192, 0, 2, 1}, {192, 0, 2, 2}], {inet6, "s.example"} => [{16#2001, 16#db8, 0, 0, 0, 0, 0, 1}],
            {srv, "_stun._udp.s.example"} => [{0, 0, 9999, "other.example"}]},
    {Found, []} = resolve([<<"stun:s.example:4000">>], Dns),
    ?assertEqual([{{stun, {{192, 0, 2, 1}, 4000}}, [{{192, 0, 2, 2}, 4000}]},
                  {{stun, {{16#2001, 16#db8, 0, 0, 0, 0, 0, 1}, 4000}}, []}], [{E, F} || {_, E, F} <- Found]).

%% Without a port, SRV first: targets in priority order, then weight,
%% with their ports (RFC 2782); none, the default port.
srv_test() ->
    Dns = #{{srv, "_turn._tcp.t.example"} => [{20, 0, 4000, "b.example"}, {10, 5, 3000, "a.example"}],
            {inet, "a.example"} => [{192, 0, 2, 10}], {inet, "b.example"} => [{192, 0, 2, 20}],
            {inet, "t.example"} => [{192, 0, 2, 30}]},
    {[{_, {turn, T}, Fallbacks}], []} = resolve([<<"turn:t.example?transport=tcp">>], Dns),
    ?assertMatch(#{address := {{192, 0, 2, 10}, 3000}, transport := tcp, username := <<"u">>, password := <<"p">>,
                   hostname := "t.example"}, T),
    %% The next SRV target is the fallback (RFC 5928 §3).
    ?assertEqual([{{192, 0, 2, 20}, 4000}], Fallbacks),
    {[{_, {turn, U}, []}], []} = resolve([<<"turn:t.example">>], Dns),
    ?assertMatch(#{address := {{192, 0, 2, 30}, 3478}, transport := udp}, U).

%% The SRV name follows scheme and transport.
srv_names_test_() ->
    Check = fun(Url, Srv) ->
        Dns = #{{srv, Srv} => [{0, 0, 7000, "x.example"}], {inet, "x.example"} => [{192, 0, 2, 1}]},
        {[{_, {_, E}, _}], []} = resolve([Url], Dns),
        ?assertMatch({{192, 0, 2, 1}, 7000}, case E of #{address := A} -> A; A -> A end)
    end,
    [
        ?_test(Check(<<"stun:x.example">>, "_stun._udp.x.example")),
        ?_test(Check(<<"turn:x.example">>, "_turn._udp.x.example")),
        ?_test(Check(<<"turn:x.example?transport=tcp">>, "_turn._tcp.x.example")),
        ?_test(Check(<<"turns:x.example">>, "_turns._tcp.x.example"))
    ].

%% A name that does not resolve, or not in time, is reported.
failure_test_() ->
    Slow = fun(_, _) -> timer:sleep(500), {ok, []} end,
    {ok, Servers, []} = ?U:servers([#{urls => [<<"stun:slow.example">>]}]),
    [
        ?_assertEqual({[], [{<<"stun:none.example">>, nxdomain}]}, resolve([<<"stun:none.example">>], #{})),
        ?_assertEqual({[], [{<<"stun:slow.example">>, timeout}]}, ?R:resolve(Servers, #{resolver => Slow, timeout => 100}))
    ].

%%====================================================================
%% Peer connection
%%====================================================================

%% A malformed list is refused; a URI that cannot be used is reported
%% to the owner and the others are kept.
peer_connection_test_() ->
    {setup, fun() -> application:ensure_all_started(webrtc) end, fun(_) -> ok end, [
        ?_assertEqual({error, {badarg, ice_servers}}, webrtc:new_peer_connection(#{ice_servers => [#{urls => [<<"stun">>]}]})),
        ?_assertEqual({error, {badarg, ice_servers}}, webrtc:new_peer_connection(#{ice_servers => not_a_list})),
        ?_test(begin
            {ok, Pc} = webrtc:new_peer_connection(#{
                ice_servers => [#{urls => [<<"stun:none.example">>, <<"stuns:192.0.2.1">>, <<"stun:192.0.2.1">>]}],
                ice_resolver => dns(#{})
            }),
            Errors = [receive {webrtc, Pc, {ice_server_error, U, R}} -> {U, R} after 1000 -> timeout end || _ <- [1, 2]],
            ?assertEqual([{<<"stun:none.example">>, nxdomain}, {<<"stuns:192.0.2.1">>, unsupported_scheme}],
                         lists:sort(Errors)),
            webrtc:close(Pc)
        end)
    ]}.
