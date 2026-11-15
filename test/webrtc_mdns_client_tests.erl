%% Transport side of host name candidates
%% (draft-ietf-mmusic-mdns-ice-candidates-03 §3.1, §3.2; RFC 8839 §5.1).
-module(webrtc_mdns_client_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_ice.hrl").

-define(CL, webrtc_mdns_client).
-define(LO, {127, 0, 0, 1}).
-define(UUID, <<"1b4e28ba-2fa1-41d2-883f-0016d3cca427.local">>).
-define(UUID2, <<"6fa459ea-ee8a-4ca4-894e-db77e160355e.local">>).

cand(Addr) ->
    <<"candidate:1 1 udp 2122260223 ", Addr/binary, " 5000 typ host generation 0">>.

client(Names) ->
    {_, Port} = Fake = webrtc_test_mdns:start(Names),
    {?CL:new(#{group => {?LO, Port}, listen => false, schedule => [100, 100]}, [inet]), Fake}.

%% Wait for the resolver's answer and hand it to the client.
next(C) ->
    receive
        {webrtc_mdns, _, _} = M -> ?CL:handle_info(M, C)
    after 3000 -> error(no_result)
    end.

ip_candidates_pass_through_test() ->
    C = ?CL:new(#{}, [inet]),
    ?assertMatch({add, <<"1 1 udp 2122260223 192.0.2.1 5000 typ host generation 0">>, _},
                 ?CL:remote_candidate(cand(<<"192.0.2.1">>), C)),
    %% A related address that is a name is dropped, and so is a mark the
    %% peer tries to set itself.
    Srflx = <<"candidate:2 1 udp 1686052607 198.51.100.7 6000 typ srflx raddr x.local rport 1 x-mdns-name y">>,
    ?assertMatch({add, <<"2 1 udp 1686052607 198.51.100.7 6000 typ srflx">>, _}, ?CL:remote_candidate(Srflx, C)),
    %% Unparsable values go to the ICE agent, which reports the error.
    ?assertMatch({add, <<"garbage">>, _}, ?CL:remote_candidate(<<"garbage">>, C)).

non_uuid_local_name_ignored_test() ->
    C = ?CL:new(#{}, [inet]),
    ?assertMatch({ignored, _}, ?CL:remote_candidate(cand(<<"printer.local">>), C)),
    ?assertMatch({ignored, _}, ?CL:remote_candidate(cand(<<"1b4e28ba-2fa1-11d2-883f-0016d3cca427.local">>), C)).

mdns_resolved_and_marked_test() ->
    {C0, Fake} = client(#{?UUID => {127, 0, 0, 1}}),
    {pending, C1} = ?CL:remote_candidate(cand(string:uppercase(?UUID)), C0),
    {ok, [V], false, C2} = next(C1),
    {ok, Ice} = webrtc_ice_candidate:from_sdp(V),
    ?assertEqual({127, 0, 0, 1}, Ice#ice_cand.address),
    ?assertEqual(5000, Ice#ice_cand.port),
    ?assertEqual([{<<"generation">>, <<"0">>}, {?ICE_EXT_MDNS, string:uppercase(?UUID)}], Ice#ice_cand.extensions),
    ok = ?CL:stop(C2),
    webrtc_test_mdns:stop(Fake).

mdns_several_addresses_ignored_test() ->
    {C0, Fake} = client(#{?UUID => [{127, 0, 0, 1}, {127, 0, 0, 2}]}),
    {pending, C1} = ?CL:remote_candidate(cand(?UUID), C0),
    %% draft §3.2.2: a name resolving to several addresses is ignored.
    ?assertMatch({ok, [], false, _}, next(C1)),
    webrtc_test_mdns:stop(Fake).

unresolved_name_and_deferred_end_of_candidates_test() ->
    {C0, Fake} = client(#{?UUID => {127, 0, 0, 1}}),
    {pending, C1} = ?CL:remote_candidate(cand(?UUID2), C0),
    {pending, C2} = ?CL:remote_candidate(cand(?UUID), C1),
    {deferred, C3} = ?CL:end_of_candidates(C2),
    %% The known name answers first; end-of-candidates waits for the
    %% other one, which times out and is dropped.
    {ok, [_], false, C4} = next(C3),
    {ok, [], true, C5} = next(C4),
    ?assertMatch({now, _}, ?CL:end_of_candidates(C5)),
    webrtc_test_mdns:stop(Fake).

fqdn_family_choice_test() ->
    C0 = ?CL:new(#{}, [inet]),
    {pending, C1} = ?CL:remote_candidate(cand(<<"localhost">>), C0),
    {ok, [V], false, _} = next(C1),
    {ok, Ice} = webrtc_ice_candidate:from_sdp(V),
    ?assertEqual({127, 0, 0, 1}, Ice#ice_cand.address),
    ?assertNot(lists:keymember(?ICE_EXT_MDNS, 1, Ice#ice_cand.extensions)).

restart_drops_pending_test() ->
    {C0, Fake} = client(#{?UUID => {127, 0, 0, 1}}),
    {pending, C1} = ?CL:remote_candidate(cand(?UUID), C0),
    C2 = ?CL:restart(C1),
    receive {webrtc_mdns, _, _} = M -> ?assertEqual(ignore, ?CL:handle_info(M, C2)) after 3000 -> error(no_result) end,
    webrtc_test_mdns:stop(Fake).

pending_bounded_test() ->
    {_, Port} = Fake = webrtc_test_mdns:start(#{}),
    C0 = ?CL:new(#{group => {?LO, Port}, listen => false, max_pending => 1}, [inet]),
    {pending, C1} = ?CL:remote_candidate(cand(?UUID), C0),
    ?assertMatch({error, too_many_pending, _}, ?CL:remote_candidate(cand(?UUID2), C1)),
    ok = ?CL:stop(C1),
    webrtc_test_mdns:stop(Fake).

hidden_local_candidates_test() ->
    GP = webrtc_test_mdns:free_port(),
    C0 = ?CL:new(#{group => {?LO, GP}, listen => {?LO, GP}, hide_host => true}, [inet]),
    Host = #ice_cand{foundation = <<"1">>, priority = 2122260223, address = {192, 0, 2, 1}, port = 5000, type = host},
    {V1, C1} = ?CL:local_candidate(Host, C0),
    ?assertMatch({match, _}, re:run(V1, "^candidate:1 1 (?i:udp) 2122260223 [0-9a-f-]{36}\\.local 5000 typ host$")),
    %% Same address, same name.
    ?assertMatch({V1, _}, ?CL:local_candidate(Host, C1)),
    %% draft §3.1.2.2: the related address does not reveal the host.
    Srflx = Host#ice_cand{type = srflx, address = {198, 51, 100, 7}, related_address = {192, 0, 2, 1}, related_port = 5000},
    {V2, C2} = ?CL:local_candidate(Srflx, C1),
    ?assertNotEqual(nomatch, binary:match(V2, <<" raddr 0.0.0.0 rport 9">>)),
    ok = ?CL:stop(C2),
    %% Without the option candidates are signaled as they are.
    ?assertMatch({<<"candidate:1 1 UDP 2122260223 192.0.2.1 5000 typ host">>, _},
                 ?CL:local_candidate(Host, ?CL:new(#{}, [inet]))).

%% draft §3.1.2.2: a STUN server mapping a hidden host to itself shows
%% the address is public; with `expose_public' later gatherings signal
%% it as it is, while the STUN servers stay the same.
public_address_test() ->
    GP = webrtc_test_mdns:free_port(),
    Stun = [{{192, 0, 2, 10}, 3478}],
    IP = {203, 0, 113, 9},
    ok = webrtc_mdns_public:ensure(),
    true = ets:delete(webrtc_mdns_public, IP),
    New = fun(Opts) -> ?CL:new(Opts#{group => {?LO, GP}, listen => {?LO, GP}, hide_host => true}, [inet]) end,
    Host = #ice_cand{foundation = <<"1">>, priority = 2122260223, address = IP, port = 5000, type = host},
    Srflx = Host#ice_cand{type = srflx, priority = 1686052607, related_address = IP, related_port = 5000},
    Plain = <<"candidate:1 1 UDP 2122260223 203.0.113.9 5000 typ host">>,
    C0 = New(#{stun_servers => Stun}),
    %% Not known yet: hidden.
    {V1, C1} = ?CL:local_candidate(Host, C0),
    ?assertNotEqual(nomatch, binary:match(V1, <<".local">>)),
    %% The mapped address is the host's: the srflx candidate still hides
    %% its related address.
    {V2, C2} = ?CL:local_candidate(Srflx, C1),
    ?assertNotEqual(nomatch, binary:match(V2, <<"203.0.113.9 5000 typ srflx raddr 0.0.0.0 rport 9">>)),
    ok = ?CL:stop(C2),
    %% The next gathering (an ICE restart or another peer connection).
    C3 = New(#{stun_servers => Stun}),
    ?assertMatch({Plain, _}, ?CL:local_candidate(Host, C3)),
    %% The policy can keep hiding it.
    C4 = New(#{stun_servers => Stun, expose_public => false}),
    {V4, C5} = ?CL:local_candidate(Host, C4),
    ?assertNotEqual(nomatch, binary:match(V4, <<".local">>)),
    ok = ?CL:stop(C5),
    %% Other STUN servers: the finding is dropped.
    C6 = New(#{stun_servers => [{{192, 0, 2, 11}, 3478}]}),
    {V6, C7} = ?CL:local_candidate(Host, C6),
    ?assertNotEqual(nomatch, binary:match(V6, <<".local">>)),
    ok = ?CL:stop(C7),
    C8 = New(#{stun_servers => Stun}),
    {V8, C9} = ?CL:local_candidate(Host, C8),
    ?assertNotEqual(nomatch, binary:match(V8, <<".local">>)),
    ok = ?CL:stop(C9).

%% A mapped address other than the host's says nothing.
private_address_test() ->
    GP = webrtc_test_mdns:free_port(),
    Stun = [{{192, 0, 2, 10}, 3478}],
    IP = {192, 0, 2, 77},
    C0 = ?CL:new(#{group => {?LO, GP}, listen => {?LO, GP}, hide_host => true, stun_servers => Stun}, [inet]),
    Host = #ice_cand{foundation = <<"1">>, priority = 2122260223, address = IP, port = 5000, type = host},
    {_, C1} = ?CL:local_candidate(Host#ice_cand{type = srflx, address = {198, 51, 100, 7}, related_address = IP,
                                                related_port = 5000}, C0),
    ?assertNot(webrtc_mdns_public:is_public(IP, Stun)),
    {V, C2} = ?CL:local_candidate(Host, C1),
    ?assertNotEqual(nomatch, binary:match(V, <<".local">>)),
    ok = ?CL:stop(C2).
