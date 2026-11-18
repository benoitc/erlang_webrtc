%% Per-peer media state stays bounded by the streams we know: a peer
%% that sends authenticated RTCP about SSRCs of its choice must not grow
%% our maps.
-module(webrtc_media_bounds_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp.hrl").
-include("webrtc_rtp_rtcp.hrl").
-include_lib("webrtc/src/transport/webrtc_media.hrl").

-define(PROFILE, srtp_aead_aes_128_gcm).

jsep() ->
    webrtc_jsep:new(#{ice_ufrag => <<"ufrag">>, ice_pwd => <<"passwordpasswordpassword">>,
                      fingerprints => [{sha256, crypto:strong_rand_bytes(32)}]}).

wire(Sdp) ->
    {ok, P} = webrtc_sdp:parse(webrtc_sdp:encode(Sdp)),
    P.

%% A sends audio and video to B; B's RTCP goes to A.
pair() ->
    {ok, _, A0} = webrtc_jsep:add_transceiver(audio, #{}, jsep()),
    {ok, _, A1} = webrtc_jsep:add_transceiver(video, #{}, A0),
    {ok, _, B0} = webrtc_jsep:add_transceiver(audio, #{}, jsep()),
    {ok, _, B1} = webrtc_jsep:add_transceiver(video, #{}, B0),
    {ok, O, A2} = webrtc_jsep:create_offer(#{}, A1),
    {ok, A3} = webrtc_jsep:set_local_description(offer, O, A2),
    {ok, B2} = webrtc_jsep:set_remote_description(offer, wire(O), B1),
    {ok, Ans, B3} = webrtc_jsep:create_answer(#{}, B2),
    {ok, B4} = webrtc_jsep:set_local_description(answer, Ans, B3),
    {ok, A4} = webrtc_jsep:set_remote_description(answer, wire(Ans), A3),
    #{media := MA} = webrtc_jsep:negotiated(A4),
    #{media := MB} = webrtc_jsep:negotiated(B4),
    Material = crypto:strong_rand_bytes(webrtc_srtp:key_material_length(?PROFILE)),
    SA = webrtc_media:set_srtp(?PROFILE, Material, server, 0, webrtc_media:configure(MA, webrtc_media:new(#{}))),
    SB = webrtc_media:set_srtp(?PROFILE, Material, client, 0, webrtc_media:configure(MB, webrtc_media:new(#{}))),
    {ok, O1, SA1} = webrtc_media:send(<<"0">>, <<"a">>, #{timestamp => 1}, 0, SA),
    {SB1, _} = deliver(O1, SB),
    {SA1, SB1}.

deliver(Acts, S) ->
    lists:foldl(fun({send, Bin}, {SA, AA}) -> {S1, A} = webrtc_media:handle_packet(Bin, 0, SA), {S1, AA ++ A};
                   (_, Acc) -> Acc
                end, {S, []}, Acts).

%% B sends `Pkts' in compounds of `N', each authenticated.
flood(Pkts, N, A, B) ->
    {A1, _} = lists:foldl(
        fun(Chunk, {AA, BB}) ->
            {Out, BB1} = webrtc_media_out:send_rtcp([#rtcp_rr{ssrc = BB#media.rtcp_ssrc} | Chunk], BB),
            {AA1, _} = deliver(Out, AA),
            {AA1, BB1}
        end,
        {A, B},
        chunks(Pkts, N)
    ),
    A1.

chunks([], _) -> [];
chunks(L, N) when length(L) =< N -> [L];
chunks(L, N) -> {H, T} = lists:split(N, L), [H | chunks(T, N)].

sizes(M) ->
    #{streams => map_size(M#media.streams), receivers => map_size(M#media.receivers),
      pause_req => map_size(M#media.pause_req), xr_rrtr => map_size(M#media.xr_rrtr),
      ssrc_mid => map_size(M#media.ssrc_mid), last_seen => map_size(M#media.last_seen)}.

%% The review's probe: 10,000 PLI for SSRCs we do not send.
unknown_pli_test() ->
    {A, B} = pair(),
    Before = sizes(A),
    Pkts = [#rtcp_pli{sender_ssrc = 1, media_ssrc = 16#10000 + I} || I <- lists:seq(1, 10000)],
    A1 = flood(Pkts, 50, A, B),
    ?assertEqual(Before, sizes(A1)),
    ?assertEqual(10000, maps:get(feedback_unknown_ssrc, A1#media.counters)).

unknown_nack_fir_test() ->
    {A, B} = pair(),
    Before = sizes(A),
    Pkts = lists:append([[#rtcp_nack{sender_ssrc = 1, media_ssrc = I, items = [{1, 0}]},
                          #rtcp_fir{sender_ssrc = 1, media_ssrc = 0, entries = [{I + 1, 0}]}]
                         || I <- lists:seq(16#20000, 16#20000 + 2000, 2)]),
    ?assertEqual(Before, sizes(flood(Pkts, 40, A, B))).

%% SR from SSRCs we do not receive: no remote-outbound stream.
unknown_sr_test() ->
    {A, B} = pair(),
    Before = sizes(A),
    Pkts = [#rtcp_sr{ssrc = 16#30000 + I, ntp = 1 bsl 40, rtp_ts = 0} || I <- lists:seq(1, 2000)],
    A1 = flood(Pkts, 20, A, B),
    ?assertEqual(Before, sizes(A1)),
    ?assertEqual(2000, maps:get(sr_unknown_ssrc, A1#media.counters)).

%% BYE: the stream's statistics go with it.
bye_removes_stream_test() ->
    {A, B} = pair(),
    [Ssrc] = [S || S := #rcv{mid = <<"0">>} <- B#media.receivers],
    ?assert(is_map_key({in, Ssrc}, B#media.streams)),
    {Bye, _} = webrtc_media_out:send_rtcp([#rtcp_rr{ssrc = Ssrc}, #rtcp_bye{ssrcs = [Ssrc]}], A),
    {B1, _} = deliver(Bye, B),
    ?assertNot(is_map_key({in, Ssrc}, B1#media.streams)),
    ?assertNot(is_map_key(Ssrc, B1#media.receivers)).

%% Random authenticated RTCP about random SSRCs: every per-SSRC map
%% stays within its bound.
random_rtcp_test() ->
    rand:seed(exsss, {7, 8, 9}),
    {A, B} = pair(),
    Pkts = [random_packet() || _ <- lists:seq(1, 5000)],
    A1 = flood(Pkts, 10, A, B),
    #{streams := St, receivers := Rc, pause_req := Pr, xr_rrtr := Xr} = sizes(A1),
    ?assert(St =< 2 * 256),
    ?assert(Rc =< 256),
    ?assert(Pr =< 256),
    ?assert(Xr =< 16),
    %% TMMBR from as many requesters keeps only the owners of the set.
    [#snd{tmmbr = T} | _] = [S || #snd{tmmbr = T0} = S <- maps:values(A1#media.senders), T0 =/= undefined],
    ?assert(erts_debug:flat_size(T) < 1000).

random_packet() ->
    S = rand:uniform(16#FFFFFFFF),
    case rand:uniform(9) of
        1 -> #rtcp_pli{sender_ssrc = S, media_ssrc = rand:uniform(16#FFFFFFFF)};
        2 -> #rtcp_fir{sender_ssrc = S, media_ssrc = 0, entries = [{rand:uniform(16#FFFFFFFF), 1}]};
        3 -> #rtcp_nack{sender_ssrc = S, media_ssrc = rand:uniform(16#FFFFFFFF), items = [{1, 0}]};
        4 -> #rtcp_sr{ssrc = S, ntp = 1 bsl 40};
        5 -> #rtcp_rr{ssrc = S, reports = [#rtcp_rb{ssrc = rand:uniform(16#FFFFFFFF)}]};
        6 -> #rtcp_bye{ssrcs = [S]};
        7 -> #rtcp_pause{sender_ssrc = S, entries = [{rand:uniform(16#FFFFFFFF), paused, 1, 0}]};
        8 -> #rtcp_tmmbr{sender_ssrc = S, media_ssrc = 0, entries = [{rand:uniform(16#FFFFFFFF), 100000 + S rem 1000, 40}]};
        9 -> #rtcp_xr{ssrc = S, blocks = [{rrtr, 1 bsl 40}]}
    end.

%% W3C: an ended stream is still reported until the receiver drops it:
%% another SSRC on the same mid, or the transceiver stopped. At most 16.
ended_stream_stats_test() ->
    {A, B} = pair(),
    [Ssrc] = [S || S := #rcv{mid = <<"0">>} <- B#media.receivers],
    {Bye, A1} = webrtc_media_out:send_rtcp([#rtcp_rr{ssrc = Ssrc}, #rtcp_bye{ssrcs = [Ssrc]}], A),
    {B1, _} = deliver(Bye, B),
    #{receivers := R1, streams := S1} = webrtc_media:stats(B1),
    ?assert(is_map_key(Ssrc, R1)),
    ?assertMatch(#{packets_received := 1}, maps:get({in, Ssrc}, S1)),
    %% A new SSRC on mid 0 replaces it.
    New = Ssrc bxor 1,
    {ok, Out, _} = webrtc_media:send(<<"0">>, <<"b">>, #{timestamp => 2}, 0, A1#media{senders = maps:map(fun(<<"0">>, S) -> S#snd{ssrc = New}; (_, S) -> S end, A1#media.senders)}),
    {B2, _} = deliver(Out, B1),
    #{receivers := R2} = webrtc_media:stats(B2),
    ?assertNot(is_map_key(Ssrc, R2)),
    ?assert(is_map_key(New, R2)).

ended_cap_test() ->
    {_A, B} = pair(),
    Ended = [{S, #{mid => <<"9">>}, #{}} || S <- lists:seq(1, 40)],
    B1 = lists:foldl(fun(E, Acc) -> Acc#media{ended = lists:sublist([E | Acc#media.ended], 16)} end, B, Ended),
    ?assertEqual(16, length(B1#media.ended)),
    %% A stopped transceiver's ended streams go on configure.
    B2 = webrtc_media:configure([], B1),
    ?assertEqual([], B2#media.ended).
