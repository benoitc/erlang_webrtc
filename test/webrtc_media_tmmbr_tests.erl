%% TMMBR and TMMBN between two media sessions (RFC 5104 §4.2, RFC 8834
%% §5.1.6): B asks A to send less on the video stream; A answers with
%% TMMBN, tells its owner and holds the stream to the limit.
-module(webrtc_media_tmmbr_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp.hrl").
-include("webrtc_rtp_rtcp.hrl").
-include_lib("webrtc/src/transport/webrtc_media.hrl").

-define(PROFILE, srtp_aead_aes_128_gcm).

jsep() ->
    webrtc_jsep:new(#{
        ice_ufrag => <<"ufrag">>,
        ice_pwd => <<"passwordpasswordpassword">>,
        fingerprints => [{sha256, crypto:strong_rand_bytes(32)}]
    }).

wire(Sdp) ->
    {ok, P} = webrtc_sdp:parse(webrtc_sdp:encode(Sdp)),
    P.

sections() ->
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
    {MA, MB}.

pair(MA, MB) ->
    Material = crypto:strong_rand_bytes(webrtc_srtp:key_material_length(?PROFILE)),
    SA = webrtc_media:set_srtp(?PROFILE, Material, server, 0, webrtc_media:configure(MA, webrtc_media:new(#{cname => <<"a">>}))),
    SB = webrtc_media:set_srtp(?PROFILE, Material, client, 0, webrtc_media:configure(MB, webrtc_media:new(#{cname => <<"b">>}))),
    {SA, SB}.

pair() ->
    {MA, MB} = sections(),
    pair(MA, MB).

%% Without ccm tmmbr on the codecs of a section.
strip(Sections) ->
    [S#{send_codecs := [C#{rtcp_fb := [F || F <- Fb, not webrtc_jsep_caps:is_tmmbr(F)]}
                        || #{rtcp_fb := Fb} = C <- maps:get(send_codecs, S)],
        recv_codecs := [C#{rtcp_fb := [F || F <- Fb, not webrtc_jsep_caps:is_tmmbr(F)]}
                        || #{rtcp_fb := Fb} = C <- maps:get(recv_codecs, S)]}
     || S <- Sections].

deliver(Acts, S, Now) ->
    lists:foldl(fun({send, Bin}, {SAcc, AAcc}) ->
                        {S1, A} = webrtc_media:handle_packet(Bin, Now, SAcc),
                        {S1, AAcc ++ A};
                   (_, Acc) ->
                        Acc
                end, {S, []}, Acts).

events(Acts) -> [E || {event, E} <- Acts].

%% B learns A's video SSRC from one packet.
started() ->
    {SA, SB} = pair(),
    {ok, Out, SA1} = webrtc_media:send(<<"1">>, <<"frame">>, #{timestamp => 1}, 0, SA),
    {SB1, _} = deliver(Out, SB, 0),
    {SA1, SB1}.

request_answered_test() ->
    {SA, SB} = started(),
    {ok, Req, SB1} = webrtc_media:request_max_bitrate(<<"1">>, 200000, 10, SB),
    ?assertMatch([_], Req),
    {SA1, Acts} = deliver(Req, SA, 10),
    %% The owner learns the net rate at the current packet rate.
    ?assertMatch([{max_bitrate, <<"1">>, 200000}], [E || {max_bitrate, _, _} = E <- events(Acts)]),
    %% A TMMBN went back, and B stops repeating once it has it.
    Tmmbn = [A || {send, _} = A <- Acts],
    ?assertMatch([_], Tmmbn),
    {SB2, _} = deliver(Tmmbn, SB1, 20),
    _ = SA1,
    ?assertEqual([], webrtc_media_limit:repeats(SB2)),
    ?assertMatch([#rtcp_tmmbr{}], webrtc_media_limit:repeats(SB1)).

not_negotiated_test() ->
    {MA, MB} = sections(),
    {_SA, SB} = pair(strip(MA), strip(MB)),
    ?assertEqual({error, not_negotiated}, webrtc_media:request_max_bitrate(<<"1">>, 200000, 0, SB)).

%% A peer that did not negotiate TMMBR has its requests ignored (RFC
%% 5104 §7).
ignored_when_not_negotiated_test() ->
    {MA, MB} = sections(),
    {SA, SB} = pair(strip(MA), MB),
    {ok, Out, _} = webrtc_media:send(<<"1">>, <<"frame">>, #{timestamp => 1}, 0, SA),
    {SB1, _} = deliver(Out, SB, 0),
    {ok, Req, _} = webrtc_media:request_max_bitrate(<<"1">>, 200000, 10, SB1),
    {SA1, Acts} = deliver(Req, SA, 10),
    ?assertEqual([], [E || {max_bitrate, _, _} = E <- events(Acts)]),
    ?assertEqual([], [A || {send, _} = A <- Acts]),
    #{counters := C} = webrtc_media:stats(SA1),
    ?assertEqual(1, maps:get(tmmbr_ignored, C)).

%% 1000 byte frames every 10 ms (800 kb/s) under a 200 kb/s limit: what
%% leaves over two seconds stays within the limit and one burst.
limit_followed_test() ->
    {SA, SB} = started(),
    {ok, Req, _} = webrtc_media:request_max_bitrate(<<"1">>, 200000, 10, SB),
    {SA1, _} = deliver(Req, SA, 10),
    Payload = binary:copy(<<0>>, 1000),
    {Sent, _} = lists:foldl(
        fun(T, {Acc, S}) ->
            {ok, Out, S1} = webrtc_media:send(<<"1">>, Payload, #{timestamp => T * 90, marker => true}, T, S),
            {S2, Out2} = run_timers(T, S1),
            {Acc + length([x || {send, B} <- Out ++ Out2, byte_size(B) > 900]), S2}
        end,
        {0, SA1},
        lists:seq(20, 2010, 10)
    ),
    %% 2 s at 200 kb/s is 50 payloads of 1000 bytes, plus the 40 ms
    %% burst and one packet.
    ?assert(Sent =< 50 + 2),
    ?assert(Sent >= 40).

run_timers(Now, S) ->
    case webrtc_media:next_timeout(S) of
        T when T =< Now ->
            {S1, A} = webrtc_media:handle_timeout(T, S),
            {S2, A2} = run_timers(Now, S1),
            {S2, A ++ A2};
        _ ->
            {S, []}
    end.

%% BYE from the owner lifts the limit once the hold-off has passed
%% (RFC 5104 §4.2.1.2), with a new TMMBN.
bye_lifts_limit_test() ->
    {SA, SB} = started(),
    {ok, Req, SB1} = webrtc_media:request_max_bitrate(<<"1">>, 200000, 10, SB),
    {SA1, _} = deliver(Req, SA, 10),
    Me = SB1#media.rtcp_ssrc,
    {Bye, _} = webrtc_media_out:send_rtcp([#rtcp_rr{ssrc = Me, reports = []}, #rtcp_bye{ssrcs = [Me]}], SB1),
    {SA2, Acts} = deliver(Bye, SA1, 20),
    ?assertMatch([_ | _], [A || {send, _} = A <- Acts]),
    ?assertEqual([], [E || {max_bitrate, _, infinity} = E <- events(Acts)]),
    {_, Later} = run_timers(20 + 600, SA2),
    ?assertMatch([{max_bitrate, <<"1">>, infinity}], [E || {max_bitrate, _, _} = E <- events(Later)]).

%% A limit of 0 holds the stream.
zero_holds_test() ->
    {SA, SB} = started(),
    %% The smallest request we can make is 1 b/s; at any packet rate the
    %% header overhead takes it to 0.
    {ok, Req, _} = webrtc_media:request_max_bitrate(<<"1">>, 1, 10, SB),
    {SA1, Acts} = deliver(Req, SA, 10),
    ?assertMatch([{max_bitrate, <<"1">>, 1}], [E || {max_bitrate, _, _} = E <- events(Acts)]),
    {ok, Out1, SA2} = webrtc_media:send(<<"1">>, <<"frame">>, #{timestamp => 90}, 20, SA1),
    {ok, Out2, _} = webrtc_media:send(<<"1">>, <<"frame">>, #{timestamp => 180}, 30, SA2),
    ?assertEqual([], [x || {send, _} <- tl(Out1 ++ Out2)]).
