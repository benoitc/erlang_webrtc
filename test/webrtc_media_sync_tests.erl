%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% RFC 6051 between two media sessions: A sends with the ntp-64 header
%% extension, B takes its mapping from it, from SR, and asks for an SR
%% with RTCP-SR-REQ when it has neither.
-module(webrtc_media_sync_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp.hrl").
-include("webrtc_rtp_rtcp.hrl").
-include_lib("webrtc/src/media/webrtc_media.hrl").

-define(PROFILE, srtp_aead_aes_128_gcm).
-define(NTP64, <<"urn:ietf:params:rtp-hdrext:ntp-64">>).
-define(NTP56, <<"urn:ietf:params:rtp-hdrext:ntp-56">>).

jsep() ->
    webrtc_jsep:new(#{ice_ufrag => <<"ufrag">>, ice_pwd => <<"passwordpasswordpassword">>,
                      fingerprints => [{sha256, crypto:strong_rand_bytes(32)}], cryptex => false}).

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

%% Without the NTP extensions on what A sends.
strip(Sections) ->
    [S#{send_extensions := maps:without([?NTP64, ?NTP56], maps:get(send_extensions, S))} || S <- Sections].

pair(MA, MB) ->
    Material = crypto:strong_rand_bytes(webrtc_srtp:key_material_length(?PROFILE)),
    {webrtc_media:set_srtp(?PROFILE, Material, server, 0, webrtc_media:configure(MA, webrtc_media:new(#{}))),
     webrtc_media:set_srtp(?PROFILE, Material, client, 0, webrtc_media:configure(MB, webrtc_media:new(#{}))),
     element(2, webrtc_srtp:dtls_contexts(?PROFILE, Material, client, #{}))}.

deliver(Acts, S, Now) ->
    lists:foldl(fun({send, Bin}, {SA, AA}) -> {S1, A} = webrtc_media:handle_packet(Bin, Now, SA), {S1, AA ++ A};
                   (_, Acc) -> Acc
                end, {S, []}, Acts).

%% Whether each RTP datagram carries the extension with id `Id'.
carries(Acts, In0, Id) ->
    {Flags, In} = lists:foldl(
        fun({send, Bin}, {Acc, I}) ->
            case webrtc_srtp:unprotect_rtp(Bin, I) of
                {ok, Plain, I1} ->
                    {ok, #rtp{ext = Ext}} = webrtc_rtp:decode(Plain, #{extensions => parse}),
                    {Acc ++ [is_list(Ext) andalso lists:keymember(Id, 1, Ext)], I1};
                _ ->
                    {Acc, I}
            end
        end,
        {[], In0},
        Acts
    ),
    {Flags, In}.

ntp_id(Sections, Mid) ->
    [Id] = [maps:get(?NTP64, maps:get(send_extensions, S)) || #{mid := M} = S <- Sections, M =:= Mid],
    Id.

negotiated_test() ->
    {MA, _} = sections(),
    [?assertMatch(#{?NTP64 := 6, ?NTP56 := 7}, maps:get(send_extensions, S)) || S <- MA].

%% Every packet carries it until the peer reports an LSR for the stream;
%% then only the first packet of a video keyframe and the next audio
%% packet.
inclusion_test() ->
    {MA, MB} = sections(),
    {SA, _SB, In} = pair(MA, MB),
    Id = ntp_id(MA, <<"0">>),
    {ok, O1, SA1} = webrtc_media:send(<<"0">>, <<"a">>, #{timestamp => 960}, 0, SA),
    {ok, O2, SA2} = webrtc_media:send(<<"0">>, <<"b">>, #{timestamp => 1920}, 20, SA1),
    {[true, true], In1} = carries(O1 ++ O2, In, Id),
    [#snd{ssrc = Audio}] = [S || #snd{kind = audio} = S <- maps:values(SA2#media.senders)],
    [#snd{ssrc = Video}] = [S || #snd{kind = video} = S <- maps:values(SA2#media.senders)],
    SA3 = webrtc_media_sync:acked(Video, webrtc_media_sync:acked(Audio, SA2)),
    {ok, O3, SA4} = webrtc_media:send(<<"0">>, <<"c">>, #{timestamp => 2880}, 40, SA3),
    {[false], In2} = carries(O3, In1, Id),
    {ok, O4, SA5} = webrtc_media:send_frame(<<"1">>, binary:copy(<<16#9d>>, 2500), #{timestamp => 3000, keyframe => true}, 50, SA4),
    {VideoFlags, In3} = carries(O4, In2, Id),
    ?assertMatch([true | _], VideoFlags),
    ?assertEqual([false], lists:usort(tl(VideoFlags))),
    {ok, O5, SA6} = webrtc_media:send(<<"0">>, <<"d">>, #{timestamp => 3840}, 60, SA5),
    {ok, O6, _} = webrtc_media:send(<<"0">>, <<"e">>, #{timestamp => 4800}, 80, SA6),
    ?assertMatch({[true, false], _}, carries(O5 ++ O6, In3, Id)).

%% The receiver's mapping from the extension and from the next SR agree:
%% the same clock (RFC 6051 §3.3).
mapping_test() ->
    {MA, MB} = sections(),
    {SA, SB, _} = pair(MA, MB),
    {ok, O1, SA1} = webrtc_media:send(<<"0">>, <<"a">>, #{timestamp => 48000}, 0, SA),
    {SB1, _} = deliver(O1, SB, 0),
    [#rcv{sync = {NtpUs, 48000}}] = [R || #rcv{mid = <<"0">>} = R <- maps:values(SB1#media.receivers)],
    ?assert(abs(NtpUs - erlang:system_time(microsecond)) < 100000),
    [Ssrc] = [S || S := #rcv{mid = <<"0">>} <- SB1#media.receivers],
    FromExt = webrtc_media_sync:ntp_time(Ssrc, 96000, SB1),
    {Rtcp, _} = webrtc_media_out:reports(0, [], SA1),
    {SB2, _} = deliver(Rtcp, SB1, 0),
    [#rcv{sync = {_, SrTs}}] = [R || #rcv{mid = <<"0">>} = R <- maps:values(SB2#media.receivers)],
    ?assertEqual(48000, SrTs),
    FromSr = webrtc_media_sync:ntp_time(Ssrc, 96000, SB2),
    ?assert(abs(FromSr - FromExt) < 5000),
    ?assertEqual(FromExt + 1000000, webrtc_media_sync:ntp_time(Ssrc, 96000 + 48000, SB1)).

%% B has no mapping after a second of media: its regular report asks for
%% an SR; A answers with one at once.
srreq_test() ->
    {MA, MB} = sections(),
    {SA, SB, _} = pair(strip(MA), MB),
    {ok, O1, SA1} = webrtc_media:send(<<"0">>, <<"a">>, #{timestamp => 960}, 0, SA),
    {SB1, _} = deliver(O1, SB, 0),
    ?assertEqual([], webrtc_media_sync:requests(500, SB1)),
    [#rtcp_srreq{media_ssrc = Ssrc}] = webrtc_media_sync:requests(1000, SB1),
    {Rtcp, _} = webrtc_media_out:reports(1000, webrtc_media_sync:requests(1000, SB1), SB1),
    {SA2, Acts} = deliver(Rtcp, SA1, 1000),
    #{counters := #{srreq_received := 1}} = webrtc_media:stats(SA2),
    {SB2, _} = deliver(Acts, SB1, 1000),
    %% The SR's timestamp is extrapolated to when it was sent (RFC 3550 §6.4.1).
    ?assertMatch([#rcv{sync = {_, 48960}}], [R || S := R <- SB2#media.receivers, S =:= Ssrc]),
    ?assertEqual([], webrtc_media_sync:requests(2000, SB2)).

%% ntp-56 needs an SR for its upper bits.
ntp56_test() ->
    Ids = #{?NTP56 => 7},
    Ntp = webrtc_rtp_stats:ntp_from_us(erlang:system_time(microsecond)),
    R0 = #rcv{mid = <<"0">>, clock_rate = 48000, rx = undefined},
    M0 = #media{receivers = #{1 => R0}, recv = #{<<"0">> => #{recv_extensions => Ids}}},
    Pkt = #rtp{ssrc = 1, ts = 100, ext = [{7, webrtc_rtp_ext:ntp56(Ntp)}]},
    M1 = webrtc_media_sync:rtp_in(<<"0">>, Pkt, 0, M0),
    ?assertEqual(undefined, (maps:get(1, M1#media.receivers))#rcv.sync),
    M2 = webrtc_media_sync:sr_in(#rtcp_sr{ssrc = 1, ntp = Ntp - (1 bsl 32), rtp_ts = 0}, M1),
    M3 = webrtc_media_sync:rtp_in(<<"0">>, Pkt, 0, M2),
    ?assertEqual({webrtc_rtp_stats:ntp_to_us(Ntp), 100}, (maps:get(1, M3#media.receivers))#rcv.sync).
