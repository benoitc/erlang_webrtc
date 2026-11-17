%% Inputs from libwebrtc's fuzz corpora (test/corpora/libwebrtc): unit
%% test samples, captures, browser SDPs and inputs that once crashed a
%% parser. Every file goes through every decoder of its kind and must
%% never raise. Each file has an expected verdict: the rejected ones are
%% listed below with the requirement that rejects them, every other file
%% must decode.
-module(webrtc_corpus_tests).
-include_lib("eunit/include/eunit.hrl").
-include("webrtc_rtp.hrl").

-export([files/0]).

dir() -> filename:join([filename:dirname(?FILE), "corpora", "libwebrtc"]).

%% @doc Every corpus file as {Kind, Name, Bin}.
files() ->
    [{list_to_atom(Kind), filename:basename(P), element(2, {ok, _} = file:read_file(P))}
     || Kind <- ["sdp", "stun", "stun-response", "rtcp", "rtp", "sctp-packet", "mdns", "h264", "av1"],
        P <- lists:sort(filelib:wildcard(filename:join([dir(), Kind, "*"])))].

%% Kinds of which every file is rejected.
-define(ALL_REJECTED, #{
    %% Scripts for libwebrtc's STUN request manager fuzzer, not STUN
    %% messages: no magic cookie (RFC 8489 §5).
    'stun-response' => bad_magic_cookie,
    %% Fuzzer output: record counts beyond the message, forward
    %% compression pointers (RFC 1035 §4.1.4 allows only prior names),
    %% A records whose length is not 4.
    mdns => any
}).

%% Single rejected files: {Kind, Name} => expected error.
-define(REJECTED, #{
    %% RFC 8839 §5.4: ice-char is ALPHA / DIGIT / "+" / "/", no "_".
    {sdp, "unittest-1.sdp"} => {15, {bad_attribute, <<"ice-ufrag">>}},
    {sdp, "unittest-2.sdp"} => {9, {bad_attribute, <<"ice-ufrag">>}},
    {sdp, "unittest-8.sdp"} => {15, {bad_attribute, <<"ice-ufrag">>}},
    {sdp, "unittest-9.sdp"} => {15, {bad_attribute, <<"ice-ufrag">>}},
    %% Media sections without the session part (RFC 8866 §5: v= first).
    {sdp, "unittest-3.sdp"} => {1, missing_version},
    {sdp, "unittest-6.sdp"} => {1, missing_version},
    {sdp, "unittest-7.sdp"} => {1, missing_version},
    %% RFC 8866 §5: every line is <type>=<value>; this one ends with an
    %% empty line.
    {sdp, "55.sdp"} => {8, empty_line},
    %% RFC 3489 message without the magic cookie (RFC 8489 §5).
    {stun, "9.stun"} => bad_magic_cookie,
    %% RESERVATION-TOKEN (0x0022) is 8 bytes (RFC 8656 §18.9), here 18.
    {stun, "validator-crash-1.stun"} => {bad_attribute, 16#22},
    %% RFC 5104 §4.3.1.2: a FIR carries one or more entries.
    {rtcp, "13.rtcp"} => {bad_packet, 206, empty_fir},
    %% REMB without the SSRC count, exponent and mantissa.
    {rtcp, "16.rtcp"} => {bad_packet, 206, bad_remb},
    {rtcp, "34.rtcp"} => {bad_packet, 206, bad_remb},
    %% RFC 3550 §6.5: an SDES chunk ends with a null item; the last one
    %% is cut.
    {rtcp, "25.rtcp"} => {bad_packet, 202, truncated},
    {rtcp, "35.rtcp"} => {bad_packet, 202, truncated},
    {rtcp, "9.rtcp"} => {bad_packet, 202, truncated},
    %% RFC 4585 §6.1: feedback carries the sender and media SSRC.
    {rtcp, "27.rtcp"} => {bad_packet, 205, truncated},
    {rtcp, "56.rtcp"} => {bad_packet, 206, truncated},
    %% BYE with a count of 2 and one SSRC (RFC 3550 §6.6).
    {rtcp, "32.rtcp"} => {bad_packet, 203, truncated},
    %% RFC 4585 §6.3.2: an SLI carries one or more entries.
    {rtcp, "39.rtcp"} => {bad_packet, 206, empty_sli},
    %% RFC 3550 §A.2: length, version and padding checks.
    {rtcp, "37.rtcp"} => bad_padding,
    {rtcp, "66.rtcp"} => bad_padding,
    {rtcp, "42.rtcp"} => truncated,
    {rtcp, "55.rtcp"} => truncated,
    {rtcp, "47.rtcp"} => bad_version,
    {rtcp, "62.rtcp"} => bad_version,
    %% Fuzzer output with version 0 or 3 (RFC 3550 §5.1).
    {rtp, "rtp-5"} => bad_version,
    {rtp, "rtp-6"} => bad_version,
    {rtp, "rtp-7"} => bad_version,
    {rtp, "rtp-8"} => bad_version,
    %% Captures cut short: the DATA chunk announces 57 and 43 bytes, 16
    %% are left (RFC 9260 §3.2).
    {'sctp-packet', "cookie-echo-data.bin"} => {bad_chunk, 0},
    {'sctp-packet', "cookie-echo-data-data.bin"} => {bad_chunk, 0},
    %% NAL unit type 0 is unspecified (RFC 6184 §5.4, Table 1).
    {h264, "h264-0"} => {bad_nal_type, 0},
    {h264, "h264-1"} => {bad_nal_type, 0}
}).

verdict_test_() ->
    [{lists:flatten(io_lib:format("~s/~s", [K, N])), fun() -> check_verdict(K, N, B) end} || {K, N, B} <- files()].

check_verdict(Kind, Name, Bin) ->
    Got = verdict(decode(Kind, Bin)),
    case {maps:find(Kind, ?ALL_REJECTED), maps:find({Kind, Name}, ?REJECTED)} of
        {{ok, any}, _} -> ?assertMatch({error, _}, Got);
        {{ok, Reason}, _} -> ?assertEqual({error, Reason}, Got);
        {error, {ok, Reason}} -> ?assertEqual({error, Reason}, Got);
        {error, error} -> ?assertEqual(ok, Got)
    end.

verdict({ok, _}) -> ok;
verdict({ok, _, _}) -> ok;
verdict({error, R}) -> {error, R}.

decode(sdp, B) -> webrtc_sdp:parse(B);
decode(stun, B) -> webrtc_stun:decode(B);
decode('stun-response', B) -> webrtc_stun:decode(B);
decode(rtcp, B) -> webrtc_rtcp:decode(B);
decode(rtp, B) -> webrtc_rtp:decode(B, #{extensions => parse});
decode('sctp-packet', B) -> webrtc_sctp_chunk:decode(B);
decode(mdns, B) -> webrtc_mdns_msg:decode(B);
decode(h264, B) -> webrtc_rtp_h264:depacketize(B);
decode(av1, B) -> webrtc_rtp_av1:aggregation_header(B).

%% Every file through every consumer of its kind, and through the
%% payload parsers whatever its kind: nothing raises.
never_raise_test_() ->
    [{lists:flatten(io_lib:format("~s/~s", [K, N])), fun() -> lists:foreach(fun(F) -> F(B) end, consumers(K)) end}
     || {K, N, B} <- files()].

consumers(sdp) -> [fun webrtc_sdp:parse/1, fun jsep_remote/1];
consumers(K) when K =:= stun; K =:= 'stun-response' ->
    [fun webrtc_stun:decode/1, fun(B) -> webrtc_stun:check_integrity(B, <<"key">>) end | payload()];
consumers(rtcp) -> [fun webrtc_rtcp:decode/1 | payload()];
consumers(rtp) ->
    [fun webrtc_rtp:decode/1, fun(B) -> webrtc_rtp:decode(B, #{extensions => parse}) end,
     %% Some libwebrtc samples start with a byte choosing extensions.
     fun(<<_, B/binary>>) -> webrtc_rtp:decode(B, #{extensions => parse}); (_) -> ok end,
     fun rtp_payload/1 | payload()];
consumers('sctp-packet') ->
    [fun webrtc_sctp_chunk:decode/1, fun sctp_engine/1, fun(B) -> sctp_engine(fix_checksum(B)) end];
consumers(mdns) -> [fun webrtc_mdns_msg:decode/1, fun mdns_resolver/1, fun mdns_responder/1];
consumers(K) when K =:= h264; K =:= av1 -> [fun h264_reassembly/1, fun av1_assembly/1, fun frame_assembly/1 | payload()].

payload() ->
    [fun webrtc_rtp_h264:depacketize/1, fun webrtc_rtp_av1:aggregation_header/1, fun webrtc_rtp_av1:is_keyframe/1,
     fun webrtc_rtp_vp8:parse/1, fun webrtc_rtp_vp8:is_keyframe/1, fun webrtc_rtp_vp9:parse/1,
     fun webrtc_rtp_vp9:is_keyframe/1, fun webrtc_rtp_opus:depacketize/1, fun webrtc_rtp_vp8:frame_size/1,
     fun webrtc_rtp_vp9:frame_size/1, fun webrtc_rtp_vp9:parse_payload/1, fun webrtc_rtp_av1:frame_size/1,
     fun webrtc_rtp_av1:obus/1, fun webrtc_rtp_h264:sps_size/1, fun(B) -> webrtc_rtp_av1:depacketize([B]) end].

rtp_payload(B) ->
    case webrtc_rtp:decode(B) of
        {ok, #rtp{payload = P}} -> [F(P) || F <- payload()];
        _ -> ok
    end.

%% A complete description goes on to JSEP as a remote offer.
jsep_remote(B) ->
    case webrtc_sdp:parse(B) of
        {ok, Sdp} ->
            J = webrtc_jsep:new(#{ice_ufrag => <<"abcd">>, ice_pwd => <<"abcdefghijklmnopqrstuv">>,
                                  fingerprints => [{sha256, <<0:256>>}]}),
            _ = webrtc_jsep:set_remote_description(offer, Sdp, J),
            _ = webrtc_jsep:set_remote_description(answer, Sdp, J);
        _ ->
            ok
    end.

%% Packets go to an engine waiting for an association.
sctp_engine(B) ->
    A = webrtc_sctp_assoc:new(#{random_seed => 1, heartbeat_interval => infinity, cookie_secret => <<"secret">>}),
    _ = webrtc_sctp_assoc:handle_packet(B, 0, A),
    {A1, _} = webrtc_sctp_assoc:connect(0, A),
    _ = webrtc_sctp_assoc:handle_packet(B, 10, A1).

mdns_resolver(B) ->
    {R, _} = webrtc_mdns_resolver:resolve(<<"a.local">>, 0, webrtc_mdns_resolver:new(#{})),
    _ = webrtc_mdns_resolver:handle_packet(multicast, B, 0, R).

mdns_responder(B) ->
    {ok, _, R} = webrtc_mdns_responder:register({127, 0, 0, 1}, webrtc_mdns_responder:new(#{})),
    _ = webrtc_mdns_responder:handle_query({{127, 0, 0, 1}, 5353}, 5353, B, 0, R).

%% FU-A reassembly over the file cut into payloads.
h264_reassembly(B) ->
    Parts = [P || P <- binary:split(B, <<0, 0, 1>>, [global]), P =/= <<>>],
    lists:foldl(fun({Seq, P}, D) -> element(3, webrtc_rtp_h264:depacketizer_push(Seq, P, D)) end,
                webrtc_rtp_h264:depacketizer_new(), lists:enumerate(Parts)).

%% libwebrtc's AV1 assemble-frame fuzzer cuts its input into payloads,
%% each after a 16 bit little endian size taken modulo 1200.
fuzz_payloads(<<Size:16/little, Rest/binary>>) ->
    N = min(Size rem 1200, byte_size(Rest)),
    <<P:N/binary, Rest1/binary>> = Rest,
    [P | fuzz_payloads(Rest1)];
fuzz_payloads(_) ->
    [].

av1_assembly(B) ->
    webrtc_rtp_av1:depacketize(fuzz_payloads(B)).

%% The same payloads as the packets of one frame, for every format.
frame_assembly(B) ->
    Pkts = lists:enumerate(fuzz_payloads(B)),
    [webrtc_frame_codec:assemble(C, Pkts, 1, #{}) || C <- [vp8, vp9, h264, av1, video]],
    [webrtc_frame_codec:packet(C, P) || C <- [vp8, vp9, h264, av1], {_, P} <- Pkts],
    Fb = webrtc_frame_buffer:new(#{codecs => [#{pt => 96, name => <<"H264">>}, #{pt => 97, name => <<"AV1">>},
                                              #{pt => 98, name => <<"VP9">>}, #{pt => 99, name => <<"VP8">>}]}),
    lists:foldl(fun({I, P}, F) ->
                    Rtp = #rtp{pt = 96 + I rem 4, seq = I, ts = I div 3, ssrc = 1, marker = I rem 3 =:= 0, payload = P},
                    element(2, webrtc_frame_buffer:push(Rtp, I, #{}, F))
                end, Fb, Pkts).

%% The captures carry their peer's checksum; recompute it so the engine
%% looks past the CRC check (RFC 9260 Appendix A).
fix_checksum(<<Hdr:8/binary, _:32, Rest/binary>>) ->
    Crc = webrtc_sctp_crc32c:crc32c([Hdr, <<0:32>>, Rest]),
    <<Hdr/binary, Crc:32/little, Rest/binary>>;
fix_checksum(B) ->
    B.
