%% @doc Opus RTP payload format (RFC 7587).
%%
%% There is nothing to packetize: each RTP payload is exactly one Opus
%% packet (RFC 6716 §3), which may itself hold one or more frames, and
%% Opus packets are never fragmented (RFC 7587 §4.2). The RTP clock rate
%% is always 48000 Hz whatever the audio bandwidth (§4.1), and the
%% timestamp advances by the packet duration in 48 kHz samples.
%%
%% `toc/1' and `duration/1' read the table-of-contents byte and the frame
%% count of RFC 6716 §3.1 and §3.2 to compute the duration of a packet
%% without decoding it, which is what a sender needs to advance the RTP
%% timestamp.
-module(webrtc_rtp_opus).

-export([clock_rate/0, toc/1, duration/1, packetize/1, depacketize/1]).

-export_type([toc/0]).

-type toc() :: #{
    config := 0..31,
    mode := silk | hybrid | celt,
    stereo := boolean(),
    code := 0..3,
    frame_samples := pos_integer()
}.

-spec clock_rate() -> 48000.
clock_rate() ->
    48000.

%% @doc One Opus packet per RTP payload.
-spec packetize(binary()) -> [binary()].
packetize(OpusPacket) when is_binary(OpusPacket), byte_size(OpusPacket) > 0 ->
    [OpusPacket].

-spec depacketize(binary()) -> {ok, binary()} | {error, empty}.
depacketize(<<>>) -> {error, empty};
depacketize(Payload) -> {ok, Payload}.

%% @doc Parse the TOC byte (RFC 6716 §3.1).
-spec toc(binary()) -> {ok, toc()} | {error, empty}.
toc(<<Config:5, S:1, Code:2, _/binary>>) ->
    {ok, #{
        config => Config,
        mode => mode(Config),
        stereo => S =:= 1,
        code => Code,
        frame_samples => frame_samples(Config)
    }};
toc(_) ->
    {error, empty}.

mode(C) when C =< 11 -> silk;
mode(C) when C =< 15 -> hybrid;
mode(_) -> celt.

%% Frame duration in 48 kHz samples (RFC 6716 §3.1, Table 2).
frame_samples(C) when C =< 11 -> element((C band 3) + 1, {480, 960, 1920, 2880});
frame_samples(C) when C =< 15 -> element((C band 1) + 1, {480, 960});
frame_samples(C) -> element((C band 3) + 1, {120, 240, 480, 960}).

%% @doc Duration of an Opus packet in 48 kHz samples. Code 3 packets
%% carry the frame count (1..48) in the second byte (§3.2.5); a packet
%% longer than 120 ms is invalid (§3.4 [R5]).
-spec duration(binary()) ->
    {ok, pos_integer()} | {error, empty | truncated | too_long | bad_frame_count}.
duration(Payload) ->
    case toc(Payload) of
        {ok, #{code := Code, frame_samples := Fs}} ->
            case frames(Code, Payload) of
                {ok, N} when N * Fs =< 5760 -> {ok, N * Fs};
                {ok, _} -> {error, too_long};
                Err -> Err
            end;
        Err ->
            Err
    end.

frames(0, _) -> {ok, 1};
frames(1, _) -> {ok, 2};
frames(2, _) -> {ok, 2};
frames(3, <<_, _:2, 0:6, _/binary>>) -> {error, bad_frame_count};
frames(3, <<_, _:2, M:6, _/binary>>) -> {ok, M};
frames(3, _) -> {error, truncated}.
