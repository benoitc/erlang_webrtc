%% @doc RTP header extensions (RFC 8285) and the typed values carried in
%% them.
%%
%% `decode/2' takes the profile and data of an RTP header extension and
%% returns `[{Id, Data}]' in wire order. Both the one-byte form (profile
%% 0xBEDE, ids 1..14, 1..16 data bytes) and the two-byte form (profile
%% 0x100X, ids 1..255, 0..255 data bytes) are handled; zero bytes between
%% elements are padding. In the one-byte form id 15 stops processing and
%% only the elements before it are returned (RFC 8285 §4.2).
%%
%% `encode/1' picks the one-byte form when every element fits and the
%% two-byte form otherwise. Using the two-byte form for some packets of a
%% stream and the one-byte form for others is only allowed when
%% `a=extmap-allow-mixed' was negotiated (RFC 8285 §6); `encode/2' with
%% `#{form => one_byte}' forces the one-byte form and fails when an
%% element does not fit.
%%
%% Typed helpers encode and decode element data for:
%% abs-send-time, transport-wide-cc, ssrc-audio-level (RFC 6464), the
%% SDES items mid / rid / repaired-rid (RFC 9143, RFC 8852), toffset
%% (RFC 5450), video-orientation (3GPP TS 26.114) and playout-delay.
-module(webrtc_rtp_ext).

-export([
    decode/2,
    encode/1,
    encode/2,
    is_rfc8285/1,
    find/2,
    abs_send_time/1,
    decode_abs_send_time/1,
    abs_send_time_from_ntp/1,
    twcc_seq/1,
    decode_twcc_seq/1,
    audio_level/2,
    decode_audio_level/1,
    sdes/1,
    decode_sdes/1,
    toffset/1,
    decode_toffset/1,
    video_orientation/1,
    decode_video_orientation/1,
    playout_delay/2,
    decode_playout_delay/1
]).

-export_type([element/0, form/0, orientation/0]).

-type element() :: {Id :: 1..255, Data :: binary()}.
-type form() :: auto | one_byte | two_byte.
-type orientation() :: #{
    camera := front | back,
    flip := boolean(),
    rotation := 0 | 90 | 180 | 270
}.

-define(ONE_BYTE, 16#BEDE).

%% @doc True when `Profile' is one of the RFC 8285 profiles.
-spec is_rfc8285(0..65535) -> boolean().
is_rfc8285(?ONE_BYTE) -> true;
is_rfc8285(P) when P bsr 4 =:= 16#100 -> true;
is_rfc8285(_) -> false.

%%====================================================================
%% Element codec
%%====================================================================

-spec decode(0..65535, binary()) -> {ok, [element()]} | {error, term()}.
decode(?ONE_BYTE, Data) ->
    one_byte(Data, []);
decode(P, Data) when P bsr 4 =:= 16#100 ->
    two_byte(Data, []);
decode(P, _) ->
    {error, {not_rfc8285, P}}.

one_byte(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
one_byte(<<0, Rest/binary>>, Acc) ->
    one_byte(Rest, Acc);
one_byte(<<0:4, _:4, _/binary>>, _) ->
    {error, bad_padding};
one_byte(<<15:4, _:4, _/binary>>, Acc) ->
    {ok, lists:reverse(Acc)};
one_byte(<<Id:4, L:4, Rest/binary>>, Acc) ->
    Len = L + 1,
    case Rest of
        <<D:Len/binary, Rest1/binary>> -> one_byte(Rest1, [{Id, D} | Acc]);
        _ -> {error, truncated}
    end.

two_byte(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
two_byte(<<0, Rest/binary>>, Acc) ->
    two_byte(Rest, Acc);
two_byte(<<Id, Len, Rest/binary>>, Acc) ->
    case Rest of
        <<D:Len/binary, Rest1/binary>> -> two_byte(Rest1, [{Id, D} | Acc]);
        _ -> {error, truncated}
    end;
two_byte(<<_>>, _) ->
    {error, truncated}.

%% @doc Encode elements, choosing the form automatically.
-spec encode([element()]) -> {0..65535, binary()}.
encode(Elems) ->
    encode(Elems, #{}).

%% @doc Encode elements into `{Profile, Data}', `Data' padded with zero
%% bytes to a multiple of 4. Raises `badarg' when an element does not
%% fit the requested form or an id is out of range.
-spec encode([element()], #{form => form(), appbits => 0..15}) -> {0..65535, binary()}.
encode(Elems, Opts) ->
    _ = [error(badarg) || E <- Elems, not valid_two(E)],
    Form =
        case maps:get(form, Opts, auto) of
            auto ->
                case lists:all(fun fits_one/1, Elems) of
                    true -> one_byte;
                    false -> two_byte
                end;
            F ->
                F
        end,
    case Form of
        one_byte ->
            _ = [error(badarg) || E <- Elems, not fits_one(E)],
            Body = <<<<Id:4, (byte_size(D) - 1):4, D/binary>> || {Id, D} <- Elems>>,
            {?ONE_BYTE, pad4(Body)};
        two_byte ->
            AppBits = maps:get(appbits, Opts, 0),
            (is_integer(AppBits) andalso AppBits >= 0 andalso AppBits =< 15) orelse
                error(badarg),
            Body = <<<<Id, (byte_size(D)), D/binary>> || {Id, D} <- Elems>>,
            {16#1000 bor AppBits, pad4(Body)}
    end.

valid_two({Id, D}) when is_integer(Id), Id >= 1, Id =< 255, is_binary(D) ->
    byte_size(D) =< 255;
valid_two(_) ->
    false.

fits_one({Id, D}) ->
    Id =< 14 andalso byte_size(D) >= 1 andalso byte_size(D) =< 16.

pad4(B) ->
    case byte_size(B) rem 4 of
        0 -> B;
        R -> <<B/binary, 0:((4 - R) * 8)>>
    end.

%% @doc Data of the first element with `Id'.
-spec find(1..255, [element()]) -> {ok, binary()} | error.
find(Id, Elems) ->
    case lists:keyfind(Id, 1, Elems) of
        {_, D} -> {ok, D};
        false -> error
    end.

%%====================================================================
%% Typed values
%%====================================================================

%% abs-send-time (http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time):
%% 24 bits, 6.18 fixed point seconds, the middle bits of an NTP time.

%% @doc Encode an abs-send-time value given as 24-bit 6.18 fixed point.
-spec abs_send_time(0..16#FFFFFF) -> <<_:24>>.
abs_send_time(V) when is_integer(V), V >= 0, V =< 16#FFFFFF ->
    <<V:24>>.

-spec decode_abs_send_time(binary()) -> {ok, 0..16#FFFFFF} | {error, bad_length}.
decode_abs_send_time(<<V:24>>) -> {ok, V};
decode_abs_send_time(_) -> {error, bad_length}.

%% @doc 6.18 fixed point abs-send-time from a 64-bit NTP timestamp.
-spec abs_send_time_from_ntp(0..16#FFFFFFFFFFFFFFFF) -> 0..16#FFFFFF.
abs_send_time_from_ntp(Ntp) ->
    (Ntp bsr 14) band 16#FFFFFF.

%% transport-wide-cc (draft-holmer-rmcat-transport-wide-cc-extensions-01
%% §2): 16-bit transport-wide sequence number.

-spec twcc_seq(0..65535) -> <<_:16>>.
twcc_seq(S) when is_integer(S), S >= 0, S =< 16#FFFF ->
    <<S:16>>.

-spec decode_twcc_seq(binary()) -> {ok, 0..65535} | {error, bad_length}.
decode_twcc_seq(<<S:16>>) -> {ok, S};
decode_twcc_seq(_) -> {error, bad_length}.

%% ssrc-audio-level (RFC 6464 §3): V flag and level in -dBov (0..127).

-spec audio_level(boolean(), 0..127) -> <<_:8>>.
audio_level(Voice, Level) when is_boolean(Voice), is_integer(Level), Level >= 0, Level =< 127 ->
    V =
        case Voice of
            true -> 1;
            false -> 0
        end,
    <<V:1, Level:7>>.

%% @doc Decode an audio level. RFC 6464 allows the two-byte form to
%% carry padding after the level byte; only the first byte is read.
-spec decode_audio_level(binary()) ->
    {ok, {Voice :: boolean(), Level :: 0..127}} | {error, bad_length}.
decode_audio_level(<<V:1, Level:7, _/binary>>) -> {ok, {V =:= 1, Level}};
decode_audio_level(_) -> {error, bad_length}.

%% SDES items carried as header extensions (RFC 7941): mid (RFC 9143
%% §15.2), rtp-stream-id and repaired-rtp-stream-id (RFC 8852 §3).
%% The value is the UTF-8 text, not zero terminated.

-spec sdes(binary()) -> binary().
sdes(Text) when is_binary(Text), byte_size(Text) >= 1, byte_size(Text) =< 255 ->
    Text.

%% @doc Decode a mid / rid value. Some senders pad the value with zero
%% bytes; trailing zeros are removed.
-spec decode_sdes(binary()) -> {ok, binary()} | {error, empty}.
decode_sdes(Bin) ->
    case strip_zeros(Bin) of
        <<>> -> {error, empty};
        T -> {ok, T}
    end.

strip_zeros(<<>>) ->
    <<>>;
strip_zeros(Bin) ->
    case binary:last(Bin) of
        0 -> strip_zeros(binary:part(Bin, 0, byte_size(Bin) - 1));
        _ -> Bin
    end.

%% toffset (RFC 5450 §3): 24-bit signed transmission time offset.

-spec toffset(-16#800000..16#7FFFFF) -> <<_:24>>.
toffset(V) when is_integer(V), V >= -16#800000, V =< 16#7FFFFF ->
    <<V:24/signed>>.

-spec decode_toffset(binary()) -> {ok, integer()} | {error, bad_length}.
decode_toffset(<<V:24/signed>>) -> {ok, V};
decode_toffset(_) -> {error, bad_length}.

%% video-orientation (urn:3gpp:video-orientation, 3GPP TS 26.114
%% §7.4.5): one byte 0 0 0 0 C F R1 R0.

-spec video_orientation(orientation()) -> <<_:8>>.
video_orientation(#{camera := Cam, flip := Flip, rotation := Rot}) ->
    C =
        case Cam of
            front -> 0;
            back -> 1
        end,
    F =
        case Flip of
            true -> 1;
            false -> 0
        end,
    R =
        case Rot of
            0 -> 0;
            90 -> 1;
            180 -> 2;
            270 -> 3
        end,
    <<0:4, C:1, F:1, R:2>>.

-spec decode_video_orientation(binary()) -> {ok, orientation()} | {error, bad_length}.
decode_video_orientation(<<_:4, C:1, F:1, R:2, _/binary>>) ->
    {ok, #{
        camera =>
            case C of
                0 -> front;
                1 -> back
            end,
        flip => F =:= 1,
        rotation => R * 90
    }};
decode_video_orientation(_) ->
    {error, bad_length}.

%% playout-delay (http://www.webrtc.org/experiments/rtp-hdrext/playout-delay):
%% 12-bit min and max delay in units of 10 ms.

%% @doc Encode a playout delay given in milliseconds (rounded down to a
%% multiple of 10, at most 40950 ms).
-spec playout_delay(0..40950, 0..40950) -> <<_:24>>.
playout_delay(Min, Max) when
    is_integer(Min), is_integer(Max), Min >= 0, Max >= Min, Max =< 40950
->
    <<(Min div 10):12, (Max div 10):12>>.

-spec decode_playout_delay(binary()) ->
    {ok, {MinMs :: non_neg_integer(), MaxMs :: non_neg_integer()}} | {error, bad_length}.
decode_playout_delay(<<Min:12, Max:12>>) -> {ok, {Min * 10, Max * 10}};
decode_playout_delay(_) -> {error, bad_length}.
