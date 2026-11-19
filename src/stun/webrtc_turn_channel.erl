%% @doc TURN ChannelData framing (RFC 8656 §12.4).
%%
%% A ChannelData message is a 4-byte header (channel number, length of
%% the application data) followed by the data. Over UDP the padding to
%% a multiple of four bytes is optional (§12.5); `encode/2' always adds
%% it and `decode/1' accepts it, ignoring any trailing padding.
-module(webrtc_turn_channel).

-export([encode/2, decode/1, is_channel_data/1, valid_number/1]).

-define(MIN_CHANNEL, 16#4000).
-define(MAX_CHANNEL, 16#4FFF).

%% @doc True for channel numbers a client may bind (0x4000 to 0x4FFF).
-spec valid_number(term()) -> boolean().
valid_number(N) -> is_integer(N) andalso N >= ?MIN_CHANNEL andalso N =< ?MAX_CHANNEL.

-spec encode(16#4000..16#4FFF, binary()) -> binary().
encode(Channel, Data) when Channel >= ?MIN_CHANNEL, Channel =< ?MAX_CHANNEL, byte_size(Data) =< 65535 ->
    Len = byte_size(Data),
    Pad =
        case Len rem 4 of
            0 -> 0;
            R -> 4 - R
        end,
    <<Channel:16, Len:16, Data/binary, 0:(Pad * 8)>>.

%% @doc First byte in 64..79 (RFC 7983 as updated by RFC 9443).
-spec is_channel_data(binary()) -> boolean().
is_channel_data(<<B, _/binary>>) -> B >= 64 andalso B =< 79;
is_channel_data(_) -> false.

%% @doc Decode a ChannelData message received over UDP. A datagram
%% shorter than the claimed length, or a channel number outside the
%% valid range (reserved values 0x5000-0xFFFF included), is rejected.
-spec decode(binary()) ->
    {ok, 16#4000..16#4FFF, binary()} | {error, bad_channel | truncated | not_channel_data}.
decode(<<Ch:16, Len:16, Rest/binary>>) when Ch >= ?MIN_CHANNEL, Ch =< ?MAX_CHANNEL ->
    case Rest of
        <<Data:Len/binary, _/binary>> -> {ok, Ch, Data};
        _ -> {error, truncated}
    end;
decode(<<Ch:16, _:16, _/binary>>) when Ch > ?MAX_CHANNEL, Ch =< 16#7FFF ->
    {error, bad_channel};
decode(_) ->
    {error, not_channel_data}.
