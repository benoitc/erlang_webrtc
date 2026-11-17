%% @doc A codec plugin decodes the frames a transceiver receives and
%% encodes what the application sends on it, and reports the W3C
%% decoder and encoder statistics. This library stays pure Erlang; a
%% plugin is where native code (FFmpeg, libvpx, Opus) comes in, in a
%% separate package.
%%
%% Set it on a transceiver that delivers frames:
%%
%% ```
%% webrtc:add_transceiver(Pc, video, #{frames => true, codec_plugin => {my_codec, Opts}})
%% '''
%%
%% Each frame received goes to `decode/2'; every output comes as
%% `{webrtc, Pc, {decoded, Mid, Out}}', after the `{frame, Mid, Frame}'
%% event. `webrtc:send_media/3' hands raw media to `encode/2' and sends
%% the frames it returns. The plugin runs in the transport process:
%% keep each call short, or hand the work to a process of your own.
%%
%% `Stats' are W3C members of the stream (`framesDecoded',
%% `totalDecodeTime', `keyFramesEncoded', ...): counters add up across
%% calls, the others replace the previous value, as with
%% `webrtc:report_media_stats/4'. `info/1' gives
%% `decoderImplementation' or `encoderImplementation'.
%%
%% A plugin that raises or returns an error is turned off for that
%% transceiver and the owner gets `{codec_plugin_error, Mid, Reason}';
%% frames keep coming.
-module(webrtc_media_codec).

-export_type([codec/0, frame/0]).

%% The negotiated codec: `name', `clock_rate', `channels', `fmtp'.
-type codec() :: map().

%% What decode/2 gets and encode/2 returns: `data', `timestamp' (RTP
%% clock), `keyframe', and for video `width' and `height' when known.
-type frame() :: #{data := binary(), timestamp := 0..16#FFFFFFFF, keyframe := boolean(), atom() => term()}.

-callback init(audio | video, codec(), Opts :: term()) -> {ok, State :: term()} | {error, term()}.

-callback decode(frame(), State :: term()) ->
    {ok, [Out :: term()], Stats :: map(), State :: term()} | {error, term()}.

-callback encode(Raw :: term(), State :: term()) ->
    {ok, [frame()], Stats :: map(), State :: term()} | {error, term()}.

-callback info(State :: term()) -> #{implementation => binary(), power_efficient => boolean()}.
