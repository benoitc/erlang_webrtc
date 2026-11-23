%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
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
%% keep each call short, or run the codec in a process of your own and
%% deliver later (see "Asynchronous plugins" below).
%%
%% `Stats' are W3C members of the stream (`framesDecoded',
%% `totalDecodeTime', `keyFramesEncoded', ...): counters add up across
%% calls, the others replace the previous value, as with
%% `webrtc:report_media_stats/4'. `info/1' gives
%% `decoderImplementation' or `encoderImplementation'.
%%
%% What a decoder sends to the remote encoder: `decode/2' may return
%% `{ok, Outs, Stats, State, Feedback}'.
%% <ul>
%% <li>`keyframe_request' in `Feedback' asks for a key frame (PLI or
%%     FIR, whichever the stream negotiated), always.</li>
%% <li>`{slice_loss, [{First, Number, PictureId}]}' and
%%     `{reference_picture, Pt, Bits}' are loss indications (RFC 8834
%%     §5.1.3, §5.1.4), sent when the transceiver negotiated `nack sli'
%%     or `nack rpsi'.</li>
%% </ul>
%%
%% What an encoder hears, through two optional callbacks:
%% <ul>
%% <li>`feedback/2' gets what the remote decoder reports about the stream
%%     it encodes, `{slice_loss, Entries}' or `{reference_picture, Pt,
%%     Bits}', to repair the slices or change its reference picture.</li>
%% <li>`control/2' gets `keyframe_request' when the peer asks for a key
%%     frame, `{max_bitrate, Bps | infinity}' when the peer's TMMBR limit
%%     for the stream changes (the payload bit rate it allows), and
%%     `{target_bitrate, Bps}' when the application sets one with
%%     `webrtc:set_target_bitrate/3'. The bit rates set before the
%%     encoder starts reach it when it starts. Ignore the events you do
%%     not know: the list may grow. The owner still gets its own
%%     `{keyframe_request, Mid}' and `{max_bitrate, Mid, Bps}' events.</li>
%% </ul>
%%
%% Errors:
%% <ul>
%% <li>`{error, Reason, State}' from `decode/2', `encode/2', `control/2'
%%     or `feedback/2' is recoverable: that frame or picture is lost, the
%%     plugin goes on with `State'. A decode error counts one
%%     `framesDropped'; an encode error makes `webrtc:send_media/3'
%%     return `{error, {encode, Reason}}'.</li>
%% <li>`{error, Reason}' or a raise turns the plugin off for that
%%     transceiver: the owner gets `{codec_plugin_error, Mid, Reason}'
%%     and frames keep coming.</li>
%% </ul>
%%
%% The optional `terminate/1' runs once when the plugin's stream ends:
%% the receive stream is forgotten (BYE, idle), its transceiver goes in
%% a renegotiation, the plugin is turned off, or the connection closes.
%% Free native resources there. It runs in the transport process, also
%% while the connection closes: keep it short. A raise in it is ignored.
%%
%% A plugin may report `framesDropped' for the frames it could not
%% decode; it adds to those the frame buffer dropped.
%%
%% Asynchronous plugins: a plugin that exports `init/4' instead of
%% `init/3' gets a `handle()'. Its `decode/2' and `encode/2' may return
%% `{ok, [], Stats, State}' at once and hand the work to a process of its
%% own, which delivers later with `decoded/3', `encoded/3' and
%% `decoder_feedback/2'. These never wait. A delivery after the
%% instance's stream ended, it was turned off, or the connection closed
%% is dropped and counted (`codec_deliveries_stale'), a malformed one
%% too (`codec_deliveries_rejected'). Keep a bounded number of frames in
%% flight, and stop the worker in `terminate/1'.
-module(webrtc_media_codec).

-export([handle/4, decoded/3, encoded/3, decoder_feedback/2]).

-export_type([codec/0, frame/0, control_event/0, handle/0]).

%% Where an asynchronous plugin delivers: one plugin instance on one
%% stream of one transport. Opaque.
-opaque handle() :: {webrtc_codec, pid(), in | out, term(), reference()}.

%% The negotiated codec: `name', `clock_rate', `channels', `fmtp'.
-type codec() :: map().

%% What decode/2 gets and encode/2 returns: `data', `timestamp' (RTP
%% clock), `keyframe', and for video `width' and `height' when known.
-type frame() :: #{data := binary(), timestamp := 0..16#FFFFFFFF, keyframe := boolean(), atom() => term()}.

%% What control/2 gets (more may come: ignore the others).
-type control_event() :: keyframe_request | {max_bitrate, non_neg_integer() | infinity} | {target_bitrate, non_neg_integer()}.

-callback init(audio | video, codec(), Opts :: term()) -> {ok, State :: term()} | {error, term()}.

-callback decode(frame(), State :: term()) ->
    {ok, [Out :: term()], Stats :: map(), State :: term()}
    | {ok, [Out :: term()], Stats :: map(), State :: term(), [webrtc_media_fb:indication() | keyframe_request]}
    | {error, Reason :: term(), State :: term()}
    | {error, term()}.

-callback encode(Raw :: term(), State :: term()) ->
    {ok, [frame()], Stats :: map(), State :: term()} | {error, Reason :: term(), State :: term()} | {error, term()}.

-callback info(State :: term()) -> #{implementation => binary(), power_efficient => boolean()}.

-callback feedback(webrtc_media_fb:indication(), State :: term()) ->
    {ok, State :: term()} | {error, Reason :: term(), State :: term()} | {error, term()}.

-callback control(control_event(), State :: term()) ->
    {ok, State :: term()} | {error, Reason :: term(), State :: term()} | {error, term()}.

-callback terminate(State :: term()) -> term().

%% Called instead of init/3 when the plugin exports it: `Handle' lets
%% the plugin's own processes deliver results later.
-callback init(audio | video, codec(), Opts :: term(), handle()) -> {ok, State :: term()} | {error, term()}.

-optional_callbacks([init/3, init/4, feedback/2, control/2, terminate/1]).

%% @private The handle of a plugin instance, made when it starts.
-spec handle(pid(), in | out, term(), reference()) -> handle().
handle(Transport, Dir, Key, Ref) ->
    {webrtc_codec, Transport, Dir, Key, Ref}.

%% @doc Deliver a decoder's outputs and statistics, from any process:
%% each output reaches the owner as `{decoded, Mid, Out}', as if
%% decode/2 had returned it. Never waits; dropped when the instance no
%% longer runs (its stream ended, it was turned off, the connection
%% closed).
-spec decoded(handle(), [term()], map()) -> ok.
decoded({webrtc_codec, T, in, Key, Ref}, Outs, Stats) ->
    gen_server:cast(T, {codec_delivery, in, Key, Ref, {decoded, Outs, Stats}}).

%% @doc Deliver an encoder's frames and statistics, from any process:
%% the frames are sent as if encode/2 had returned them. Never waits.
-spec encoded(handle(), [frame()], map()) -> ok.
encoded({webrtc_codec, T, out, Key, Ref}, Frames, Stats) ->
    gen_server:cast(T, {codec_delivery, out, Key, Ref, {encoded, Frames, Stats}}).

%% @doc Deliver what a decoder found after decode/2 returned, as its
%% fifth element would: `keyframe_request', slice loss, reference
%% picture. Never waits.
-spec decoder_feedback(handle(), [webrtc_media_fb:indication() | keyframe_request]) -> ok.
decoder_feedback({webrtc_codec, T, in, Key, Ref}, Feedback) ->
    gen_server:cast(T, {codec_delivery, in, Key, Ref, {decoder_feedback, Feedback}}).
