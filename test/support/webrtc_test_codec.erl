%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% A codec plugin (webrtc_media_codec) for the tests: it decodes a
%% frame into its size and "encodes" `{frame, Data, Keyframe}' into
%% that frame, with fixed statistics. `#{crash => N}' raises at the Nth
%% call. `#{loss => Feedback}' makes every decode report those loss
%% indications; `#{notify => Pid}' sends `{codec_feedback, Fb}' to Pid
%% for each indication the remote decoder sends, `{codec_control, Ev}'
%% for each control/2 event and `{codec_terminate, Calls}' when it ends.
%% `#{decode_error => N}' and `#{encode_error => N}' make the Nth call a
%% recoverable error (the plugin stays on); `#{terminate_crash => true}'
%% raises in terminate/1; `#{control_error => true}' makes control/2
%% fail.
-module(webrtc_test_codec).
-behaviour(webrtc_media_codec).

-export([init/3, decode/2, encode/2, info/1, feedback/2, control/2, terminate/1]).

init(Kind, #{name := Name}, Opts) ->
    {ok, #{kind => Kind, codec => Name, calls => 0, crash => maps:get(crash, Opts, infinity),
           loss => maps:get(loss, Opts, []), notify => maps:get(notify, Opts, undefined),
           decode_error => maps:get(decode_error, Opts, infinity), encode_error => maps:get(encode_error, Opts, infinity),
           terminate_crash => maps:get(terminate_crash, Opts, false),
           control_error => maps:get(control_error, Opts, false)}}.

decode(_F, #{calls := N, decode_error := N} = St) ->
    {error, bad_frame, St#{calls => N + 1}};
decode(#{data := D, keyframe := K}, St) ->
    St1 = call(St),
    Stats = #{framesDecoded => 1, keyFramesDecoded => key(K), totalDecodeTime => 0.001},
    case maps:get(loss, St) of
        [] -> {ok, [{size, byte_size(D)}], Stats, St1};
        Loss -> {ok, [{size, byte_size(D)}], Stats, St1, Loss}
    end.

feedback(Fb, #{notify := Pid} = St) when is_pid(Pid) ->
    Pid ! {codec_feedback, Fb},
    {ok, St};
feedback(_Fb, St) ->
    {ok, St}.

encode(_Raw, #{calls := N, encode_error := N} = St) ->
    {error, bad_picture, St#{calls => N + 1}};
encode({frame, D, K, Ts}, St) ->
    St1 = call(St),
    {ok, [#{data => D, keyframe => K, timestamp => Ts}], #{framesEncoded => 1, keyFramesEncoded => key(K),
                                                            qualityLimitationReason => <<"none">>}, St1}.

control(_Ev, #{control_error := true}) ->
    {error, refused};
control(Ev, St) ->
    tell(St, {codec_control, Ev}),
    {ok, St}.

terminate(#{terminate_crash := true}) ->
    error(terminate_crash);
terminate(#{calls := N} = St) ->
    tell(St, {codec_terminate, N}).

tell(#{notify := Pid}, Msg) when is_pid(Pid) -> Pid ! Msg;
tell(_, _) -> ok.

info(#{codec := C}) ->
    #{implementation => <<"test ", C/binary>>, power_efficient => false}.

call(#{calls := N, crash := N}) -> error(crash);
call(#{calls := N} = St) -> St#{calls => N + 1}.

key(true) -> 1;
key(false) -> 0.
