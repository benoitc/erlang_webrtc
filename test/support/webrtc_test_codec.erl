%% A codec plugin (webrtc_media_codec) for the tests: it decodes a
%% frame into its size and "encodes" `{frame, Data, Keyframe}' into
%% that frame, with fixed statistics. `#{crash => N}' raises at the Nth
%% call. `#{loss => Feedback}' makes every decode report those loss
%% indications; `#{notify => Pid}' sends `{codec_feedback, Fb}' to Pid
%% for each indication the remote decoder sends.
-module(webrtc_test_codec).
-behaviour(webrtc_media_codec).

-export([init/3, decode/2, encode/2, info/1, feedback/2]).

init(Kind, #{name := Name}, Opts) ->
    {ok, #{kind => Kind, codec => Name, calls => 0, crash => maps:get(crash, Opts, infinity),
           loss => maps:get(loss, Opts, []), notify => maps:get(notify, Opts, undefined)}}.

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

encode({frame, D, K, Ts}, St) ->
    St1 = call(St),
    {ok, [#{data => D, keyframe => K, timestamp => Ts}], #{framesEncoded => 1, keyFramesEncoded => key(K),
                                                            qualityLimitationReason => <<"none">>}, St1}.

info(#{codec := C}) ->
    #{implementation => <<"test ", C/binary>>, power_efficient => false}.

call(#{calls := N, crash := N}) -> error(crash);
call(#{calls := N} = St) -> St#{calls => N + 1}.

key(true) -> 1;
key(false) -> 0.
