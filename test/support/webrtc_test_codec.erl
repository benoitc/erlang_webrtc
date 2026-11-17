%% A codec plugin (webrtc_media_codec) for the tests: it decodes a
%% frame into its size and "encodes" `{frame, Data, Keyframe}' into
%% that frame, with fixed statistics. `#{crash => N}' raises at the Nth
%% call.
-module(webrtc_test_codec).
-behaviour(webrtc_media_codec).

-export([init/3, decode/2, encode/2, info/1]).

init(Kind, #{name := Name}, Opts) ->
    {ok, #{kind => Kind, codec => Name, calls => 0, crash => maps:get(crash, Opts, infinity)}}.

decode(#{data := D, keyframe := K}, St) ->
    St1 = call(St),
    {ok, [{size, byte_size(D)}], #{framesDecoded => 1, keyFramesDecoded => key(K), totalDecodeTime => 0.001}, St1}.

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
