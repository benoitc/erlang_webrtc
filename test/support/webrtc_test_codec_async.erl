%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% An asynchronous codec plugin for the tests: init/4 starts a worker
%% that does the work and delivers with webrtc_media_codec:decoded/3,
%% encoded/3 and decoder_feedback/2; decode/2 and encode/2 only hand it
%% the frame. Options: `delay' (ms per call, default 0), `feedback' (a
%% list the worker delivers with decoder_feedback/2 after the first
%% frame), `notify' (a pid told `{async_worker, Pid}' and
%% `{async_terminate, Pid}').
-module(webrtc_test_codec_async).
-behaviour(webrtc_media_codec).

-export([init/4, decode/2, encode/2, info/1, terminate/1]).

init(_Kind, #{name := Name}, Opts, Handle) ->
    Delay = maps:get(delay, Opts, 0),
    Feedback = maps:get(feedback, Opts, []),
    W = spawn(fun() -> worker(Handle, Delay, Feedback, 0) end),
    tell(Opts, {async_worker, W}),
    {ok, #{worker => W, codec => Name, opts => Opts}}.

decode(Frame, #{worker := W} = St) ->
    W ! {decode, Frame},
    {ok, [], #{}, St}.

encode(Raw, #{worker := W} = St) ->
    W ! {encode, Raw},
    {ok, [], #{}, St}.

info(#{codec := C}) ->
    #{implementation => <<"async ", C/binary>>}.

terminate(#{worker := W, opts := Opts}) ->
    tell(Opts, {async_terminate, W}),
    exit(W, kill).

worker(H, Delay, Feedback, N) ->
    receive
        {decode, #{data := D}} ->
            timer:sleep(Delay),
            webrtc_media_codec:decoded(H, [{size, byte_size(D)}], #{framesDecoded => 1}),
            case {N, Feedback} of
                {0, [_ | _]} -> webrtc_media_codec:decoder_feedback(H, Feedback);
                _ -> ok
            end,
            worker(H, Delay, Feedback, N + 1);
        {encode, {frame, D, K, Ts}} ->
            timer:sleep(Delay),
            webrtc_media_codec:encoded(H, [#{data => D, keyframe => K, timestamp => Ts}], #{framesEncoded => 1}),
            worker(H, Delay, Feedback, N + 1)
    end.

tell(#{notify := Pid}, Msg) when is_pid(Pid) -> Pid ! Msg;
tell(_, _) -> ok.
