%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Statistics a codec plugin or the application reports
%% (`webrtc:report_media_stats/4'): the W3C members each kind of object
%% takes, and how a report merges into what is kept. Counters add up,
%% the other members replace the previous value; an unknown member or a
%% value of the wrong type is dropped.
-module(webrtc_media_report).

-export([merge/3]).

-export_type([dir/0]).

-type dir() :: inbound | outbound | source | playout.

%% counter: a non-negative number added up; number, string, boolean or
%% map (of numbers): replaced.
members(inbound) ->
    #{
        framesDecoded => counter, keyFramesDecoded => counter, framesRendered => counter, qpSum => counter,
        %% Added to the frame buffer's own count (webrtc_stats).
        framesDropped => counter,
        totalDecodeTime => counter, totalInterFrameDelay => counter, totalSquaredInterFrameDelay => counter,
        pauseCount => counter, totalPausesDuration => counter, freezeCount => counter,
        totalFreezesDuration => counter, totalProcessingDelay => counter, totalSamplesReceived => counter,
        concealedSamples => counter, silentConcealedSamples => counter, concealmentEvents => counter,
        insertedSamplesForDeceleration => counter, removedSamplesForAcceleration => counter,
        totalCorruptionProbability => counter, totalSquaredCorruptionProbability => counter,
        corruptionMeasurements => counter, estimatedPlayoutTimestamp => number,
        decoderImplementation => string, powerEfficientDecoder => boolean
    };
members(outbound) ->
    #{
        framesEncoded => counter, keyFramesEncoded => counter, qpSum => counter, psnrMeasurements => counter,
        totalEncodeTime => counter, totalEncodedBytesTarget => counter,
        qualityLimitationResolutionChanges => counter, psnrSum => map, qualityLimitationDurations => map,
        qualityLimitationReason => string, encoderImplementation => string, powerEfficientEncoder => boolean,
        scalabilityMode => string, targetBitrate => number
    };
members(source) ->
    #{
        audioLevel => number, totalAudioEnergy => counter, totalSamplesDuration => counter,
        echoReturnLoss => number, echoReturnLossEnhancement => number, width => number, height => number,
        frames => counter, framesPerSecond => number
    };
members(playout) ->
    #{
        synthesizedSamplesDuration => counter, synthesizedSamplesEvents => counter,
        totalSamplesDuration => counter, totalPlayoutDelay => counter, totalSamplesCount => counter
    }.

%% @doc Merge `Report' into `Kept'. Returns the members kept and those
%% dropped.
-spec merge(dir(), map(), map()) -> {map(), [{term(), term()}]}.
merge(Dir, Report, Kept) when is_map(Report) ->
    Members = members(Dir),
    maps:fold(
        fun(K0, V, {Acc, Bad}) ->
            K = key(K0),
            case {maps:find(K, Members), V} of
                {{ok, counter}, _} when is_number(V), V >= 0 -> {Acc#{K => maps:get(K, Acc, 0) + V}, Bad};
                {{ok, number}, _} when is_number(V) -> {Acc#{K => V}, Bad};
                {{ok, string}, _} when is_binary(V) -> {Acc#{K => V}, Bad};
                {{ok, boolean}, _} when is_boolean(V) -> {Acc#{K => V}, Bad};
                {{ok, map}, #{}} ->
                    case lists:all(fun({Mk, Mv}) -> is_binary(Mk) andalso is_number(Mv) end, maps:to_list(V)) of
                        true -> {Acc#{K => V}, Bad};
                        false -> {Acc, [{K0, V} | Bad]}
                    end;
                _ ->
                    {Acc, [{K0, V} | Bad]}
            end
        end,
        {Kept, []},
        Report
    );
merge(_Dir, Report, Kept) ->
    {Kept, [{report, Report}]}.

%% Members may come as atoms or binaries.
key(K) when is_atom(K) -> K;
key(K) when is_binary(K) ->
    try binary_to_existing_atom(K) catch error:badarg -> K end;
key(K) -> K.
