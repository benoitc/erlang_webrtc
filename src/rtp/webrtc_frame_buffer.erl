%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Frame assembly and jitter buffer for one received RTP stream.
%% No I/O: packets go in with `push/4', frames come out as actions, and
%% the caller runs `timeout/2' at `next_timeout/1'.
%%
%% Packets are put in sequence order and duplicates dropped (RFC 3550
%% §A.1). The packets of one timestamp form a frame, complete once the
%% packets from its first one to the one with the marker bit are all
%% there. The first packet is the one the payload format marks (VP8 S
%% bit and partition 0, VP9 B bit, AV1 N bit), or the one after a packet
%% of another frame. An H.264 packet that can start an access unit
%% (ITU-T H.264 §7.4.1.2.3) is taken as the first once the packets
%% missing before it are given up.
%%
%% Timestamps must rise with sequence numbers: H.264 with B frames,
%% which WebRTC encoders do not send, is not supported.
%%
%% A frame leaves in order once it is complete and decodable:
%% <ul>
%% <li>a key frame always is;</li>
%% <li>VP8, and VP9 in non-flexible mode, with picture IDs: a frame of
%%     the base temporal layer when the previous base frame left
%%     (TL0PICIDX), a higher layer frame when its base frame left and
%%     every frame between them did, or it is a layer sync frame;</li>
%% <li>VP9 in flexible mode: when every picture it references left;</li>
%% <li>VP8 and VP9 with picture IDs only: the picture after the last one
%%     that left;</li>
%% <li>other video (H.264, AV1, and VP8 and VP9 without picture IDs):
%%     when it follows the last frame that left with no packet missing;
%%     </li>
%% <li>audio: every frame.</li>
%% </ul>
%%
%% It leaves at its playout time: its timestamp, plus the smallest
%% transit time of the last 10 s, plus the target delay, three times the
%% interarrival jitter of frames (RFC 3550 §6.4.1) within `min_delay'
%% and `max_delay' (and the playout-delay extension when the sender
%% sets it). A complete frame that comes later leaves at once.
%%
%% A frame that misses packets is waited for until a later frame is
%% complete and its playout time has passed by 100 ms, for packets that
%% come out of order, or by three round trip times when the stream is
%% repaired by NACK (two retransmissions); until `lost/3' says a missing
%% packet will not come; or for 3 s. It is then dropped with the frames
%% that depend on it, and a key frame is requested (at most once per
%% round trip and never more than five times a second).
%%
%% Actions: `{frame, Frame}' and `request_keyframe'.
-module(webrtc_frame_buffer).

-include("webrtc_rtp.hrl").

-export([new/1, push/4, padding/3, lost/3, timeout/2, next_timeout/1, set_rtt/2, stats/1]).

-export_type([state/0, frame/0, action/0]).

-define(MAX_PACKETS, 2048).
-define(STALE, 3000).
-define(KEYFRAME_INTERVAL, 200).
-define(DEFAULT_RTT, 100).
-define(REORDER, 100).
-define(WINDOW, 10).
-define(PIDS, 128).

-type frame() :: #{
    timestamp := 0..16#FFFFFFFF,
    keyframe := boolean(),
    data := binary(),
    codec := binary(),
    width => undefined | pos_integer(),
    height => undefined | pos_integer()
}.

-type action() :: {frame, frame()} | request_keyframe.

-record(pkt, {
    seq :: integer(),
    ts :: integer(),
    marker :: boolean(),
    payload :: binary(),
    at :: integer(),
    pt :: 0..127,
    info :: webrtc_frame_codec:info()
}).

%% A frame as seen in the buffer.
-record(f, {
    ts :: integer(),
    pkts :: [#pkt{}],
    first :: integer(),
    last :: integer(),
    start :: boolean(),
    %% Complete if its first packet, a probable start, is the first.
    probable :: boolean(),
    complete :: boolean(),
    keyframe :: boolean()
}).

-record(fb, {
    kind :: audio | video,
    clock :: pos_integer(),
    %% Payload type to {format, codec name}.
    codecs :: #{0..127 => {webrtc_frame_codec:codec(), binary()}},
    min_delay :: non_neg_integer(),
    max_delay :: non_neg_integer(),
    playout = undefined :: undefined | {non_neg_integer(), non_neg_integer()},
    nack :: boolean(),
    rtt = ?DEFAULT_RTT :: non_neg_integer(),
    last_seq :: undefined | integer(),
    last_ts :: undefined | integer(),
    pkts = gb_trees:empty() :: gb_trees:tree(integer(), #pkt{}),
    %% Sequence numbers the sender will not repeat.
    lost = [] :: [integer()],
    %% Sequence numbers of packets that carry no media (FEC, padding):
    %% no frame misses them.
    fillers = [] :: [integer()],
    %% The last packet and timestamp of the frames that left or were
    %% dropped: anything at or before them is late.
    done_seq :: undefined | integer(),
    done_ts :: undefined | integer(),
    %% Last packet of the last frame that left.
    last_end :: undefined | integer(),
    %% A key frame left and nothing it needs was dropped since.
    chain = false :: boolean(),
    %% The last frame done was dropped before its last packet came: a gap
    %% after it may be its own end.
    tail_open = false :: boolean(),
    tl0 :: undefined | {0..255, non_neg_integer()},
    pids = [] :: [non_neg_integer()],
    dropped_hi = [] :: [{non_neg_integer(), non_neg_integer()}],
    keyframe_at :: undefined | integer(),
    %% Smallest transit time per second, the last ?WINDOW seconds.
    transit = [] :: [{integer(), integer()}],
    jitter = 0.0 :: float(),
    last_transit :: undefined | integer(),
    codec_state = #{} :: map(),
    size :: undefined | {pos_integer(), pos_integer()},
    emitted = [] :: [integer()],
    timer = infinity :: integer() | infinity,
    stats = #{} :: map()
}).

-opaque state() :: #fb{}.

%% @doc A buffer for one stream. Options: `kind' (`audio' or `video'),
%% `clock_rate', `codecs' (`[#{pt, name}]'), `nack' (the stream is
%% repaired by retransmission), `min_delay' and `max_delay' in ms
%% (default 0 and 10000).
-spec new(map()) -> state().
new(Opts) ->
    Kind = maps:get(kind, Opts, video),
    #fb{
        kind = Kind,
        clock = maps:get(clock_rate, Opts, 90000),
        codecs = maps:from_list([{Pt, {webrtc_frame_codec:codec(Kind, N), N}} || #{pt := Pt, name := N} <- maps:get(codecs, Opts, [])]),
        min_delay = maps:get(min_delay, Opts, 0),
        max_delay = maps:get(max_delay, Opts, 10000),
        nack = maps:get(nack, Opts, false)
    }.

%% @doc The round trip time of the path, in ms.
-spec set_rtt(non_neg_integer(), state()) -> state().
set_rtt(Rtt, St) when is_integer(Rtt), Rtt >= 0 ->
    St#fb{rtt = Rtt}.

%% @doc Add a packet received at `Now' (ms). `Opts': `playout_delay',
%% the `{Min, Max}' of the playout-delay extension it carried.
-spec push(#rtp{}, integer(), map(), state()) -> {[action()], state()}.
push(#rtp{pt = Pt} = Rtp, Now, Opts, #fb{codecs = Cs} = St0) when is_map_key(Pt, Cs) ->
    St = case Opts of #{playout_delay := Pd} -> St0#fb{playout = Pd}; _ -> St0 end,
    Seq = webrtc_rtp_seq:seq_unwrap(Rtp#rtp.seq, St#fb.last_seq),
    Ts = webrtc_rtp_seq:ts_unwrap(Rtp#rtp.ts, St#fb.last_ts),
    St1 = St#fb{last_seq = max(Seq, default(St#fb.last_seq, Seq)), last_ts = max(Ts, default(St#fb.last_ts, Ts))},
    case late(Seq, Ts, St1) of
        true ->
            process(Now, count(packets_discarded, 1, St1));
        false ->
            case gb_trees:is_defined(Seq, St1#fb.pkts) of
                true ->
                    process(Now, count(duplicates, 1, St1));
                false ->
                    {Codec, _} = maps:get(Pt, Cs),
                    P = #pkt{seq = Seq, ts = Ts, marker = Rtp#rtp.marker, payload = Rtp#rtp.payload, at = Now,
                             pt = Pt, info = webrtc_frame_codec:packet(Codec, Rtp#rtp.payload)},
                    CS = webrtc_frame_codec:track(Codec, Seq, Rtp#rtp.payload, St1#fb.codec_state),
                    St2 = transit(Now, Ts, St1#fb{pkts = gb_trees:insert(Seq, P, St1#fb.pkts), codec_state = CS}),
                    {A0, St3} = bound(Now, St2),
                    {A1, St4} = process(Now, St3),
                    {A0 ++ A1, St4}
            end
    end;
push(_Rtp, Now, _Opts, St) ->
    process(Now, count(unknown_payload_type, 1, St)).

default(undefined, D) -> D;
default(V, _) -> V.

late(Seq, Ts, #fb{done_seq = DS, done_ts = DT}) ->
    (DS =/= undefined andalso Seq =< DS) orelse (DT =/= undefined andalso Ts =< DT).

%% @doc A packet of the stream that carries no media (an FEC packet,
%% padding): its sequence number is no gap.
-spec padding(0..65535, integer(), state()) -> {[action()], state()}.
padding(Seq0, Now, #fb{last_seq = Last} = St) ->
    Seq = webrtc_rtp_seq:seq_unwrap(Seq0, Last),
    St1 = St#fb{last_seq = max(Seq, default(Last, Seq))},
    case St1#fb.done_seq of
        D when is_integer(D), Seq =< D -> process(Now, St1);
        _ -> process(Now, St1#fb{fillers = lists:sublist(lists:usort([Seq | St1#fb.fillers]), ?MAX_PACKETS)})
    end.

%% The first sequence number below Seq that is not a filler.
below(Seq, #fb{fillers = F}) ->
    below_list(Seq, F).

below_list(Seq, F) ->
    case lists:member(Seq - 1, F) of
        true -> below_list(Seq - 1, F);
        false -> Seq - 1
    end.

%% @doc The sender will not repeat these packets (NACK gave up on them).
-spec lost([0..65535], integer(), state()) -> {[action()], state()}.
lost(Seqs, Now, #fb{last_seq = Last} = St) when Last =/= undefined ->
    Ext = [webrtc_rtp_seq:seq_unwrap(S, Last) || S <- Seqs],
    process(Now, St#fb{lost = lists:usort(Ext ++ St#fb.lost)});
lost(_, Now, St) ->
    process(Now, St).

-spec next_timeout(state()) -> integer() | infinity.
next_timeout(#fb{timer = T}) ->
    T.

-spec timeout(integer(), state()) -> {[action()], state()}.
timeout(Now, St) ->
    process(Now, St).

%% Too many packets: the oldest frames go.
bound(Now, #fb{pkts = Pkts} = St) ->
    case gb_trees:size(Pkts) > ?MAX_PACKETS of
        true ->
            [F | _] = frames(St),
            {A, St1} = drop(F, Now, St),
            {A1, St2} = bound(Now, St1),
            {A ++ A1, St2};
        false ->
            {[], St}
    end.

%%====================================================================
%% Release
%%====================================================================

process(Now, St) ->
    process(Now, St, []).

process(Now, St0, Acc) ->
    St = St0#fb{timer = infinity},
    case frames(St) of
        [] ->
            {lists:reverse(Acc), St};
        [F | Later] ->
            Gap = gap_before(F, St),
            case skip_to_keyframe(F, Later, St) of
                {skip, Skipped} ->
                    {A, St1} = drop_all(Skipped, Now, St),
                    process(Now, St1, lists:reverse(A, Acc));
                keep ->
                    head(F, Later, Gap, Now, St, Acc)
            end
    end.

%% Waiting for a key frame and one is complete: the frames before it
%% will never be decodable when each is known to be a delta frame (its
%% first packet is there; for H.264, whose IDR may be in any slice, all
%% of it).
skip_to_keyframe(F, Later, #fb{chain = false, kind = video} = St) ->
    case lists:splitwith(fun(#f{keyframe = K, complete = C}) -> not (K andalso C) end, [F | Later]) of
        {[_ | _] = Before, [_ | _]} ->
            Delta = fun(#f{start = S, keyframe = K, complete = C} = X) ->
                        S andalso not K andalso (C orelse codec(X, St) =/= h264)
                    end,
            case lists:all(Delta, Before) of
                true -> {skip, Before};
                false -> keep
            end;
        _ ->
            keep
    end;
skip_to_keyframe(_, _, _) ->
    keep.

head(#f{complete = true} = F, _Later, Gap, Now, St, Acc) ->
    Play = playout(F, St),
    case decodable(F, Gap, St) of
        yes when Now >= Play ->
            {A, St1} = release(F, Now, St),
            process(Now, St1, lists:reverse(A, Acc));
        yes ->
            {lists:reverse(Acc), St#fb{timer = Play}};
        wait ->
            Deadline = Play + repair_time(St),
            case Now >= Deadline orelse lost_in(F, St) of
                true ->
                    %% The missing frames before it are given up; it is
                    %% then looked at again without them.
                    process(Now, give_up_gap(F, St), Acc);
                false ->
                    {lists:reverse(Acc), St#fb{timer = Deadline}}
            end;
        never ->
            {A, St1} = drop(F, Now, St),
            process(Now, St1, lists:reverse(A, Acc))
    end;
head(F, Later, _Gap, Now, St, Acc) ->
    Deadline =
        case [K || #f{complete = true} = K <- Later] of
            [K | _] -> playout(K, St) + repair_time(St);
            [] -> playout(F, St) + ?STALE
        end,
    case Now >= Deadline orelse lost_in(F, St) of
        true when F#f.probable ->
            %% What is missing before it is given up: its probable start
            %% is its first packet.
            process(Now, give_up_gap(F, St), Acc);
        true ->
            {A, St1} = drop(F, Now, St),
            process(Now, St1, lists:reverse(A, Acc));
        false ->
            {lists:reverse(Acc), St#fb{timer = Deadline}}
    end.

repair_time(#fb{nack = true, rtt = Rtt}) -> max(?REORDER, 3 * Rtt);
repair_time(_) -> ?REORDER.

%% A packet the frame misses (or one missing before it) will not come.
lost_in(_F, #fb{lost = []}) ->
    false;
lost_in(#f{first = First, last = Last, pkts = Pkts}, #fb{lost = Lost, done_seq = Done, fillers = F}) ->
    From = case Done of undefined -> First; _ -> Done + 1 end,
    Have = [S || #pkt{seq = S} <- Pkts] ++ F,
    lists:any(fun(S) -> S >= From andalso S =< Last andalso not lists:member(S, Have) end, Lost).

%% Packets are missing between the last frame done and this one; before
%% any frame is done, earlier packets may still come.
gap_before(_F, #fb{done_seq = undefined}) -> true;
gap_before(#f{first = First}, #fb{done_seq = Done} = St) -> below(First, St) > Done.

%%====================================================================
%% Decodability
%%====================================================================

decodable(_F, _Gap, #fb{kind = audio}) ->
    yes;
decodable(#f{keyframe = true}, _Gap, _St) ->
    yes;
decodable(#f{pkts = [#pkt{pt = Pt} | _]} = F, Gap, #fb{codecs = Cs} = St) ->
    {Codec, _} = maps:get(Pt, Cs),
    decodable(Codec, info(F), F, Gap, St).

%% A video format we cannot look into: every complete frame.
decodable(video, _, _F, _Gap, _St) ->
    yes;
decodable(_, _, _F, Gap, #fb{chain = false}) ->
    wait_or(Gap, never);
decodable(vp9, #{flexible := true, pid := Pid, refs := Refs}, _F, Gap, #fb{pids = Pids}) when Pid =/= undefined ->
    case lists:all(fun(R) -> lists:member(R, Pids) end, Refs) of
        true -> yes;
        false -> wait_or(Gap, never)
    end;
decodable(C, #{pid := {Bits, Pid}, tl0 := Tl0} = I, _F, Gap, #fb{tl0 = {Last, Base}} = St)
  when (C =:= vp8 orelse C =:= vp9), Tl0 =/= undefined ->
    case maps:get(tid, I, 0) of
        T when T =:= 0; T =:= undefined ->
            case Tl0 =:= (Last + 1) band 255 of
                true -> yes;
                false -> wait_or(Gap, never)
            end;
        Tid when Tl0 =:= Last ->
            Mask = (1 bsl Bits) - 1,
            Dist = (Pid - Base) band Mask,
            Between = [(Base + D) band Mask || D <- lists:seq(1, min(Dist, ?PIDS + 1) - 1)],
            Known = fun(P) -> lists:member(P, St#fb.pids) orelse
                                  lists:any(fun({P1, T1}) -> P1 =:= P andalso T1 > Tid end, St#fb.dropped_hi) end,
            case maps:get(sync, I, false) orelse (Dist =< ?PIDS andalso lists:all(Known, Between)) of
                true -> yes;
                false -> wait_or(Gap, never)
            end;
        _ ->
            wait_or(Gap, never)
    end;
%% VP8 and VP9 with picture IDs and no temporal layers: the frame after
%% the last one left, by picture ID (as libwebrtc's reference finders),
%% so a lost packet that carried no media (an FEC packet) costs nothing.
decodable(C, #{pid := {Bits, Pid}}, _F, Gap, #fb{pids = [Last | _]}) when C =:= vp8; C =:= vp9 ->
    case Pid =:= (Last + 1) band ((1 bsl Bits) - 1) of
        true -> yes;
        false -> wait_or(Gap, never)
    end;
decodable(_, _, #f{first = First}, Gap, #fb{last_end = End} = St) ->
    case below(First, St) =:= End of
        true -> yes;
        false -> wait_or(Gap, never)
    end.

wait_or(true, _) -> wait;
wait_or(false, V) -> V.

%% What the frame's first packet says.
info(#f{pkts = [#pkt{info = I} | _]}) -> I.

codec(#f{pkts = [#pkt{pt = Pt} | _]}, #fb{codecs = Cs}) -> element(1, maps:get(Pt, Cs)).

%% A dropped frame of a higher temporal layer leaves the base layer
%% decodable.
droppable(#f{pkts = [#pkt{pt = Pt, info = I} | _]}, #fb{codecs = Cs}) ->
    case {maps:get(Pt, Cs), I} of
        {{C, _}, #{tid := Tid, pid := {_, _}, tl0 := Tl0}} when (C =:= vp8 orelse C =:= vp9),
                                                              is_integer(Tid), Tid > 0, Tl0 =/= undefined ->
            true;
        _ ->
            false
    end.

%%====================================================================
%% Frames in the buffer
%%====================================================================

%% The frames in sequence order.
frames(#fb{pkts = Pkts} = St) ->
    group(gb_trees:values(Pkts), St, []).

group([], _St, Acc) ->
    lists:reverse(Acc);
group([#pkt{ts = Ts} | _] = Pkts, St, Acc) ->
    {Mine, Rest} = lists:splitwith(fun(#pkt{ts = T}) -> T =:= Ts end, Pkts),
    group(Rest, St, [frame(Mine, Acc, St) | Acc]).

frame([#pkt{seq = First, ts = Ts, info = I} | _] = Pkts, Before, #fb{kind = Kind, done_seq = Done} = St) ->
    #pkt{seq = Last} = lists:last(Pkts),
    Below = below(First, St),
    Start = Kind =:= audio orelse maps:get(start, I) =:= true orelse
        (Done =/= undefined andalso Below =:= Done) orelse
        case Before of
            [#f{last = L} | _] -> L =:= Below;
            [] -> false
        end,
    %% Every packet from the first to the one with the marker bit.
    Whole = Kind =:= audio orelse (contiguous(Pkts) andalso (lists:last(Pkts))#pkt.marker),
    #f{ts = Ts, pkts = Pkts, first = First, last = Last, start = Start, complete = Start andalso Whole,
       probable = not Start andalso Whole andalso maps:get(start, I) =:= probable,
       keyframe = lists:any(fun(#pkt{info = #{keyframe := K}}) -> K end, Pkts)}.

contiguous([#pkt{seq = A}, #pkt{seq = B} = P | Rest]) -> B =:= A + 1 andalso contiguous([P | Rest]);
contiguous(_) -> true.

%%====================================================================
%% Leaving the buffer
%%====================================================================

release(#f{pkts = [#pkt{pt = Pt, at = At0} | _] = Pkts, keyframe = Key, ts = Ts, first = First, last = Last} = F, Now, St0) ->
    {Codec, Name} = maps:get(Pt, St0#fb.codecs),
    case webrtc_frame_codec:assemble(Codec, [{S band 16#FFFF, P} || #pkt{seq = S, payload = P} <- Pkts], First,
                                     St0#fb.codec_state) of
        {ok, Data, Size0, CS} ->
            St1 = remove(F, St0#fb{codec_state = CS}),
            Size = case Size0 of undefined -> St1#fb.size; _ -> Size0 end,
            I = info(F),
            St2 = case Key of
                      true -> St1#fb{chain = true, dropped_hi = [], pids = []};
                      false -> St1
                  end,
            St3 = case I of
                      #{pid := {_, Pid}, tl0 := Tl0} when Tl0 =/= undefined, (Key orelse map_get(tid, I) =:= 0 orelse map_get(tid, I) =:= undefined) ->
                          St2#fb{tl0 = {Tl0, Pid}};
                      _ -> St2
                  end,
            St4 = case I of
                      #{pid := {_, P}} -> St3#fb{pids = lists:sublist([P | St3#fb.pids], ?PIDS)};
                      _ -> St3
                  end,
            Target = target(St4),
            Assembly = (lists:max([A || #pkt{at = A} <- Pkts]) - At0) / 1000,
            Multi = length(Pkts) > 1,
            Emitted = [E || E <- [Now | St4#fb.emitted], E > Now - 1000],
            Completed = lists:max([A || #pkt{at = A} <- Pkts]),
            St5 = (jitter(Completed, Ts, St4))#fb{size = Size, last_end = Last, done_seq = max_done(Last, St4),
                                                 done_ts = max_ts(Ts, St4), emitted = Emitted, tail_open = false},
            Stats = add(#{
                frames_received => 1,
                keyframes_received => case Key of true -> 1; false -> 0 end,
                frames_assembled_from_multiple_packets => case Multi of true -> 1; false -> 0 end,
                total_assembly_time => case Multi of true -> Assembly; false -> 0.0 end,
                jitter_buffer_delay => (Now - At0) / 1000,
                jitter_buffer_target_delay => Target / 1000,
                jitter_buffer_minimum_delay => minimum(St4) / 1000,
                jitter_buffer_emitted_count => 1
            }, St5#fb.stats),
            Frame0 = #{timestamp => Ts band 16#FFFFFFFF, keyframe => Key, data => Data, codec => Name},
            Frame = case St5#fb.kind of
                        video ->
                            {W, H} = case Size of undefined -> {undefined, undefined}; _ -> Size end,
                            Frame0#{width => W, height => H};
                        audio ->
                            Frame0
                    end,
            {[{frame, Frame}], St5#fb{stats = Stats}};
        {error, _, CS} ->
            drop(F, Now, count(frames_malformed, 1, St0#fb{codec_state = CS}))
    end.

drop_all(Fs, Now, St) ->
    lists:foldl(fun(F, {A, S}) -> {A1, S1} = drop(F, Now, S), {A ++ A1, S1} end, {[], St}, Fs).

%% The frame goes, and the frames that depend on it with it unless it
%% was on a higher temporal layer.
drop(#f{ts = Ts, last = Last, complete = Complete} = F, Now, St0) ->
    St1 = remove(F, St0),
    St2 = St1#fb{done_seq = max_done(Last, St1), done_ts = max_ts(Ts, St1), tail_open = not Complete,
                 stats = add(#{frames_dropped => 1, frames_received => case Complete of true -> 1; false -> 0 end},
                             St1#fb.stats)},
    case St2#fb.kind =:= audio orelse droppable(F, St2) of
        true ->
            I = info(F),
            Hi = case I of #{pid := {_, P}, tid := T} when is_integer(T) -> [{P, T}]; _ -> [] end,
            {[], St2#fb{dropped_hi = lists:sublist(Hi ++ St2#fb.dropped_hi, ?PIDS)}};
        false ->
            keyframe_request(Now, St2#fb{chain = false})
    end.

%% The packets missing before the head frame are given up, counted as
%% one dropped frame unless they may be the end of the last one dropped.
give_up_gap(#f{first = First}, #fb{tail_open = Open, done_seq = Done} = St) ->
    Dropped = case Open orelse Done =:= undefined of true -> 0; false -> 1 end,
    St#fb{done_seq = First - 1, tail_open = false, stats = add(#{frames_dropped => Dropped}, St#fb.stats)}.

keyframe_request(Now, #fb{kind = video, keyframe_at = At, rtt = Rtt} = St) ->
    case At =:= undefined orelse Now - At >= max(?KEYFRAME_INTERVAL, Rtt) of
        true -> {[request_keyframe], St#fb{keyframe_at = Now, stats = add(#{keyframe_requests => 1}, St#fb.stats)}};
        false -> {[], St}
    end;
keyframe_request(_Now, St) ->
    {[], St}.

remove(#f{pkts = Pkts, last = Last}, #fb{pkts = T, lost = Lost, fillers = F} = St) ->
    St#fb{pkts = lists:foldl(fun(#pkt{seq = S}, Acc) -> gb_trees:delete(S, Acc) end, T, Pkts),
          lost = [S || S <- Lost, S > Last], fillers = [S || S <- F, S > Last - 64]}.

max_done(Last, #fb{done_seq = undefined}) -> Last;
max_done(Last, #fb{done_seq = D}) -> max(Last, D).

max_ts(Ts, #fb{done_ts = undefined}) -> Ts;
max_ts(Ts, #fb{done_ts = D}) -> max(Ts, D).

%%====================================================================
%% Timing
%%====================================================================

ms(Ts, #fb{clock = C}) -> Ts * 1000 div C.

%% Smallest transit time per second.
transit(Now, Ts, #fb{transit = Tr} = St) ->
    T = Now - ms(Ts, St),
    Sec = Now div 1000,
    Kept = [X || {S, _} = X <- Tr, S > Sec - ?WINDOW],
    St#fb{transit = case Kept of
                        [{Sec, M} | Rest] -> [{Sec, min(M, T)} | Rest];
                        _ -> [{Sec, T} | Kept]
                    end}.

offset(#fb{transit = []}) -> 0;
offset(#fb{transit = Tr}) -> lists:min([M || {_, M} <- Tr]).

playout(#f{ts = Ts}, St) ->
    ms(Ts, St) + offset(St) + target(St).

%% Three times the jitter, within the limits.
minimum(#fb{jitter = J}) -> round(3 * J).

target(#fb{min_delay = Min0, max_delay = Max0, playout = Pd} = St) ->
    {Min, Max} =
        case Pd of
            undefined -> {Min0, Max0};
            {PMin, PMax} -> {max(Min0, PMin), max(min(Max0, PMax), max(Min0, PMin))}
        end,
    min(Max, max(Min, minimum(St))).

%% RFC 3550 §6.4.1 over the times frames are complete.
jitter(At, Ts, #fb{last_transit = Prev, jitter = J} = St) ->
    T = At - ms(Ts, St),
    case Prev of
        undefined -> St#fb{last_transit = T};
        _ -> St#fb{last_transit = T, jitter = J + (abs(T - Prev) - J) / 16}
    end.

%%====================================================================
%% Statistics
%%====================================================================

count(K, N, #fb{stats = S} = St) ->
    St#fb{stats = maps:update_with(K, fun(V) -> V + N end, N, S)}.

add(Map, Stats) ->
    maps:fold(fun(K, V, Acc) -> maps:update_with(K, fun(X) -> X + V end, V, Acc) end, Stats, Map).

%% @doc Counters (W3C RTCInboundRtpStreamStats names, in snake case;
%% times in seconds) and the current frame size, rate and target delay.
-spec stats(state()) -> map().
stats(#fb{stats = S, size = Size, emitted = E} = St) ->
    {W, H} = case Size of undefined -> {undefined, undefined}; _ -> Size end,
    maps:merge(#{frames_received => 0, frames_dropped => 0, packets_discarded => 0,
                 jitter_buffer_emitted_count => 0}, S#{
        frame_width => W,
        frame_height => H,
        frames_per_second => length(E),
        target_delay => target(St),
        buffered_packets => gb_trees:size(St#fb.pkts)
    }).
