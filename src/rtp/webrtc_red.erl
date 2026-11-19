%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc RTP payload for redundant data (RFC 2198).
%%
%% A RED payload is a list of block headers, then the blocks in the same
%% order. A redundant block's header has F = 1, its payload type, a
%% 14-bit timestamp offset back from the packet's timestamp and a 10-bit
%% length (4 bytes); the last header, the primary block's, has F = 0 and
%% its payload type only (1 byte) (§3).
%%
%% WebRTC uses it for audio redundancy (RFC 8854 §5.2) and to carry
%% ULPFEC with the video it protects (RFC 5109 §14.2).
-module(webrtc_red).

-include("webrtc_rtp.hrl").

-export([encode/2, decode/1, packets/3, packets/4, repair/4, seen/3]).

-export_type([history/0]).

%% The last {Seq, Ts} a receiver got, newest first.
-type history() :: [{0..65535, non_neg_integer()}].

-define(HISTORY, 64).

-export_type([block/0]).

%% {PayloadType, TimestampOffset, Data}; the primary block has offset 0.
-type block() :: {0..127, 0..16#3FFF, binary()}.

-define(MAX_OFFSET, 16#3FFF).
-define(MAX_LEN, 16#3FF).

%% @doc A RED payload: redundant blocks, oldest first, then the primary
%% block. Redundant blocks the header cannot describe (an offset or a
%% length out of range, §3) are left out.
-spec encode([block()], {0..127, binary()}) -> binary().
encode(Redundant, {Pt, Primary}) ->
    Kept = [{P, O, D} || {P, O, D} <- Redundant, O > 0, O =< ?MAX_OFFSET, byte_size(D) =< ?MAX_LEN],
    Headers = [<<1:1, P:7, O:14, (byte_size(D)):10>> || {P, O, D} <- Kept],
    iolist_to_binary([Headers, <<0:1, Pt:7>>, [D || {_, _, D} <- Kept], Primary]).

%% @doc The blocks of a RED payload, oldest first, the primary last
%% (offset 0). Headers that do not add up to the payload are an error.
-spec decode(binary()) -> {ok, [block()]} | {error, term()}.
decode(Bin) ->
    headers(Bin, []).

headers(<<1:1, Pt:7, Off:14, Len:10, Rest/binary>>, Acc) ->
    headers(Rest, [{Pt, Off, Len} | Acc]);
headers(<<0:1, Pt:7, Rest/binary>>, Acc) ->
    blocks(lists:reverse(Acc), Rest, Pt, []);
headers(_, _) ->
    {error, truncated_header}.

blocks([], Primary, Pt, Acc) ->
    {ok, lists:reverse([{Pt, 0, Primary} | Acc])};
blocks([{P, O, L} | Hs], Bin, Pt, Acc) ->
    case Bin of
        <<D:L/binary, Rest/binary>> -> blocks(Hs, Rest, Pt, [{P, O, D} | Acc]);
        _ -> {error, truncated_block}
    end.

%% @doc The RTP packets a RED packet carries: the primary with the
%% packet's sequence number and marker, and the redundant blocks as the
%% packets they repeat, the n-th before the primary taking sequence
%% number seq - n (one block per earlier packet, as libwebrtc sends
%% them). Blocks whose payload type `Keep' refuses are left out.
-spec packets(#rtp{}, [block()], fun((0..127) -> boolean())) -> [#rtp{}].
packets(Pkt, Blocks, Keep) ->
    packets(Pkt, Blocks, Keep, fun(I, N, _Offset) -> (Pkt#rtp.seq - (N - I)) band 16#FFFF end).

%% @doc The same, with the sequence number of a redundant block given
%% by `SeqOf(Index, Count, Offset)'. A block carries no sequence number
%% (§3): a sender may repeat an older packet than the previous one
%% (GStreamer's `distance'), so the receiver finds it from the
%% timestamp offset and the packet duration.
-spec packets(#rtp{}, [block()], fun((0..127) -> boolean()),
              fun((pos_integer(), pos_integer(), 0..16#3FFF) -> 0..65535)) -> [#rtp{}].
packets(#rtp{ts = Ts} = Pkt, Blocks, Keep, SeqOf) ->
    N = length(Blocks),
    [case I of
         N -> Pkt#rtp{pt = P, payload = D};
         _ -> Pkt#rtp{pt = P, payload = D, marker = false, seq = SeqOf(I, N, O), ts = (Ts - O) band 16#FFFFFFFF}
     end
     || {I, {P, O, D}} <- lists:enumerate(Blocks), Keep(P)].

%%====================================================================
%% Receiver
%%====================================================================

%% @doc Record a received packet in a receiver's history.
-spec seen(0..65535, non_neg_integer(), history()) -> history().
seen(Seq, Ts, History) ->
    lists:sublist([{Seq, Ts} | History], ?HISTORY).

%% @doc What a receiver delivers for a RED packet, given its history:
%% the redundant blocks that repair a lost packet (before the RED
%% packet, within the history, received neither under that sequence
%% number nor that timestamp), then the primary.
%%
%% A block carries no sequence number (§3), and a sender may repeat an
%% older packet than the previous one (GStreamer's `distance'). The
%% block is placed between the latest packet received before its
%% timestamp and the RED packet, the gap spread evenly over the packets
%% between them; without such a packet, the n-th block before the
%% primary is the n-th packet before it (libwebrtc's layout).
-spec repair(#rtp{}, [block()], fun((0..127) -> boolean()), history()) -> {[#rtp{}], [#rtp{}]}.
repair(#rtp{seq = Seq, ts = Ts} = Red, Blocks, Keep, History) ->
    SeqOf = fun(I, N, Off) -> block_seq(Seq, Ts, I, N, Off, History) end,
    {Redundant, Primary} = lists:partition(fun(#rtp{seq = S}) -> S =/= Seq end, packets(Red, Blocks, Keep, SeqOf)),
    {[P || P <- Redundant, lost(P, Seq, History)], Primary}.

block_seq(Seq, Ts, I, N, Off, History) ->
    %% Received packets older than the block: {how far back, Seq}.
    Before = [{(Ts - T) band 16#FFFFFFFF, S} || {S, T} <- History,
              (Ts - T) band 16#FFFFFFFF > Off, (Ts - T) band 16#FFFFFFFF < 16#80000000],
    case lists:sort(Before) of
        [{Back, S} | _] ->
            Gap = (Seq - S) band 16#FFFF,
            K = round((Back - Off) * Gap / Back),
            case K > 0 andalso K < Gap of
                true -> (S + K) band 16#FFFF;
                false -> (Seq - (N - I)) band 16#FFFF
            end;
        [] ->
            (Seq - (N - I)) band 16#FFFF
    end.

lost(_P, _RedSeq, []) ->
    false;
lost(#rtp{seq = Seq, ts = Ts}, RedSeq, History) ->
    Age = (RedSeq - Seq) band 16#FFFF,
    Age > 0 andalso Age < ?HISTORY andalso not lists:keymember(Seq, 1, History) andalso
        not lists:keymember(Ts, 2, History).
