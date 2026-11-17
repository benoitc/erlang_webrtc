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

-export([encode/2, decode/1, packets/3]).

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
%% number seq - n (one block per earlier packet, as WebRTC sends them).
%% Blocks whose payload type `Keep' refuses are left out.
-spec packets(#rtp{}, [block()], fun((0..127) -> boolean())) -> [#rtp{}].
packets(#rtp{seq = Seq, ts = Ts} = Pkt, Blocks, Keep) ->
    N = length(Blocks),
    [case I of
         N -> Pkt#rtp{pt = P, payload = D};
         _ -> Pkt#rtp{pt = P, payload = D, marker = false, seq = (Seq - (N - I)) band 16#FFFF,
                      ts = (Ts - O) band 16#FFFFFFFF}
     end
     || {I, {P, O, D}} <- lists:enumerate(Blocks), Keep(P)].
