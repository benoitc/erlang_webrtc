%% @doc Transport-wide congestion control feedback, RTPFB FMT 15
%% (draft-holmer-rmcat-transport-wide-cc-extensions-01 §3.1).
%%
%% The record `#rtcp_twcc{}' lists one entry per transport-wide sequence
%% number from `base_seq': `not_received' or the receive delta in
%% multiples of 250 microseconds. The first delta is relative to
%% `ref_time' (multiples of 64 ms), each next one to the previous
%% received packet.
%%
%% Packet status chunks follow the draft and libwebrtc: a run length
%% chunk, a one-bit status vector (1 = received with a small delta,
%% 0 = not received; the draft text has the two values swapped but its
%% example and every implementation use this order) or a two-bit status
%% vector. Symbol 3 is reserved and rejected. The encoder picks run
%% length chunks for runs of 14 or more, then one-bit vectors when the
%% next 14 symbols allow it, then run length chunks for runs of 7 or
%% more, otherwise two-bit vectors. Deltas in 0..255 use the small
%% symbol, others the large (signed 16-bit) one.
%%
%% `from_arrivals/4' builds feedback messages from absolute arrival
%% times and `arrivals/1' does the reverse.
-module(webrtc_rtcp_twcc).

-include("webrtc_rtp_rtcp.hrl").

-export([decode/3, encode_fci/1, from_arrivals/4, arrivals/1]).

-define(MAX_RUN, 8191).

%%====================================================================
%% Decoding
%%====================================================================

-spec decode(0..16#FFFFFFFF, 0..16#FFFFFFFF, binary()) ->
    {ok, #rtcp_twcc{}} | {error, term()}.
decode(Sender, Media, <<Base:16, Count:16, Ref:24/signed, FbCount:8, Rest/binary>>) ->
    case chunks(Count, Rest, []) of
        {ok, Symbols, Rest1} ->
            case deltas(Symbols, Base, Rest1, []) of
                {ok, Packets, Tail} when byte_size(Tail) < 4 ->
                    {ok, #rtcp_twcc{
                        sender_ssrc = Sender,
                        media_ssrc = Media,
                        base_seq = Base,
                        ref_time = Ref,
                        fb_count = FbCount,
                        packets = Packets
                    }};
                {ok, _, _} ->
                    {error, trailing_data};
                Err ->
                    Err
            end;
        Err ->
            Err
    end;
decode(_, _, _) ->
    {error, truncated}.

%% Read chunks until Count symbols are known. A chunk describing more
%% symbols than remain is cut; the reserved symbol 3 is only an error
%% when it describes a packet within the status count.
chunks(0, Rest, Acc) ->
    Symbols = lists:append(lists:reverse(Acc)),
    case lists:member(3, Symbols) of
        true -> {error, reserved_symbol};
        false -> {ok, Symbols, Rest}
    end;
chunks(Count, <<0:1, S:2, Run:13, Rest/binary>>, Acc) ->
    N = min(Run, Count),
    chunks(Count - N, Rest, [lists:duplicate(N, S) | Acc]);
chunks(Count, <<1:1, 0:1, Bits:14/bitstring, Rest/binary>>, Acc) ->
    take_symbols(Count, [B || <<B:1>> <= Bits], Rest, Acc);
chunks(Count, <<1:1, 1:1, Syms:14/bitstring, Rest/binary>>, Acc) ->
    take_symbols(Count, [S || <<S:2>> <= Syms], Rest, Acc);
chunks(_, _, _) ->
    {error, truncated}.

take_symbols(Count, Symbols, Rest, Acc) ->
    L = lists:sublist(Symbols, Count),
    chunks(Count - length(L), Rest, [L | Acc]).

deltas([], _Seq, Rest, Acc) ->
    {ok, lists:reverse(Acc), Rest};
deltas([0 | Syms], Seq, Rest, Acc) ->
    deltas(Syms, next(Seq), Rest, [{Seq, not_received} | Acc]);
deltas([1 | Syms], Seq, <<D:8, Rest/binary>>, Acc) ->
    deltas(Syms, next(Seq), Rest, [{Seq, D} | Acc]);
deltas([2 | Syms], Seq, <<D:16/signed, Rest/binary>>, Acc) ->
    deltas(Syms, next(Seq), Rest, [{Seq, D} | Acc]);
deltas(_, _, _, _) ->
    {error, truncated}.

next(Seq) ->
    (Seq + 1) band 16#FFFF.

%%====================================================================
%% Encoding
%%====================================================================

%% @doc Encode the FCI part (everything after the two SSRCs), padded with
%% zero bytes to a multiple of 4. Raises `badarg' when the packets are
%% not consecutive from `base_seq' or a field is out of range.
-spec encode_fci(#rtcp_twcc{}) -> binary().
encode_fci(#rtcp_twcc{base_seq = Base, ref_time = Ref, fb_count = Fb, packets = Packets}) when
    is_integer(Base),
    Base >= 0,
    Base =< 16#FFFF,
    is_integer(Ref),
    Ref >= -16#800000,
    Ref =< 16#7FFFFF,
    is_integer(Fb),
    Fb >= 0,
    Fb =< 255,
    length(Packets) =< 16#FFFF
->
    Symbols = symbols(Packets, Base),
    Chunks = encode_chunks(Symbols),
    Deltas = [delta(D) || {_, D} <- Packets, D =/= not_received],
    pad4(
        iolist_to_binary([
            <<Base:16, (length(Packets)):16, Ref:24/signed, Fb:8>>, Chunks, Deltas
        ])
    );
encode_fci(_) ->
    error(badarg).

symbols([], _) ->
    [];
symbols([{Seq, D} | Rest], Seq) ->
    [symbol(D) | symbols(Rest, next(Seq))];
symbols(_, _) ->
    error(badarg).

symbol(not_received) -> 0;
symbol(D) when is_integer(D), D >= 0, D =< 255 -> 1;
symbol(D) when is_integer(D), D >= -32768, D =< 32767 -> 2;
symbol(_) -> error(badarg).

delta(D) when D >= 0, D =< 255 -> <<D:8>>;
delta(D) -> <<D:16/signed>>.

encode_chunks([]) ->
    [];
encode_chunks([S | _] = Syms) ->
    Run = run(S, Syms, 0),
    {First14, _} = take(14, Syms),
    OneBit = lists:all(fun(X) -> X =/= 2 end, First14),
    if
        Run >= 14 ->
            [<<0:1, S:2, Run:13>> | encode_chunks(lists:nthtail(Run, Syms))];
        OneBit ->
            N = length(First14),
            Bits = <<<<X:1>> || X <- First14>>,
            [<<1:1, 0:1, Bits/bitstring, 0:(14 - N)>> | encode_chunks(lists:nthtail(N, Syms))];
        Run >= 7 ->
            [<<0:1, S:2, Run:13>> | encode_chunks(lists:nthtail(Run, Syms))];
        true ->
            {First7, Rest} = take(7, Syms),
            N = length(First7),
            Bits = <<<<X:2>> || X <- First7>>,
            [<<1:1, 1:1, Bits/bitstring, 0:((7 - N) * 2)>> | encode_chunks(Rest)]
    end.

run(S, [S | Rest], N) when N < ?MAX_RUN -> run(S, Rest, N + 1);
run(_, _, N) -> N.

take(N, L) when length(L) =< N -> {L, []};
take(N, L) -> lists:split(N, L).

pad4(B) ->
    case byte_size(B) rem 4 of
        0 -> B;
        R -> <<B/binary, 0:((4 - R) * 8)>>
    end.

%%====================================================================
%% Arrival times
%%====================================================================

%% @doc Build feedback messages from `[{Seq, ArrivalUs}]', arrival times
%% in microseconds on any monotonic clock. Packets are ordered by
%% sequence number relative to the first one; gaps become
%% `not_received'. A new message is started when a delta does not fit
%% 16 bits or the status count would overflow. Feedback counts start at
%% `FbCount' and increase by one per message.
-spec from_arrivals(
    0..16#FFFFFFFF, 0..16#FFFFFFFF, 0..255, [{0..65535, integer()}]
) -> [#rtcp_twcc{}].
from_arrivals(_, _, _, []) ->
    [];
from_arrivals(Sender, Media, FbCount, [{First, _} | _] = Arrivals) ->
    Sorted = lists:keysort(1, [{webrtc_rtp_seq:seq_unwrap(S, First), A} || {S, A} <- Arrivals]),
    Dedup = dedup(Sorted),
    build(Dedup, #rtcp_twcc{sender_ssrc = Sender, media_ssrc = Media}, FbCount).

dedup([{S, A}, {S, _} | Rest]) -> dedup([{S, A} | Rest]);
dedup([X | Rest]) -> [X | dedup(Rest)];
dedup([]) -> [].

build([], _, _) ->
    [];
build([{Ext, A} | _] = List, Tmpl, Fb) ->
    RefTime = floor_div(A, 64000),
    {Packets, Rest} = fill(List, Ext, RefTime * 64000, []),
    Msg = Tmpl#rtcp_twcc{
        base_seq = Ext band 16#FFFF,
        ref_time = wrap24(RefTime),
        fb_count = Fb band 255,
        packets = Packets
    },
    [Msg | build(Rest, Tmpl, Fb + 1)].

fill([], _Next, _T, Acc) ->
    {lists:reverse(Acc), []};
fill(List, _Next, _T, Acc) when length(Acc) >= 16#FFFF ->
    {lists:reverse(Acc), List};
fill([{Ext, A} | Rest] = List, Next, T, Acc) when Ext =:= Next ->
    D = round_div(A - T, 250),
    case D >= -32768 andalso D =< 32767 of
        true -> fill(Rest, Next + 1, T + D * 250, [{Next band 16#FFFF, D} | Acc]);
        false -> {lists:reverse(Acc), List}
    end;
fill(List, Next, T, Acc) ->
    fill(List, Next + 1, T, [{Next band 16#FFFF, not_received} | Acc]).

%% @doc Absolute arrival times in microseconds, on the time base of the
%% feedback sender (`ref_time' * 64 ms plus the cumulative deltas).
-spec arrivals(#rtcp_twcc{}) -> [{0..65535, integer() | not_received}].
arrivals(#rtcp_twcc{ref_time = Ref, packets = Packets}) ->
    {L, _} = lists:mapfoldl(
        fun
            ({S, not_received}, T) -> {{S, not_received}, T};
            ({S, D}, T) -> {{S, T + D * 250}, T + D * 250}
        end,
        Ref * 64000,
        Packets
    ),
    L.

floor_div(A, B) when A >= 0 -> A div B;
floor_div(A, B) -> -((-A + B - 1) div B).

round_div(A, B) -> floor_div(2 * A + B, 2 * B).

wrap24(V) ->
    W = V band 16#FFFFFF,
    case W >= 16#800000 of
        true -> W - 16#1000000;
        false -> W
    end.
