%% @doc Sender-side retransmission buffer for NACK (RFC 4585 §6.2.1,
%% RFC 4588).
%%
%% A bounded ring indexed by RTP sequence number: storing packet `Seq'
%% overwrites the slot `Seq rem Size', so the buffer keeps at most the
%% last `size' packets. `retransmit/3' returns the stored packets for a
%% list of NACK'd sequence numbers, skipping packets that are older than
%% `max_age' or were already resent less than one RTT ago (a NACK sent
%% before our retransmission arrived). Times are integers in
%% milliseconds.
-module(webrtc_nack_buffer).

-export([new/1, store/4, lookup/2, retransmit/3, set_rtt/2, count/1]).

-export_type([buffer/0]).

-record(buf, {
    size :: pos_integer(),
    max_age :: pos_integer() | infinity,
    rtt :: non_neg_integer(),
    %% Index => {Seq, Packet, StoredAt, LastResentAt}
    slots = #{} :: #{non_neg_integer() => {0..65535, term(), integer(), integer() | undefined}}
}).

-opaque buffer() :: #buf{}.

%% @doc Options: `size' (default 1024 packets), `max_age' in ms (default
%% 2000) and the initial `rtt' in ms (default 0).
-spec new(#{size => pos_integer(), max_age => pos_integer() | infinity, rtt => non_neg_integer()}) ->
    buffer().
new(Opts) ->
    Size = maps:get(size, Opts, 1024),
    true = is_integer(Size) andalso Size > 0 andalso Size =< 65536,
    #buf{size = Size, max_age = maps:get(max_age, Opts, 2000), rtt = maps:get(rtt, Opts, 0)}.

-spec set_rtt(non_neg_integer(), buffer()) -> buffer().
set_rtt(Rtt, B) when is_integer(Rtt), Rtt >= 0 ->
    B#buf{rtt = Rtt}.

%% @doc Number of stored packets.
-spec count(buffer()) -> non_neg_integer().
count(#buf{slots = S}) ->
    map_size(S).

%% @doc Store a sent packet (any term, usually the encoded RTP packet).
-spec store(0..65535, term(), integer(), buffer()) -> buffer().
store(Seq, Packet, Now, #buf{size = Size, slots = S} = B) when
    is_integer(Seq), Seq >= 0, Seq =< 65535
->
    B#buf{slots = S#{Seq rem Size => {Seq, Packet, Now, undefined}}}.

-spec lookup(0..65535, buffer()) -> {ok, term()} | error.
lookup(Seq, #buf{size = Size, slots = S}) ->
    case S of
        #{(Seq rem Size) := {Seq, Packet, _, _}} -> {ok, Packet};
        _ -> error
    end.

%% @doc Packets to resend for `Seqs', in request order.
-spec retransmit([0..65535], integer(), buffer()) -> {[{0..65535, term()}], buffer()}.
retransmit(Seqs, Now, #buf{size = Size, max_age = MaxAge, rtt = Rtt} = B) ->
    {Out, Slots} = lists:foldl(
        fun(Seq, {Acc, S}) ->
            Idx = Seq rem Size,
            case S of
                #{Idx := {Seq, Packet, At, Last}} ->
                    Fresh = MaxAge =:= infinity orelse Now - At =< MaxAge,
                    Allowed = Last =:= undefined orelse Now - Last >= Rtt,
                    case Fresh andalso Allowed of
                        true -> {[{Seq, Packet} | Acc], S#{Idx := {Seq, Packet, At, Now}}};
                        false -> {Acc, S}
                    end;
                _ ->
                    {Acc, S}
            end
        end,
        {[], B#buf.slots},
        Seqs
    ),
    {lists:reverse(Out), B#buf{slots = Slots}}.
