%% @doc SCTP output: actions, control chunk queue and packet bundling
%% (RFC 9260 §6.10, RFC 9653 §5.2).
%%
%% Internal module of `webrtc_sctp_assoc'. Engines accumulate actions in
%% reverse order in `#assoc.acts' and control chunks in `#assoc.ctrl';
%% `flush/2' turns pending control chunks, a SACK when one is due and
%% the data chunks allowed by the send side into packets of at most one
%% MTU.
-module(webrtc_sctp_out).

-include("webrtc_sctp_assoc.hrl").

-export([event/2, raw/4, ctrl/2, flush/2, take/1, terminate/2, bump/2, bump/3]).

-spec event(term(), #assoc{}) -> #assoc{}.
event(E, #assoc{acts = Acts} = A) ->
    A#assoc{acts = [{event, E} | Acts]}.

%% @doc Queue a control chunk for the next flush (bundled with other
%% chunks, peer verification tag).
-spec ctrl(term(), #assoc{}) -> #assoc{}.
ctrl(C, #assoc{ctrl = Cs} = A) ->
    A#assoc{ctrl = [C | Cs]}.

%% @doc Send one packet now with an explicit verification tag. `crc32c'
%% forces a correct checksum (INIT, COOKIE ECHO, OOTB responses);
%% `auto' uses a zero checksum when RFC 9653 was negotiated.
-spec raw(0..16#FFFFFFFF, [term()], crc32c | auto, #assoc{}) -> #assoc{}.
raw(Vtag, Chunks, Mode, #assoc{cfg = C} = A) ->
    Pkt = #sctp_packet{
        src_port = C#cfg.local_port,
        dst_port = C#cfg.remote_port,
        vtag = Vtag,
        chunks = Chunks
    },
    Cs =
        case Mode of
            crc32c -> crc32c;
            auto -> tx_checksum(A)
        end,
    Bin = webrtc_sctp_chunk:encode(Pkt, #{checksum => Cs}),
    A1 = bump(packets_sent, A),
    A1#assoc{acts = [{send, Bin} | A1#assoc.acts]}.

tx_checksum(#assoc{cfg = #cfg{zero_checksum = true}, peer = #{zero_checksum := true}}) -> zero;
tx_checksum(_) -> crc32c.

%% @doc Return the accumulated actions in order and clear them.
-spec take(#assoc{}) -> {#assoc{}, [term()]}.
take(#assoc{acts = Acts} = A) ->
    {A#assoc{acts = []}, lists:reverse(Acts)}.

%% @doc Emit everything that is due now.
-spec flush(integer(), #assoc{}) -> #assoc{}.
flush(Now, #assoc{state = St} = A0) when
    St =:= established; St =:= shutdown_pending; St =:= shutdown_received
->
    {Snd, Data, Evs} = webrtc_sctp_send:transmit(Now, A0#assoc.snd),
    A1 = lists:foldl(fun event/2, A0#assoc{snd = Snd}, Evs),
    A2 = webrtc_sctp_reconfig:poll(Now, A1),
    bundle(Now, Data, A2);
flush(Now, #assoc{state = St} = A) when St =:= shutdown_sent; St =:= shutdown_ack_sent ->
    bundle(Now, [], A);
flush(_Now, #assoc{} = A) ->
    A#assoc{ctrl = []}.

bundle(Now, Data, #assoc{ctrl = Ctrl0, rcv = Rcv0, snd = #snd{mtu = Mtu}} = A) ->
    Ctrl = lists:reverse(Ctrl0),
    {First, Others} = lists:partition(fun(X) -> X =:= cookie_ack end, Ctrl),
    WantSack =
        webrtc_sctp_recv:sack_wanted(Now, Rcv0) orelse
            (Data =/= [] andalso webrtc_sctp_recv:ack_pending(Rcv0)),
    {Rcv, Sack} =
        case WantSack of
            true ->
                {R1, S} = webrtc_sctp_recv:build_sack(Mtu - ?SCTP_COMMON_HEADER_SIZE, Rcv0),
                {R1, [S]};
            false ->
                {Rcv0, []}
        end,
    Chunks = First ++ Sack ++ Others ++ Data,
    A1 = A#assoc{ctrl = [], rcv = Rcv},
    lists:foldl(
        fun(Pkt, Acc) -> raw(Acc#assoc.peer_vtag, Pkt, auto, Acc) end,
        A1,
        pack(Chunks, Mtu)
    ).

%% Greedy packing preserving chunk order.
pack([], _Mtu) ->
    [];
pack(Chunks, Mtu) ->
    pack(Chunks, Mtu, ?SCTP_COMMON_HEADER_SIZE, [], []).

pack([], _Mtu, _Size, [], Pkts) ->
    lists:reverse(Pkts);
pack([], _Mtu, _Size, Cur, Pkts) ->
    lists:reverse([lists:reverse(Cur) | Pkts]);
pack([C | Rest], Mtu, Size, Cur, Pkts) ->
    CS = webrtc_sctp_chunk:chunk_size(C),
    case Size + CS =< Mtu orelse Cur =:= [] of
        true -> pack(Rest, Mtu, Size + CS, [C | Cur], Pkts);
        false -> pack([C | Rest], Mtu, ?SCTP_COMMON_HEADER_SIZE, [], [lists:reverse(Cur) | Pkts])
    end.

%% @doc The association is over: stop every timer and report `Reason'.
-spec terminate(term(), #assoc{}) -> #assoc{}.
terminate(Reason, #assoc{snd = Snd, rcv = Rcv, rcf = Rcf} = A) ->
    A1 = A#assoc{
        state = closed,
        terminated = true,
        t1 = undefined,
        t2 = undefined,
        hb_at = undefined,
        hb_out = undefined,
        ctrl = [],
        snd = Snd#snd{t3 = undefined, zwp = undefined},
        rcv = Rcv#rcv{sack_at = undefined, sack_now = false},
        rcf = Rcf#rcf{inflight = undefined}
    },
    event({closed, Reason}, A1).

-spec bump(atom(), #assoc{}) -> #assoc{}.
bump(K, A) -> bump(K, 1, A).

-spec bump(atom(), non_neg_integer(), #assoc{}) -> #assoc{}.
bump(K, N, #assoc{stats = St} = A) ->
    A#assoc{stats = maps:update_with(K, fun(V) -> V + N end, N, St)}.
