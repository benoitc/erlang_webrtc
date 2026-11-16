%% @private Handshake message reassembly shared by DTLS 1.2 (RFC 6347
%% §4.2.3) and DTLS 1.3 (RFC 9147 §5.5). Fragments may overlap; all
%% fragments of one message must use the same type, length and epoch.
%% Complete messages are delivered in message_seq order to the
%% handshake logic of the negotiated version.
-module(webrtc_dtls_reasm).

-include("webrtc_dtls.hrl").

-export([fragment/4, classify/2, add/3, deliver/2]).

-ifdef(TEST).
-export([peek/2]).
-endif.

-define(MAX_MSG_LEN, 131072).
-define(REASM_AHEAD, 8).
%% At most this many disjoint ranges per message: fragments that only
%% extend a range (however small, RFC 6347 §4.2.3 allows any size) never
%% count against it.
-define(MAX_PIECES, 256).
-define(MAX_HELD, 262144).
%% A range's data is an iolist of the fragments it joined; past this
%% many it is copied into one binary, so tiny fragments do not pile up.
-define(FLATTEN, 32).

-record(msg, {
    type :: webrtc_dtls_msg:msg_type(),
    len :: non_neg_integer(),
    epoch :: non_neg_integer(),
    %% Sorted disjoint, non-adjacent intervals {Start, End, iodata(),
    %% binaries in it}.
    ivs = [] :: [{non_neg_integer(), non_neg_integer(), iodata(), pos_integer()}],
    covered = 0 :: non_neg_integer()
}).

%% @doc DTLS 1.2 entry point (and the hello exchange before a version
%% is chosen): handle one fragment, detect peer retransmissions.
-spec fragment(webrtc_dtls_msg:fragment(), non_neg_integer(), integer(), #dtls{}) -> #dtls{}.
fragment(#{length := Len}, _E, _Now, St) when Len > ?MAX_MSG_LEN ->
    webrtc_dtls:fail(?ALERT_HANDSHAKE_FAILURE, message_too_large, St);
fragment(#{seq := Seq, type := client_hello} = F, E, Now, #dtls{state = wait_client_hello} = St) when
    Seq > St#dtls.recv_msg_seq
->
    %% A stateless server takes the message sequence from the client's
    %% ClientHello (RFC 6347 §4.2.2, RFC 9147 §5.2).
    fragment(F, E, Now, St#dtls{recv_msg_seq = Seq, reasm = #{}});
fragment(F, E, Now, St) ->
    case classify(F, St) of
        old -> webrtc_dtls12:peer_retransmitted(Now, St);
        new -> deliver(Now, add(F, E, St));
        ignore -> St
    end.

%% @doc `old': a message already processed (a retransmission); `new':
%% the next expected message or one shortly after it, buffered;
%% `ignore': too far ahead, discarded (and so never acknowledged).
-spec classify(webrtc_dtls_msg:fragment(), #dtls{}) -> old | new | ignore.
classify(#{seq := Seq}, #dtls{recv_msg_seq = Next}) when Seq < Next -> old;
classify(#{seq := Seq, length := L}, #dtls{recv_msg_seq = Next}) when
    Seq < Next + ?REASM_AHEAD, L =< ?MAX_MSG_LEN
->
    new;
classify(_, _) ->
    ignore.

%% @doc Buffer a fragment.
%%
%% A message is kept as sorted, disjoint intervals of the bytes received
%% so far. A new fragment is trimmed to the bytes not covered yet, so the
%% bytes held never exceed the advertised length however the peer
%% overlaps its fragments; completion is a counter check. Fragments are
%% dropped, as any invalid record would be, when they would leave a
%% message in more than ?MAX_PIECES disjoint ranges or all buffered
%% messages above ?MAX_HELD bytes.
-spec add(webrtc_dtls_msg:fragment(), non_neg_integer(), #dtls{}) -> #dtls{}.
add(#{length := Len}, _E, St) when Len > ?MAX_MSG_LEN ->
    webrtc_dtls:fail(?ALERT_HANDSHAKE_FAILURE, message_too_large, St);
add(#{type := T, length := L, seq := Seq, offset := Off, data := D}, E, #dtls{reasm = R} = St) ->
    case maps:get(Seq, R, #msg{type = T, len = L, epoch = E}) of
        #msg{type = T, len = L, epoch = E} = M ->
            case insert(Off, D, M, held(R)) of
                {ok, M1} -> St#dtls{reasm = R#{Seq => M1}};
                drop -> St
            end;
        #msg{type = T, len = L} ->
            %% A fragment of the same message in another epoch cannot
            %% be genuine; ignore it.
            St;
        _ ->
            %% Inconsistent type or length for the same message sequence.
            webrtc_dtls:fail(?ALERT_ILLEGAL_PARAMETER, inconsistent_fragment, St)
    end.

held(R) ->
    maps:fold(fun(_, #msg{covered = C}, Acc) -> Acc + C end, 0, R).

insert(Off, D, #msg{ivs = Ivs, covered = C} = M, Held) ->
    New = gaps(Off, Off + byte_size(D), Ivs),
    Bytes = lists:sum([E - S || {S, E} <- New]),
    case New =:= [] orelse Held + Bytes > ?MAX_HELD of
        true when New =:= [] ->
            {ok, M};
        true ->
            drop;
        false ->
            Pieces = [{S, E, binary:part(D, S - Off, E - S), 1} || {S, E} <- New],
            Ivs1 = merge(lists:keymerge(1, Ivs, Pieces)),
            case length(Ivs1) > ?MAX_PIECES of
                true -> drop;
                false -> {ok, M#msg{ivs = Ivs1, covered = C + Bytes}}
            end
    end.

%% Sub-ranges of [S, E) not covered by the sorted disjoint intervals.
gaps(S, E, _) when S >= E -> [];
gaps(S, E, []) -> [{S, E}];
gaps(S, E, [{_IS, IE, _, _} | Rest]) when IE =< S -> gaps(S, E, Rest);
gaps(S, E, [{IS, _, _, _} | _]) when IS >= E -> [{S, E}];
gaps(S, E, [{IS, IE, _, _} | Rest]) when IS > S -> [{S, IS} | gaps(IE, E, Rest)];
gaps(_S, E, [{_IS, IE, _, _} | Rest]) -> gaps(IE, E, Rest).

%% Join adjacent intervals; their data is an iolist, so joining copies
%% nothing until a range holds ?FLATTEN fragments.
merge([{S1, E1, D1, N1}, {E1, E2, D2, N2} | Rest]) when N1 + N2 > ?FLATTEN ->
    merge([{S1, E2, iolist_to_binary([D1, D2]), 1} | Rest]);
merge([{S1, E1, D1, N1}, {E1, E2, D2, N2} | Rest]) ->
    merge([{S1, E2, [D1, D2], N1 + N2} | Rest]);
merge([I | Rest]) -> [I | merge(Rest)];
merge([]) -> [].

%% @doc Deliver complete messages in order.
-spec deliver(integer(), #dtls{}) -> #dtls{}.
deliver(Now, #dtls{recv_msg_seq = Next, reasm = R} = St) ->
    case maps:find(Next, R) of
        {ok, #msg{type = T, len = L, epoch = E, covered = L, ivs = Ivs}} ->
            Body =
                case Ivs of
                    [] -> <<>>;
                    [{0, L, Io, _}] -> iolist_to_binary(Io)
                end,
            St1 = St#dtls{recv_msg_seq = Next + 1, reasm = maps:remove(Next, R)},
            St2 =
                case St1#dtls.version of
                    dtls13 ->
                        webrtc_dtls13_hs:handle(T, Body, E, Now, St1);
                    _ ->
                        webrtc_dtls_hs:handle(T, Body, webrtc_dtls_msg:full(T, Next, Body), Now, St1)
                end,
            case St2#dtls.state of
                S when S =:= failed; S =:= closed -> St2;
                _ -> deliver(Now, St2)
            end;
        _ ->
            St
    end.

-ifdef(TEST).
%% Test helper: `{Covered, Ranges, Body | incomplete}' of a buffered
%% message, or `none'.
peek(Seq, #dtls{reasm = R}) ->
    case maps:find(Seq, R) of
        {ok, #msg{len = L, covered = L, ivs = [{0, L, Io, _}]}} -> {L, 1, iolist_to_binary(Io)};
        {ok, #msg{covered = C, ivs = Ivs}} -> {C, length(Ivs), incomplete};
        error -> none
    end.
-endif.
