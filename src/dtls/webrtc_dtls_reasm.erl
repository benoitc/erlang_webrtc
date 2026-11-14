%% @private Handshake message reassembly shared by DTLS 1.2 (RFC 6347
%% §4.2.3) and DTLS 1.3 (RFC 9147 §5.5). Fragments may overlap; all
%% fragments of one message must use the same type, length and epoch.
%% Complete messages are delivered in message_seq order to the
%% handshake logic of the negotiated version.
-module(webrtc_dtls_reasm).

-include("webrtc_dtls.hrl").

-export([fragment/4, classify/2, add/3, deliver/2]).

-define(MAX_MSG_LEN, 131072).
-define(REASM_AHEAD, 8).

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
-spec add(webrtc_dtls_msg:fragment(), non_neg_integer(), #dtls{}) -> #dtls{}.
add(#{length := Len}, _E, St) when Len > ?MAX_MSG_LEN ->
    webrtc_dtls:fail(?ALERT_HANDSHAKE_FAILURE, message_too_large, St);
add(#{type := T, length := L, seq := Seq, offset := Off, data := D}, E, #dtls{reasm = R} = St) ->
    case maps:get(Seq, R, {T, L, E, #{}}) of
        {T, L, E, Pieces} ->
            St#dtls{reasm = R#{Seq => {T, L, E, Pieces#{Off => D}}}};
        {T, L, _OtherEpoch, _} ->
            %% A fragment of the same message in another epoch cannot
            %% be genuine; ignore it.
            St;
        _ ->
            %% Inconsistent type or length for the same message sequence.
            webrtc_dtls:fail(?ALERT_ILLEGAL_PARAMETER, inconsistent_fragment, St)
    end.

%% @doc Deliver complete messages in order.
-spec deliver(integer(), #dtls{}) -> #dtls{}.
deliver(Now, #dtls{recv_msg_seq = Next, reasm = R} = St) ->
    case maps:find(Next, R) of
        {ok, {T, L, E, Pieces}} ->
            case assemble(L, lists:sort(maps:to_list(Pieces)), 0, []) of
                {ok, Body} ->
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
                incomplete ->
                    St
            end;
        error ->
            St
    end.

%% Pieces may overlap (retransmissions with a different fragmentation).
assemble(L, _Pieces, Pos, Acc) when Pos >= L ->
    {ok, iolist_to_binary(lists:reverse(Acc))};
assemble(_L, [], _Pos, _Acc) ->
    incomplete;
assemble(L, [{Off, _} | _], Pos, _Acc) when Off > Pos, Off < L ->
    incomplete;
assemble(L, [{Off, D} | Rest], Pos, Acc) ->
    End = Off + byte_size(D),
    case End =< Pos of
        true ->
            assemble(L, Rest, Pos, Acc);
        false ->
            Skip = Pos - Off,
            <<_:Skip/binary, New/binary>> = D,
            assemble(L, Rest, End, [New | Acc])
    end.
