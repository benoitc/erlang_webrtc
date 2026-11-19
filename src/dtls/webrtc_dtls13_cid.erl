%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @private DTLS 1.3 connection IDs after the handshake (RFC 9147 §9).
%%
%% <ul>
%% <li>We receive on a set of CIDs, all as long as the one we offered
%%     so records still parse with one length, at most 4. A record
%%     carrying another CID is dropped.</li>
%% <li>A RequestConnectionId is answered with spare CIDs added to that
%%     set, as many as asked for and fit. Once the peer's authenticated
%%     records carry another of our CIDs, the one they carried before is
%%     retired: it is still accepted (records sent before the switch may
%%     arrive late) until a request needs its room, so the peer can keep
%%     rotating.</li>
%% <li>Spare CIDs from the peer are kept (at most 8). `rotate/1' moves
%%     our records to the next one, so a new path cannot be linked to
%%     the old one by its CID (RFC 9146 §8); without one it asks for
%%     more and moves when they arrive.</li>
%% <li>One CID message at a time: it goes out when no flight is
%%     waiting for its ACK, else once that flight is acknowledged
%%     (§5.8.4).</li>
%% </ul>
-module(webrtc_dtls13_cid).

-include("webrtc_dtls.hrl").

-export([known/2, seen/2, received/3, rotate/1, flight_done/1]).

-define(MAX_OWN, 4).
-define(MAX_SPARES, 8).
-define(REQUEST, 2).

%% @doc Whether a record's CID is one we receive on.
-spec known(binary(), #dtls{}) -> boolean().
known(<<>>, _St) -> true;
known(Cid, #dtls{cids = Cids}) -> lists:member(Cid, Cids).

%% @doc An authenticated record of the peer carried `Cid'.
-spec seen(binary(), #dtls{}) -> #dtls{}.
seen(<<>>, St) ->
    St;
seen(Cid, #dtls{cid_in_use = Cid} = St) ->
    St;
seen(Cid, #dtls{cid_in_use = undefined} = St) ->
    St#dtls{cid_in_use = Cid};
seen(Cid, #dtls{cid_in_use = Old, cid_retired = R} = St) ->
    St#dtls{cid_in_use = Cid, cid_retired = [C || C <- R, C =/= Cid] ++ [Old]}.

%% @doc NewConnectionId or RequestConnectionId from the peer (CIDs
%% negotiated). Both are acknowledged (§5.7).
-spec received(new_connection_id | request_connection_id, term(), #dtls{}) -> #dtls{}.
received(new_connection_id, {[Cid | Rest], immediate}, St) ->
    spares(Rest, St#dtls{peer_cid = Cid, ack_now = true});
received(new_connection_id, {Cids, spare}, #dtls{rotate = Wanted} = St0) ->
    St = spares(Cids, St0#dtls{ack_now = true}),
    case Wanted of
        true -> rotate(St#dtls{rotate = false});
        false -> St
    end;
received(new_connection_id, {[], _}, St) ->
    St#dtls{ack_now = true};
received(request_connection_id, N, #dtls{cids = Own, cid_retired = R} = St) ->
    Room = case Own of [C | _] when byte_size(C) > 0 -> ?MAX_OWN - length(Own -- R); _ -> 0 end,
    case min(N, Room) of
        0 -> St#dtls{ack_now = true};
        K -> send({spares, K}, St#dtls{ack_now = true})
    end.

spares(Cids, #dtls{peer_spares = S, peer_cid = Cur} = St) ->
    New = [C || C <- Cids, C =/= Cur, not lists:member(C, S)],
    St#dtls{peer_spares = lists:sublist(S ++ New, ?MAX_SPARES)}.

%% @doc Send our next records with a fresh CID of the peer.
-spec rotate(#dtls{}) -> #dtls{}.
rotate(#dtls{peer_spares = [Next | Rest]} = St) ->
    St1 = St#dtls{peer_cid = Next, peer_spares = Rest},
    case Rest of
        [] -> send({request, ?REQUEST}, St1);
        _ -> St1
    end;
rotate(#dtls{peer_spares = []} = St) ->
    send({request, ?REQUEST}, St#dtls{rotate = true}).

%% @doc Our last flight was acknowledged: the next CID message, if any.
-spec flight_done(#dtls{}) -> #dtls{}.
flight_done(#dtls{cid_queue = [Msg | Rest]} = St) ->
    send(Msg, St#dtls{cid_queue = Rest});
flight_done(St) ->
    St.

send(Msg, #dtls{last_flight = [], building = [], state = connected} = St) ->
    queue(Msg, St);
send(Msg, #dtls{cid_queue = Q} = St) ->
    %% One of each kind waits; a later one replaces it.
    St#dtls{cid_queue = [M || M <- Q, element(1, M) =/= element(1, Msg)] ++ [Msg]}.

queue({request, N}, St) ->
    {_, St1} = webrtc_dtls:queue_handshake(request_connection_id, webrtc_dtls13_msg:encode(request_connection_id, N),
                                           false, St),
    St1;
queue({spares, K}, #dtls{cids = [C | _] = Own0, cid_retired = R0} = St) ->
    %% Retired CIDs make room, the oldest first.
    Drop = lists:sublist(R0, max(0, length(Own0) + K - ?MAX_OWN)),
    Own = Own0 -- Drop,
    New = fresh(K, byte_size(C), Own0),
    Body = webrtc_dtls13_msg:encode(new_connection_id, {New, spare}),
    {_, St1} = webrtc_dtls:queue_handshake(new_connection_id, Body, false,
                                           St#dtls{cids = Own ++ New, cid_retired = R0 -- Drop}),
    St1.

fresh(0, _Len, _Own) ->
    [];
fresh(K, Len, Own) ->
    C = crypto:strong_rand_bytes(Len),
    case lists:member(C, Own) of
        true -> fresh(K, Len, Own);
        false -> [C | fresh(K - 1, Len, [C | Own])]
    end.
