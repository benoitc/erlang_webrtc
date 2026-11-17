%% @private DTLS 1.3 epochs (RFC 9147 §6.1) and KeyUpdate (§8): traffic
%% keys per epoch, the next application traffic secret, and the rule
%% that new sending keys are only used once the KeyUpdate is
%% acknowledged (with erratum 8047). Epochs are limited to 2^16-1
%% (erratum 8050).
-module(webrtc_dtls13_epoch).

-include("webrtc_dtls.hrl").

-export([install_read/3, install_write/3, start_key_update/2, key_update_acked/1, peer_key_update/2]).

-import(webrtc_dtls, [fail/3]).

-define(MAX_EPOCH, 16#FFFF).

%% @doc Install the read keys of `Epoch'. From epoch 4 on (KeyUpdate),
%% only the previous epoch is kept for reordered records (§8).
-spec install_read(non_neg_integer(), binary(), #dtls{}) -> #dtls{}.
install_read(Epoch, Secret, #dtls{suite13 = Suite, read_keys = RK, replay = Rp} = St) ->
    Keys = webrtc_dtls13_keys:traffic_keys(webrtc_dtls13_keys:prefix(), Suite, Secret),
    RK1 = RK#{Epoch => Keys#{failures => 0}},
    {RK2, Rp1} =
        case Epoch >= 4 of
            true ->
                Keep = fun(E, _) -> E >= Epoch - 1 end,
                {maps:filter(Keep, RK1), maps:filter(fun(E, V) -> E =:= 0 orelse Keep(E, V) end, Rp)};
            false ->
                {RK1, Rp}
        end,
    St#dtls{read_keys = RK2, replay = Rp1, prev_epoch_until = undefined}.

%% @doc Install the write keys of `Epoch' and make it the write epoch.
-spec install_write(non_neg_integer(), binary(), #dtls{}) -> #dtls{}.
install_write(Epoch, Secret, #dtls{suite13 = Suite} = St) ->
    Keys = webrtc_dtls13_keys:traffic_keys(webrtc_dtls13_keys:prefix(), Suite, Secret),
    St#dtls{
        write_ciphers = maps:put(Epoch, Keys, St#dtls.write_ciphers),
        write_seq = maps:put(Epoch, 0, St#dtls.write_seq),
        write_epoch = Epoch
    }.

%% @doc Queue a KeyUpdate (§8). Our keys change once it is acknowledged.
-spec start_key_update(update_requested | update_not_requested, #dtls{}) -> #dtls{}.
start_key_update(_Req, #dtls{ku_pending = true} = St) ->
    St;
start_key_update(_Req, #dtls{write_epoch = E} = St) when E >= ?MAX_EPOCH ->
    St;
start_key_update(Req, St) ->
    Body = webrtc_dtls13_msg:encode(key_update, Req),
    {_, St1} = webrtc_dtls:queue_handshake(key_update, Body, false, St),
    St1#dtls{ku_pending = true}.

%% @doc Our KeyUpdate was acknowledged: switch to the next epoch.
-spec key_update_acked(#dtls{}) -> #dtls{}.
key_update_acked(#dtls{write_epoch = E, write_ciphers = WC} = St) ->
    #{secret := S, hash := H} = maps:get(E, WC),
    Next = webrtc_dtls13_keys:next_secret(webrtc_dtls13_keys:prefix(), H, S),
    St1 = install_write(E + 1, Next, St#dtls{ku_pending = false}),
    %% Records not acknowledged yet keep their ACK timer, and the ACK
    %% goes in the new epoch.
    St1#dtls{
        write_ciphers = maps:with([E + 1], St1#dtls.write_ciphers),
        write_seq = maps:with([0, E + 1], St1#dtls.write_seq)
    }.

%% @doc The peer updated its keys: install the next read epoch,
%% acknowledge, and update ours if asked to (§8).
-spec peer_key_update({update_requested | update_not_requested, non_neg_integer()}, #dtls{}) -> #dtls{}.
peer_key_update({Req, E}, #dtls{read_keys = RK} = St) ->
    E =:= lists:max(maps:keys(RK)) orelse fail(?ALERT_UNEXPECTED_MESSAGE, key_update_wrong_epoch, St),
    E < ?MAX_EPOCH orelse fail(?ALERT_INTERNAL_ERROR, epoch_exhausted, St),
    %% Handshake messages must not span a key change (RFC 8446 §5.1).
    webrtc_dtls_reasm:pending(E, St) andalso fail(?ALERT_UNEXPECTED_MESSAGE, message_after_key_update, St),
    #{secret := S, hash := H} = maps:get(E, RK),
    Next = webrtc_dtls13_keys:next_secret(webrtc_dtls13_keys:prefix(), H, S),
    %% Acknowledged on the ACK timer, with the rest of its flight (§7.1).
    St1 = install_read(E + 1, Next, St),
    %% Asked to update too: the ACK goes first, then our KeyUpdate
    %% (Figure 14), before any more data (RFC 8446 §4.6.3). Otherwise the
    %% ACK waits for the ACK timer.
    case Req of
        update_requested when not St1#dtls.ku_pending ->
            start_key_update(update_not_requested, St1#dtls{ack_now = true});
        _ ->
            St1
    end.

