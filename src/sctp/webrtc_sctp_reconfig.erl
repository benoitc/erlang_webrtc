%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc SCTP stream reconfiguration (RFC 6525).
%%
%% Internal module of `webrtc_sctp_assoc'. Supported requests:
%%
%% - Outgoing SSN Reset Request, sent by `reset_streams/3' once every
%%   message queued on the streams before the call has a TSN. Messages
%%   sent on these streams after the call wait until the reset
%%   completes and then start again at sequence number 0.
%% - Incoming Outgoing SSN Reset Requests, with deferred processing when
%%   the peer's last assigned TSN was not received yet (§5.2.2 E2).
%% - Incoming SSN Reset Requests, answered with an Outgoing SSN Reset
%%   Request for the same streams (§5.2.3).
%% - Add Outgoing Streams requests from the peer, accepted up to 65535
%%   incoming streams.
%%
%% SSN/TSN Reset and Add Incoming Streams requests are answered with
%% "Denied". Only one request is in flight at a time (§5.1.1); it is
%% retransmitted with the RTO and exponential backoff.
-module(webrtc_sctp_reconfig).

-include("webrtc_sctp_assoc.hrl").

-export([start/4, request/3, poll/2, handle/3, timeout/2, next_timeout/1, deferred_done/2]).

-spec start(0..16#FFFFFFFF, 0..16#FFFFFFFF, boolean(), #rcf{}) -> #rcf{}.
start(MyItsn, PeerItsn, Enabled, _Rcf) ->
    #rcf{enabled = Enabled, my_seq = MyItsn, peer_seq = PeerItsn}.

%% @doc Queue an outgoing reset of `Sids'.
-spec request([0..65535], integer(), #assoc{}) -> {ok, #assoc{}} | {error, atom()}.
request(_Sids, _Now, #assoc{rcf = #rcf{enabled = false}}) ->
    {error, not_supported};
request(Sids, _Now, #assoc{rcf = Rcf, snd = Snd} = A) ->
    OS = Snd#snd.os,
    case
        Sids =/= [] andalso
            lists:all(fun(S) -> is_integer(S) andalso S >= 0 andalso S < OS end, Sids)
    of
        false ->
            {error, invalid_stream};
        true ->
            Snd1 = webrtc_sctp_send:pause_streams(Sids, Snd),
            Pending = lists:usort(Rcf#rcf.pending ++ Sids),
            {ok, A#assoc{snd = Snd1, rcf = Rcf#rcf{pending = Pending}}}
    end.

%% @doc Send the next request when none is in flight and some pending
%% streams are drained.
-spec poll(integer(), #assoc{}) -> #assoc{}.
poll(Now, #assoc{rcf = #rcf{inflight = undefined, pending = [_ | _] = Pending} = Rcf} = A) ->
    #assoc{snd = Snd, cfg = C} = A,
    %% Keep the RE-CONFIG chunk within one packet.
    Max = (C#cfg.mtu - ?SCTP_COMMON_HEADER_SIZE - 4 - 16) div 2,
    case lists:sublist(webrtc_sctp_send:drained(Pending, Snd), Max) of
        [] ->
            A;
        Sids ->
            Seq = Rcf#rcf.my_seq band ?U32,
            RespSeq =
                case Rcf#rcf.resp_for of
                    undefined -> (Rcf#rcf.peer_seq - 1) band ?U32;
                    R -> R
                end,
            Param = {out_reset, Seq, RespSeq, webrtc_sctp_send:last_assigned_tsn(Snd), Sids},
            Rto = Snd#snd.rto,
            Rcf1 = Rcf#rcf{
                my_seq = Rcf#rcf.my_seq + 1,
                pending = Pending -- Sids,
                resp_for = undefined,
                inflight = #{
                    seq => Seq,
                    param => Param,
                    sids => Sids,
                    deadline => Now + Rto,
                    rto => Rto,
                    counted => true
                }
            },
            webrtc_sctp_out:ctrl({reconfig, [Param]}, A#assoc{rcf = Rcf1})
    end;
poll(_Now, A) ->
    A.

%% @doc Process the parameters of a received RE-CONFIG chunk; responses
%% go back in one RE-CONFIG chunk (§5.2.1).
-spec handle([term()], integer(), #assoc{}) -> #assoc{}.
handle(Params, Now, A0) ->
    {A, Resps} = lists:foldl(
        fun(P, {Acc, Rs}) ->
            {Acc1, R} = param(P, Now, Acc),
            {Acc1, Rs ++ R}
        end,
        {A0, []},
        Params
    ),
    Requests = [P || P <- Params, is_request(P)],
    A1 =
        case Requests of
            [] -> A;
            _ -> A#assoc{rcv = (A#assoc.rcv)#rcv{sack_now = true}}
        end,
    case Resps of
        [] -> A1;
        _ -> webrtc_sctp_out:ctrl({reconfig, Resps}, A1)
    end.

is_request({reconf_response, _, _, _}) -> false;
is_request({unknown_param, _, _}) -> false;
is_request(_) -> true.

param({out_reset, Seq, _, _, _}, _Now, #assoc{rcf = Rcf, rcv = #rcv{deferred = [_ | _]}} = A) when
    Seq =:= Rcf#rcf.peer_seq band ?U32
->
    %% A new request while an earlier one is still deferred: the peer
    %% has more than one request in flight (§5.1.1). Do not queue it.
    {A, resp(Seq, error_request_in_progress)};
param({out_reset, Seq, _RespSeq, LastTsn, Sids}, _Now, A) ->
    request_seq(Seq, A, fun(Acc) ->
        Rcv = Acc#assoc.rcv,
        case lists:all(fun(S) -> S < Rcv#rcv.mis end, Sids) of
            false ->
                {Acc, resp(Seq, denied)};
            true ->
                case webrtc_sctp_recv:reset_incoming(Sids, LastTsn, Seq, Rcv) of
                    {done, Rcv1} ->
                        Acc1 = webrtc_sctp_out:event({stream_reset, Sids}, Acc#assoc{rcv = Rcv1}),
                        {Acc1, resp(Seq, success_performed)};
                    {deferred, Rcv1} ->
                        {Acc#assoc{rcv = Rcv1}, resp(Seq, in_progress)}
                end
        end
    end);
param({in_reset, Seq, Sids}, _Now, A) ->
    request_seq(Seq, A, fun(#assoc{snd = Snd, rcf = Rcf} = Acc) ->
        OS = Snd#snd.os,
        case Sids =/= [] andalso lists:all(fun(S) -> S < OS end, Sids) of
            false ->
                {Acc, resp(Seq, denied)};
            true ->
                Snd1 = webrtc_sctp_send:pause_streams(Sids, Snd),
                Rcf1 = Rcf#rcf{pending = lists:usort(Rcf#rcf.pending ++ Sids), resp_for = Seq},
                {Acc#assoc{snd = Snd1, rcf = Rcf1}, []}
        end
    end);
param({tsn_reset, Seq}, _Now, A) ->
    request_seq(Seq, A, fun(Acc) -> {Acc, resp(Seq, denied)} end);
param({add_in_streams, Seq, _N}, _Now, A) ->
    request_seq(Seq, A, fun(Acc) -> {Acc, resp(Seq, denied)} end);
param({add_out_streams, Seq, N}, _Now, A) ->
    request_seq(Seq, A, fun(#assoc{rcv = Rcv} = Acc) ->
        case Rcv#rcv.mis + N =< 65535 of
            true ->
                {
                    Acc#assoc{rcv = webrtc_sctp_recv:add_streams(N, Rcv)},
                    resp(Seq, success_performed)
                };
            false ->
                {Acc, resp(Seq, denied)}
        end
    end);
param({reconf_response, RespSeq, Result, _}, Now, #assoc{rcf = Rcf} = A) ->
    case Rcf#rcf.inflight of
        #{seq := RespSeq, sids := Sids} = Inf ->
            response(Result, Sids, Inf, Now, A);
        _ ->
            {A, []}
    end;
param(_Unknown, _Now, A) ->
    {A, []}.

%% Request sequence number checks (§5.2.1 and Table 3 "Bad Sequence
%% Number"). A retransmitted request gets the previous answer again.
request_seq(Seq, #assoc{rcf = Rcf} = A, Fun) ->
    Expected = Rcf#rcf.peer_seq band ?U32,
    Previous = (Rcf#rcf.peer_seq - 1) band ?U32,
    if
        Seq =:= Expected ->
            {A1, R} = Fun(A#assoc{rcf = Rcf#rcf{peer_seq = Rcf#rcf.peer_seq + 1}}),
            Rcf1 = A1#assoc.rcf,
            {A1#assoc{rcf = Rcf1#rcf{last_resp = {Seq, R}}}, R};
        Seq =:= Previous ->
            case webrtc_sctp_recv:deferred_seq(Seq, A#assoc.rcv) of
                true ->
                    {A, resp(Seq, in_progress)};
                false ->
                    case Rcf#rcf.last_resp of
                        {Seq, []} -> {A, resp(Seq, in_progress)};
                        {Seq, R} -> {A, R};
                        _ -> {A, resp(Seq, success_nothing_to_do)}
                    end
            end;
        true ->
            {A, resp(Seq, error_bad_sequence_number)}
    end.

resp(Seq, Result) -> [{reconf_response, Seq, Result, undefined}].

%% §5.2.7 H1 to H4.
response(Result, Sids, Inf, Now, #assoc{rcf = Rcf, snd = Snd} = A) when
    Result =:= success_performed; Result =:= success_nothing_to_do
->
    _ = Inf,
    _ = Now,
    A1 = A#assoc{
        snd = webrtc_sctp_send:reset_streams(Sids, Snd),
        rcf = Rcf#rcf{inflight = undefined}
    },
    {webrtc_sctp_out:event({outgoing_stream_reset, Sids}, A1), []};
response(Result, _Sids, Inf, Now, #assoc{rcf = Rcf} = A) when
    Result =:= in_progress; Result =:= error_request_in_progress
->
    Rto = maps:get(rto, Inf),
    {A#assoc{rcf = Rcf#rcf{inflight = Inf#{deadline := Now + Rto, counted := false}}}, []};
response(Result, Sids, _Inf, _Now, #assoc{rcf = Rcf, snd = Snd} = A) ->
    A1 = A#assoc{
        snd = webrtc_sctp_send:resume_streams(Sids, Snd),
        rcf = Rcf#rcf{inflight = undefined}
    },
    {webrtc_sctp_out:event({stream_reset_failed, Sids, Result}, A1), []}.

%% @doc Retransmit the request in flight if its timer expired. Returns
%% whether the expiry counts toward the error counter (§5.1.1, H2).
-spec timeout(integer(), #assoc{}) -> {#assoc{}, boolean()}.
timeout(Now, #assoc{rcf = #rcf{inflight = #{deadline := D} = Inf} = Rcf, cfg = C} = A) when
    Now >= D
->
    #{param := Param, rto := Rto, counted := Counted} = Inf,
    Rto1 = min(2 * Rto, C#cfg.rto_max),
    Inf1 = Inf#{deadline := Now + Rto1, rto := Rto1, counted := true},
    A1 = webrtc_sctp_out:ctrl({reconfig, [Param]}, A#assoc{rcf = Rcf#rcf{inflight = Inf1}}),
    {webrtc_sctp_out:bump(reconfig_retransmissions, A1), Counted};
timeout(_Now, A) ->
    {A, false}.

-spec next_timeout(#assoc{}) -> integer() | infinity.
next_timeout(#assoc{rcf = #rcf{inflight = #{deadline := D}}}) -> D;
next_timeout(_) -> infinity.

%% @doc Deferred incoming resets completed: answer "Success - Performed"
%% (§5.2.2 E5).
-spec deferred_done([non_neg_integer()], #assoc{}) -> #assoc{}.
deferred_done([], A) ->
    A;
deferred_done(Seqs, #assoc{rcf = Rcf} = A) ->
    Resps = lists:append([resp(S, success_performed) || S <- Seqs]),
    Last =
        case Rcf#rcf.last_resp of
            {S, _} = LR ->
                case lists:member(S, Seqs) of
                    true -> {S, resp(S, success_performed)};
                    false -> LR
                end;
            undefined ->
                undefined
        end,
    webrtc_sctp_out:ctrl({reconfig, Resps}, A#assoc{rcf = Rcf#rcf{last_resp = Last}}).
