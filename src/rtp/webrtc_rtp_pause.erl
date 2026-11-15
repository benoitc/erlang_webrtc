%% @doc RTP stream pause and resume (RFC 7728), without I/O.
%%
%% Two sides, one state per RTP stream:
%%
%% <ul>
%% <li>the stream sender (`sender/1'): honours PAUSE and RESUME carrying
%%     the current PauseID, answers others with REFUSED, sends PAUSED
%%     when it pauses and in the next two regular reports (§6.2), and
%%     moves to the next PauseID when it resumes (§8.1);</li>
%% <li>the requester (`requester/0'): sends PAUSE or RESUME for a
%%     stream it receives, retransmits it after 2 * RTT + T_dither_max
%%     until the sender answers (§6.1, §6.4), and learns the current
%%     PauseID from PAUSED and REFUSED.</li>
%% </ul>
%%
%% Messages are `{Type, PauseId}' or `{paused, PauseId, ExtSeq}'; the
%% caller puts them in RTPFB PAUSE-RESUME packets (`#rtcp_pause{}') for
%% the stream's SSRC.
-module(webrtc_rtp_pause).

-export([
    sender/1,
    sender_in/5,
    sender_timeout/2,
    sender_report/2,
    sender_next_timeout/1,
    is_paused/1,
    requester/0,
    request/3,
    requester_in/3,
    requester_rtp/1,
    requester_timeout/3,
    requester_next_timeout/1,
    remote_state/1
]).

-export_type([sender/0, requester/0, message/0, event/0]).

%% Retransmission time when no RTT is known (RFC 7728 §6.1).
-define(DEFAULT_RETX, 500).

-record(snd, {
    state = playing :: playing | {pausing, integer()} | paused,
    id = 0 :: 0..65535,
    %% Regular reports that still repeat PAUSED (§6.2).
    repeats = 0 :: non_neg_integer(),
    %% Last sequence number sent before the pause.
    seq = 0 :: non_neg_integer()
}).

-record(req, {
    id = 0 :: 0..65535,
    %% What we asked for and have no answer to yet.
    want = none :: none | pause | resume,
    retx_at = infinity :: integer() | infinity,
    %% What the sender told us.
    remote = playing :: playing | paused
}).

-opaque sender() :: #snd{}.
-opaque requester() :: #req{}.
-type message() :: {pause | resume | refused, 0..65535} | {paused, 0..65535, non_neg_integer()}.
-type event() :: none | paused | resumed | refused.

%%====================================================================
%% Stream sender
%%====================================================================

%% @doc A sender, paused from the start when the answer marked the
%% stream paused (RFC 8853 §5.3).
-spec sender(boolean()) -> sender().
sender(true) -> #snd{state = paused};
sender(false) -> #snd{}.

-spec is_paused(sender()) -> boolean().
is_paused(#snd{state = paused}) -> true;
is_paused(#snd{}) -> false.

%% @doc A PAUSE or RESUME from the requester. `HoldOff' is 0 when
%% `nowait' was negotiated, 2 * RTT + T_dither_max otherwise (§6.2);
%% `Seq' is the extended sequence number of the last packet sent.
-spec sender_in(pause | resume, 0..65535, non_neg_integer(), {integer(), non_neg_integer()}, sender()) ->
    {sender(), [message()], event()}.
sender_in(pause, Id, Seq, {Now, HoldOff}, #snd{state = playing, id = Id} = S) ->
    case HoldOff of
        0 -> pause_now(Seq, S);
        _ -> {S#snd{state = {pausing, Now + HoldOff}}, [], none}
    end;
sender_in(pause, Id, _Seq, _T, #snd{id = Id} = S) ->
    %% Already pausing or paused.
    {S, [], none};
sender_in(resume, Id, _Seq, _T, #snd{state = playing, id = Cur} = S) ->
    case Id =:= Cur orelse past(Id, Cur) of
        true -> {S, [], none};
        false -> {S, [{refused, Cur}], none}
    end;
sender_in(resume, Id, _Seq, _T, #snd{state = {pausing, _}, id = Id} = S) ->
    %% Disapproved during the hold-off: keep playing (§6.2).
    {S#snd{state = playing}, [], none};
sender_in(resume, Id, _Seq, _T, #snd{state = paused, id = Id} = S) ->
    {S#snd{state = playing, id = next(Id), repeats = 0}, [], resumed};
sender_in(_Type, _Id, _Seq, _T, #snd{id = Cur} = S) ->
    {S, [{refused, Cur}], none}.

pause_now(Seq, #snd{id = Id} = S) ->
    {S#snd{state = paused, repeats = 2, seq = Seq}, [{paused, Id, Seq}], paused}.

%% @doc The hold-off is over: pause.
-spec sender_timeout({integer(), non_neg_integer()}, sender()) -> {sender(), [message()], event()}.
sender_timeout({Now, Seq}, #snd{state = {pausing, At}} = S) when Now >= At ->
    pause_now(Seq, S);
sender_timeout(_, S) ->
    {S, [], none}.

-spec sender_next_timeout(sender()) -> integer() | infinity.
sender_next_timeout(#snd{state = {pausing, At}}) -> At;
sender_next_timeout(#snd{}) -> infinity.

%% @doc Messages to add to a regular report.
-spec sender_report(non_neg_integer(), sender()) -> {sender(), [message()]}.
sender_report(_Seq, #snd{state = paused, repeats = N, id = Id, seq = Last} = S) when N > 0 ->
    {S#snd{repeats = N - 1}, [{paused, Id, Last}]};
sender_report(_Seq, S) ->
    {S, []}.

%%====================================================================
%% Requester
%%====================================================================

-spec requester() -> requester().
requester() -> #req{}.

%% @doc Ask the sender to pause or resume. `Now' and the RTT in ms
%% (undefined when unknown) set the retransmission time.
-spec request(pause | resume, {integer(), undefined | non_neg_integer()}, requester()) ->
    {requester(), [message()]}.
request(Want, {Now, Rtt}, #req{id = Id} = R) ->
    {R#req{want = Want, retx_at = Now + retx(Rtt)}, [{Want, Id}]}.

%% @doc PAUSED or REFUSED from the sender.
-spec requester_in(message(), integer(), requester()) -> {requester(), event()}.
requester_in({paused, Id, _Seq}, _Now, #req{id = Cur} = R) ->
    case Id =:= Cur orelse future(Id, Cur) of
        true -> {R#req{id = Id, remote = paused, want = none, retx_at = infinity}, paused};
        false -> {R, none}
    end;
requester_in({refused, Id}, _Now, #req{want = W} = R) when W =/= none ->
    {R#req{id = Id, want = none, retx_at = infinity}, refused};
requester_in({refused, Id}, _Now, R) ->
    {R#req{id = Id}, none};
requester_in(_, _Now, R) ->
    {R, none}.

%% @doc An RTP packet of the stream arrived: a paused stream resumed,
%% and the sender moved to the next PauseID (§8.1).
-spec requester_rtp(requester()) -> {requester(), event()}.
requester_rtp(#req{remote = paused, id = Id} = R) ->
    {R#req{remote = playing, id = next(Id), want = none, retx_at = infinity}, resumed};
requester_rtp(#req{want = resume} = R) ->
    {R#req{want = none, retx_at = infinity}, none};
requester_rtp(R) ->
    {R, none}.

%% @doc Retransmit an unanswered request.
-spec requester_timeout(integer(), undefined | non_neg_integer(), requester()) -> {requester(), [message()]}.
requester_timeout(Now, Rtt, #req{want = W, retx_at = At} = R) when W =/= none, Now >= At ->
    request(W, {Now, Rtt}, R);
requester_timeout(_Now, _Rtt, R) ->
    {R, []}.

-spec requester_next_timeout(requester()) -> integer() | infinity.
requester_next_timeout(#req{retx_at = At}) -> At.

%% @doc What the sender last reported.
-spec remote_state(requester()) -> playing | paused.
remote_state(#req{remote = S}) -> S.

%%====================================================================
%% PauseID arithmetic (§8.1)
%%====================================================================

next(Id) -> (Id + 1) band 16#FFFF.

%% The half of the range before the current value.
past(Id, Cur) ->
    D = (Cur - Id) band 16#FFFF,
    D >= 1 andalso D =< 16#8000.

%% The quarter of the range after it.
future(Id, Cur) ->
    D = (Id - Cur) band 16#FFFF,
    D >= 1 andalso D =< 16#4000.

%% 2 * RTT + T_dither_max; point to point, T_dither_max is 0 (RFC 4585
%% §3.4).
retx(undefined) -> ?DEFAULT_RETX;
retx(Rtt) -> max(2 * Rtt, 20).
