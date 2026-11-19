%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc Packetization layer path MTU discovery for SCTP over DTLS
%% (RFC 8899 §4, §5 and §6.2, RFC 8261 §5, RFC 8831 §5).
%%
%% Internal module of `webrtc_sctp_assoc'. The association starts at the
%% base size (`mtu', safe on every path) and, once established, probes
%% larger sizes up to `max_mtu' with HEARTBEAT chunks padded by a PAD
%% chunk (RFC 4820): each answered probe raises the packet size, three
%% unanswered probes of one size end the search there. Probe loss never
%% counts toward Association.Max.Retrans. A retransmission timeout above
%% the base (a possible black hole) or a path change goes back to the
%% base and searches again; a finished search is repeated after
%% RAISE_MS.
-module(webrtc_sctp_pmtu).

-include("webrtc_sctp_assoc.hrl").

-export([new/1, start/2, timeout/2, next_timeout/1, ack/3, black_hole/2, path_changed/2, mtu/1, info/1]).

-define(MAX_PROBES, 3).
-define(START_MS, 1000).
-define(RETRY_MS, 5000).
-define(RAISE_MS, 600000).
-define(PROBE_TAG, "PLPMTUD").

-type state() :: #{
    base := pos_integer(),
    max := pos_integer(),
    cur := pos_integer(),
    phase := off | idle | search | done,
    todo := [pos_integer()],
    probe := undefined | {pos_integer(), binary(), integer(), pos_integer()},
    at := undefined | integer()
}.
-export_type([state/0]).

-spec new(#cfg{}) -> state().
new(#cfg{mtu = Base, max_mtu = Max}) ->
    #{base => Base, max => max(Base, Max), cur => Base, phase => case Max > Base of true -> idle; false -> off end,
      todo => [], probe => undefined, at => undefined}.

%% @doc The association is established: search shortly.
-spec start(integer(), #assoc{}) -> #assoc{}.
start(Now, #assoc{pmtu = #{phase := idle} = P} = A) ->
    A#assoc{pmtu = P#{phase := search, todo := sizes(P), at := Now + ?START_MS}};
start(_Now, A) ->
    A.

%% Sizes to try above the current one, ascending, multiples of 4.
sizes(#{cur := Cur, max := Max}) when Max =< Cur ->
    [];
sizes(#{cur := Cur, max := Max}) ->
    Step = max(4, (Max - Cur) div 3),
    lists:usort([align(Cur + Step), align(Cur + 2 * Step), align(Max)]) -- [Cur].

align(N) -> N band (bnot 3).

-spec mtu(state()) -> pos_integer().
mtu(#{cur := Cur}) -> Cur.

-spec next_timeout(state()) -> integer() | infinity.
next_timeout(#{probe := {_, _, Deadline, _}}) -> Deadline;
next_timeout(#{at := At}) when is_integer(At) -> At;
next_timeout(_) -> infinity.

-spec timeout(integer(), #assoc{}) -> #assoc{}.
timeout(Now, #assoc{state = established, pmtu = #{probe := {Size, _, Deadline, N}} = P} = A) when Now >= Deadline ->
    case N >= ?MAX_PROBES of
        %% This size does not get through: the search ends below it.
        true -> A#assoc{pmtu = P#{phase := done, todo := [], probe := undefined, at := Now + ?RAISE_MS}};
        false -> probe(Size, N + 1, Now, A)
    end;
timeout(Now, #assoc{state = established, pmtu = #{probe := undefined, at := At} = P} = A) when
    is_integer(At), Now >= At
->
    case P of
        #{todo := [Size | _]} -> probe(Size, 1, Now, A#assoc{pmtu = P#{phase := search}});
        #{phase := done} -> probe_next(Now, A#assoc{pmtu = P#{todo := sizes(P)}});
        _ -> A#assoc{pmtu = P#{at := undefined}}
    end;
timeout(_Now, A) ->
    A.

probe_next(Now, #assoc{pmtu = #{todo := [Size | _]} = P} = A) ->
    probe(Size, 1, Now, A#assoc{pmtu = P#{phase := search}});
probe_next(Now, #assoc{pmtu = P} = A) ->
    A#assoc{pmtu = P#{phase := done, probe := undefined, at := Now + ?RAISE_MS}}.

%% One probe packet of exactly Size bytes: HEARTBEAT and PAD.
probe(Size, N, Now, #assoc{pmtu = P, snd = Snd} = A0) ->
    {R1, A1} = webrtc_sctp_handshake:rand32(A0),
    {R2, A2} = webrtc_sctp_handshake:rand32(A1),
    Nonce = <<R1:32, R2:32>>,
    Hb = {heartbeat, <<?PROBE_TAG, Size:16, Nonce/binary>>},
    Pad = Size - ?SCTP_COMMON_HEADER_SIZE - webrtc_sctp_chunk:chunk_size(Hb) - 4,
    A3 = webrtc_sctp_out:raw(A2#assoc.peer_vtag, [Hb, {pad, max(0, Pad)}], auto, A2),
    Wait = max(Snd#snd.rto, 1000),
    webrtc_sctp_out:bump(pmtu_probes, A3#assoc{pmtu = P#{probe := {Size, Nonce, Now + Wait, N}}}).

%% @doc A HEARTBEAT ACK: `ignore' when it is not one of our probes.
-spec ack(binary(), integer(), #assoc{}) -> ignore | #assoc{}.
ack(<<?PROBE_TAG, Size:16, Nonce:8/binary>>, Now, #assoc{pmtu = #{probe := {Size, Nonce, _, _}} = P} = A) ->
    A1 = set(Size, A#assoc{pmtu = P#{probe := undefined, todo := [S || S <- maps:get(todo, P), S > Size]}}),
    probe_next(Now, A1);
ack(<<?PROBE_TAG, _/binary>>, _Now, A) ->
    %% A late answer to an older probe.
    A;
ack(_Info, _Now, _A) ->
    ignore.

%% @doc A retransmission timeout: above the base the larger packets may
%% be dropped by the path (RFC 8899 §4.3), go back to the base.
-spec black_hole(integer(), #assoc{}) -> #assoc{}.
black_hole(Now, #assoc{pmtu = #{cur := Cur, base := Base} = P} = A) when Cur > Base ->
    webrtc_sctp_out:bump(pmtu_black_holes, set(Base, A#assoc{pmtu = P#{
        phase := search, todo := [], probe := undefined, at := Now + ?RETRY_MS}}));
black_hole(_Now, A) ->
    A.

%% @doc The lower layer moved to another path (RFC 8261 §6.1): base
%% size, search again.
-spec path_changed(integer(), #assoc{}) -> #assoc{}.
path_changed(Now, #assoc{pmtu = #{phase := Phase, base := Base} = P} = A) when Phase =/= off ->
    A1 = set(Base, A#assoc{pmtu = P#{cur := Base, probe := undefined}}),
    #assoc{pmtu = P1} = A1,
    A1#assoc{pmtu = P1#{phase := search, todo := sizes(P1), at := Now + ?START_MS}};
path_changed(_Now, A) ->
    A.

set(Size, #assoc{pmtu = P, snd = Snd} = A) ->
    A#assoc{pmtu = P#{cur := Size}, snd = Snd#snd{mtu = Size}}.

-spec info(state()) -> map().
info(#{cur := Cur, base := Base, max := Max, phase := Phase}) ->
    #{pmtu => Cur, base => Base, max => Max, search => Phase}.
