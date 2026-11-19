%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% @doc DSCP values for WebRTC flows (RFC 8837 §5, Table 1), as RFC 8835
%% §4.2 asks implementations to mark their packets.
%%
%% The flow type and the application priority pick the value. Where a
%% cell has two values, the first (lower drop precedence) is for the more
%% important packets of the flow: those of a key frame.
%%
%% | Flow type | very_low | low | medium | high |
%% |---|---|---|---|---|
%% | audio | LE 1 | DF 0 | EF 46 | EF 46 |
%% | interactive video | LE 1 | DF 0 | AF42 36, AF43 38 | AF41 34, AF42 36 |
%% | non-interactive video | LE 1 | DF 0 | AF32 28, AF33 30 | AF31 26, AF32 28 |
%% | data | LE 1 | DF 0 | AF11 10 | AF21 18 |
%%
%% The default priority, `low', is DF: nothing is marked unless the
%% application sets a priority. Browsers MUST NOT use AF3x; this library
%% is not a browser and uses it for video the application says is not
%% interactive, as RFC 8837 §5 allows.
-module(webrtc_dscp).

-export([dscp/4, priority/1, class/1, tos/2]).
-export_type([priority/0, kind/0]).

-type priority() :: very_low | low | medium | high.
-type kind() :: audio | video | data.

%% @doc The DSCP of a packet: flow kind, application priority, whether
%% the video is interactive, whether the packet is among the important
%% ones of its flow.
-spec dscp(kind(), priority(), boolean(), boolean()) -> 0..63.
dscp(_, very_low, _, _) -> 1;
dscp(_, low, _, _) -> 0;
dscp(audio, P, _, _) when P =:= medium; P =:= high -> 46;
dscp(video, medium, true, Important) -> pick(Important, 36, 38);
dscp(video, high, true, Important) -> pick(Important, 34, 36);
dscp(video, medium, false, Important) -> pick(Important, 28, 30);
dscp(video, high, false, Important) -> pick(Important, 26, 28);
dscp(data, medium, _, _) -> 10;
dscp(data, high, _, _) -> 18.

pick(true, A, _) -> A;
pick(false, _, B) -> B.

%% @doc Validate an application priority.
-spec priority(term()) -> {ok, priority()} | error.
priority(P) when P =:= very_low; P =:= low; P =:= medium; P =:= high -> {ok, P};
priority(_) -> error.

%% @doc The priority class of a data channel's DCEP priority (RFC 8831
%% §6.4: 128, 256, 512 and 1024, values between round down).
-spec class(0..65535) -> priority().
class(P) when P >= 1024 -> high;
class(P) when P >= 512 -> medium;
class(P) when P >= 256 -> low;
class(_) -> very_low.

%% @doc The IP TOS or traffic class byte: DSCP in the upper six bits,
%% ECN in the lower two.
-spec tos(0..63, 0..3) -> 0..255.
tos(Dscp, Ecn) -> (Dscp bsl 2) bor Ecn.
