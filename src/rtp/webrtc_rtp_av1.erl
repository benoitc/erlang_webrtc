%% @doc AV1 RTP payload format (AOMedia "RTP Payload Format for AV1"
%% v1.0.0 §4.4), aggregation header and key frame detection only.
%%
%% The aggregation header is `Z Y W(2) N' followed by three reserved
%% bits. N = 1 marks the first packet of a coded video sequence, which
%% starts with a key frame and a sequence header; it is the signal used
%% here for key frame detection.
-module(webrtc_rtp_av1).

-export([aggregation_header/1, is_keyframe/1]).

-export_type([aggregation_header/0]).

-type aggregation_header() :: #{
    continuation := boolean(),
    continues := boolean(),
    obu_count := 0..3,
    new_sequence := boolean()
}.

%% @doc Parse the aggregation header. `continuation' (Z): the first OBU
%% element continues one from the previous packet; `continues' (Y): the
%% last OBU element continues in the next packet; `obu_count' (W): the
%% number of OBU elements, 0 when each element carries a length field.
-spec aggregation_header(binary()) -> {ok, aggregation_header()} | {error, truncated}.
aggregation_header(<<Z:1, Y:1, W:2, N:1, _:3, _/binary>>) ->
    {ok, #{continuation => Z =:= 1, continues => Y =:= 1, obu_count => W, new_sequence => N =:= 1}};
aggregation_header(_) ->
    {error, truncated}.

-spec is_keyframe(binary()) -> boolean().
is_keyframe(Payload) ->
    case aggregation_header(Payload) of
        {ok, #{new_sequence := true, continuation := false}} -> true;
        _ -> false
    end.
