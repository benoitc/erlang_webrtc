%% @doc WebRTC data channels: the Data Channel Establishment Protocol
%% (RFC 8832) and the data channel rules of RFC 8831 on top of
%% `webrtc_sctp_assoc'.
%%
%% The manager owns the SCTP association and is a sans-IO engine with
%% the same contract: `handle_packet/3', `handle_timeout/2' and
%% `next_timeout/1' return `{State, Actions}' where actions are
%% `{send, Bin}' (DTLS application data) and `{event, Event}'.
%%
%% Events:
%%
%% - `{connected, Info}': the SCTP association is up (see
%%   `webrtc_sctp_assoc').
%% - `{channel_open, Id, Label, Protocol, Opts}': a channel is usable,
%%   either opened by the peer with DATA_CHANNEL_OPEN, or created
%%   locally (sent once the association is up). `Opts' holds `ordered',
%%   `max_retransmits' or `max_packet_life_time' when set, `priority',
%%   `negotiated' and `initiator' (`local' or `remote').
%% - `{channel_message, Id, text | binary, Data}'.
%% - `{channel_closed, Id}': both directions of the stream were reset
%%   (RFC 8831 §6.7), the id can be reused.
%% - `{buffered_amount_low, Id}'.
%% - `{closed, Reason}' and `{restarted, Info}' from the association;
%%   every channel is reported closed first.
%%
%% Options of `new/1': `role' (`client' or `server', the DTLS role,
%% which selects even or odd stream ids, RFC 8832 §6, required),
%% `max_message_size' (the peer's SDP max-message-size, RFC 8841 §6;
%% 0 means no limit, default 65536), `sctp' (options of
%% `webrtc_sctp_assoc:new/1'; its `max_message_size' bounds incoming
%% messages).
-module(webrtc_dcep).

-export([
    new/1,
    connect/2,
    open_channel/4,
    send/5,
    close_channel/3,
    handle_packet/3,
    handle_timeout/2,
    next_timeout/1,
    buffered_amount/2,
    set_buffered_amount_low_threshold/3,
    channels/1,
    sctp/1,
    encode/1,
    decode/1
]).

-export_type([dcep/0, message/0, channel_opts/0, action/0]).

-type action() :: {send, binary()} | {event, term()}.

-define(PPID_DCEP, 50).
-define(PPID_STRING, 51).
-define(PPID_BINARY_PARTIAL, 52).
-define(PPID_BINARY, 53).
-define(PPID_STRING_PARTIAL, 54).
-define(PPID_STRING_EMPTY, 56).
-define(PPID_BINARY_EMPTY, 57).

-define(MSG_ACK, 16#02).
-define(MSG_OPEN, 16#03).

-define(RELIABLE, 16#00).
-define(PARTIAL_REXMIT, 16#01).
-define(PARTIAL_TIMED, 16#02).
-define(UNORDERED_BIT, 16#80).

-define(MAX_ID, 65534).

-type message() ::
    {open, #{
        ordered := boolean(),
        reliability :=
            reliable | {max_retransmits, 0..16#FFFFFFFF} | {max_packet_life_time, 0..16#FFFFFFFF},
        priority := 0..65535,
        label := binary(),
        protocol := binary()
    }}
    | ack.
-type channel_opts() :: #{
    ordered => boolean(),
    max_retransmits => non_neg_integer(),
    max_packet_life_time => non_neg_integer(),
    priority => 0..65535,
    protocol => binary(),
    negotiated => boolean(),
    id => 0..?MAX_ID
}.

-record(ch, {
    id :: 0..?MAX_ID,
    label = <<>> :: binary(),
    protocol = <<>> :: binary(),
    ordered = true :: boolean(),
    reliability = reliable ::
        reliable | {max_retransmits | max_packet_life_time, non_neg_integer()},
    priority = 256 :: 0..65535,
    negotiated = false :: boolean(),
    initiator = local :: local | remote,
    state = connecting :: connecting | open | closing,
    %% RFC 8832 §6: user data goes ordered until the peer sent something.
    heard = false :: boolean(),
    out_reset = false :: boolean(),
    in_reset = false :: boolean(),
    partial = [] :: [binary()],
    partial_bytes = 0 :: non_neg_integer()
}).

-record(dc, {
    sctp :: webrtc_sctp_assoc:assoc(),
    role :: client | server,
    max_message_size = 65536 :: non_neg_integer(),
    local_max :: pos_integer(),
    connected = false :: boolean(),
    channels = #{} :: #{0..?MAX_ID => #ch{}},
    acts = [] :: [term()]
}).

-opaque dcep() :: #dc{}.

%%====================================================================
%% Codec (RFC 8832 §5)
%%====================================================================

-spec encode(message()) -> binary().
encode(ack) ->
    <<?MSG_ACK>>;
encode(
    {open, #{ordered := Ordered, reliability := Rel, priority := Prio, label := L, protocol := P}}
) ->
    {Type, Param} =
        case Rel of
            reliable -> {?RELIABLE, 0};
            {max_retransmits, N} -> {?PARTIAL_REXMIT, N};
            {max_packet_life_time, Ms} -> {?PARTIAL_TIMED, Ms}
        end,
    Type1 =
        case Ordered of
            true -> Type;
            false -> Type bor ?UNORDERED_BIT
        end,
    <<?MSG_OPEN, Type1, Prio:16, Param:32, (byte_size(L)):16, (byte_size(P)):16, L/binary,
        P/binary>>.

-spec decode(binary()) -> {ok, message()} | {error, term()}.
decode(<<?MSG_ACK>>) ->
    {ok, ack};
decode(<<?MSG_OPEN, Type, Prio:16, Param:32, LL:16, PL:16, Rest/binary>>) when
    byte_size(Rest) =:= LL + PL
->
    <<L:LL/binary, P:PL/binary>> = Rest,
    Rel =
        case Type band (bnot ?UNORDERED_BIT) of
            ?RELIABLE -> {ok, reliable};
            ?PARTIAL_REXMIT -> {ok, {max_retransmits, Param}};
            ?PARTIAL_TIMED -> {ok, {max_packet_life_time, Param}};
            _ -> {error, {bad_channel_type, Type}}
        end,
    case {Rel, utf8(L), utf8(P)} of
        {{ok, R}, true, true} ->
            {ok,
                {open, #{
                    ordered => Type band ?UNORDERED_BIT =:= 0,
                    reliability => R,
                    priority => Prio,
                    label => L,
                    protocol => P
                }}};
        {{error, _} = E, _, _} ->
            E;
        _ ->
            {error, bad_utf8}
    end;
decode(<<?MSG_OPEN, _/binary>>) ->
    {error, bad_length};
decode(<<?MSG_ACK, _/binary>>) ->
    {error, bad_length};
decode(<<T, _/binary>>) ->
    {error, {unknown_message_type, T}};
decode(<<>>) ->
    {error, empty}.

utf8(B) ->
    case unicode:characters_to_binary(B, utf8, utf8) of
        B -> true;
        _ -> false
    end.

%%====================================================================
%% Manager API
%%====================================================================

-spec new(map()) -> dcep().
new(#{role := Role} = Opts) when Role =:= client; Role =:= server ->
    SOpts = maps:get(sctp, Opts, #{}),
    Max = maps:get(max_message_size, Opts, 65536),
    case is_integer(Max) andalso Max >= 0 of
        true -> ok;
        false -> error({badarg, max_message_size})
    end,
    #dc{
        sctp = webrtc_sctp_assoc:new(SOpts),
        role = Role,
        max_message_size = Max,
        local_max = maps:get(max_message_size, SOpts, 262144)
    };
new(_) ->
    error({badarg, role}).

-spec sctp(dcep()) -> webrtc_sctp_assoc:assoc().
sctp(#dc{sctp = S}) -> S.

-spec connect(integer(), dcep()) -> {dcep(), [action()]}.
connect(Now, #dc{sctp = S} = D) ->
    {S1, Acts} = webrtc_sctp_assoc:connect(Now, S),
    finish(Now, assoc_actions(Acts, Now, D#dc{sctp = S1})).

%% @doc Create a channel. Without `negotiated' a DATA_CHANNEL_OPEN is
%% sent on a stream id of our parity; with `negotiated => true' the
%% application agreed on `id' out of band and no DCEP message is used.
-spec open_channel(binary(), channel_opts(), integer(), dcep()) ->
    {ok, 0..?MAX_ID, dcep(), [action()]} | {error, atom()}.
open_channel(Label, Opts, Now, #dc{} = D) when is_binary(Label), is_map(Opts) ->
    case channel_from_opts(Label, Opts, D) of
        {ok, Ch} ->
            D1 = D#dc{channels = (D#dc.channels)#{Ch#ch.id => Ch}},
            D2 =
                case Ch#ch.negotiated of
                    true -> D1;
                    false -> dcep_send(Ch#ch.id, encode({open, open_msg(Ch)}), Now, D1)
                end,
            D3 =
                case D2#dc.connected of
                    true -> announce(Ch#ch.id, D2);
                    false -> D2
                end,
            {D4, Acts} = finish(Now, D3),
            {ok, Ch#ch.id, D4, Acts};
        {error, _} = E ->
            E
    end;
open_channel(_, _, _, _) ->
    {error, badarg}.

channel_from_opts(Label, Opts, #dc{channels = Chs} = D) ->
    Rel =
        case
            {
                maps:get(max_retransmits, Opts, undefined),
                maps:get(max_packet_life_time, Opts, undefined)
            }
        of
            {undefined, undefined} ->
                {ok, reliable};
            {N, undefined} when is_integer(N), N >= 0, N =< 16#FFFFFFFF ->
                {ok, {max_retransmits, N}};
            {undefined, T} when is_integer(T), T >= 0, T =< 16#FFFFFFFF ->
                {ok, {max_packet_life_time, T}};
            _ ->
                {error, badarg}
        end,
    Negotiated = maps:get(negotiated, Opts, false),
    Proto = maps:get(protocol, Opts, <<>>),
    Prio = maps:get(priority, Opts, 256),
    Ordered = maps:get(ordered, Opts, true),
    Valid =
        is_boolean(Negotiated) andalso is_binary(Proto) andalso is_boolean(Ordered) andalso
            is_integer(Prio) andalso Prio >= 0 andalso Prio =< 65535 andalso
            byte_size(Label) =< 65535 andalso byte_size(Proto) =< 65535,
    Id =
        case {Negotiated, maps:get(id, Opts, undefined)} of
            {true, undefined} ->
                {error, missing_id};
            {_, undefined} ->
                free_id(D);
            {_, I} when is_integer(I), I >= 0, I =< ?MAX_ID ->
                case maps:is_key(I, Chs) of
                    true -> {error, id_in_use};
                    false when not Negotiated -> parity(I, D#dc.role);
                    false -> {ok, I}
                end;
            _ ->
                {error, badarg}
        end,
    case {Valid, Rel, Id} of
        {false, _, _} ->
            {error, badarg};
        {_, {error, _} = E, _} ->
            E;
        {_, _, {error, _} = E} ->
            E;
        {true, {ok, R}, {ok, I1}} ->
            {ok, #ch{
                id = I1,
                label = Label,
                protocol = Proto,
                ordered = Ordered,
                reliability = R,
                priority = Prio,
                negotiated = Negotiated,
                initiator = local,
                heard = Negotiated
            }}
    end.

parity(I, Role) ->
    case I rem 2 =:= own_parity(Role) of
        true -> {ok, I};
        false -> {error, wrong_parity}
    end.

%% RFC 8832 §6: the DTLS client uses even ids, the server odd ones.
own_parity(client) -> 0;
own_parity(server) -> 1.

free_id(#dc{role = Role, channels = Chs, sctp = S}) ->
    Info = webrtc_sctp_assoc:info(S),
    Max = min(?MAX_ID, min(maps:get(outbound_streams, Info), maps:get(inbound_streams, Info)) - 1),
    free_id(own_parity(Role), Max, Chs).

free_id(I, Max, _Chs) when I > Max -> {error, no_stream_id};
free_id(I, Max, Chs) ->
    case maps:is_key(I, Chs) of
        true -> free_id(I + 2, Max, Chs);
        false -> {ok, I}
    end.

open_msg(#ch{} = Ch) ->
    #{
        ordered => Ch#ch.ordered,
        reliability => Ch#ch.reliability,
        priority => Ch#ch.priority,
        label => Ch#ch.label,
        protocol => Ch#ch.protocol
    }.

%% @doc Send a text (UTF-8) or binary message. Empty messages use the
%% "empty" PPIDs and one zero byte (RFC 8831 §6.6).
-spec send(0..?MAX_ID, text | binary, binary(), integer(), dcep()) ->
    {ok, dcep(), [action()]} | {error, atom()}.
send(Id, Type, Data, Now, #dc{channels = Chs, max_message_size = Max} = D) when
    (Type =:= text orelse Type =:= binary), is_binary(Data)
->
    case Chs of
        #{Id := #ch{state = open} = Ch} when Max =:= 0; byte_size(Data) =< Max ->
            {Ppid, Payload} = user_ppid(Type, Data),
            case webrtc_sctp_assoc:send(Id, Ppid, Payload, send_opts(Ch), Now, D#dc.sctp) of
                {ok, S1, Acts} ->
                    {D1, Out} = finish(Now, assoc_actions(Acts, Now, D#dc{sctp = S1})),
                    {ok, D1, Out};
                {error, _} = E ->
                    E
            end;
        #{Id := #ch{state = open}} ->
            {error, message_too_large};
        #{Id := _} ->
            {error, not_open};
        _ ->
            {error, unknown_channel}
    end;
send(_, _, _, _, _) ->
    {error, badarg}.

user_ppid(text, <<>>) -> {?PPID_STRING_EMPTY, <<0>>};
user_ppid(text, D) -> {?PPID_STRING, D};
user_ppid(binary, <<>>) -> {?PPID_BINARY_EMPTY, <<0>>};
user_ppid(binary, D) -> {?PPID_BINARY, D}.

send_opts(#ch{ordered = O, heard = Heard, reliability = R}) ->
    Base = #{ordered => O orelse not Heard},
    case R of
        reliable -> Base;
        {max_retransmits, N} -> Base#{max_retransmits => N};
        {max_packet_life_time, Ms} -> Base#{max_lifetime => Ms}
    end.

%% @doc Close a channel by resetting its outgoing stream (RFC 8831 §6.7).
-spec close_channel(0..?MAX_ID, integer(), dcep()) ->
    {ok, dcep(), [action()]} | {error, atom()}.
close_channel(Id, Now, #dc{channels = Chs} = D) ->
    case Chs of
        #{Id := #ch{state = closing}} ->
            {error, closing};
        #{Id := Ch} ->
            D1 = reset_out(Ch, Now, D),
            {D2, Acts} = finish(Now, D1),
            {ok, D2, Acts};
        _ ->
            {error, unknown_channel}
    end.

-spec buffered_amount(0..?MAX_ID, dcep()) -> non_neg_integer().
buffered_amount(Id, #dc{sctp = S}) ->
    webrtc_sctp_assoc:buffered_amount(Id, S).

-spec set_buffered_amount_low_threshold(0..?MAX_ID, non_neg_integer(), dcep()) -> dcep().
set_buffered_amount_low_threshold(Id, Low, #dc{sctp = S} = D) ->
    D#dc{sctp = webrtc_sctp_assoc:set_buffered_amount_low_threshold(Id, Low, S)}.

%% @doc Channels by id with their label, state and options.
-spec channels(dcep()) -> #{0..?MAX_ID => map()}.
channels(#dc{channels = Chs}) ->
    maps:map(
        fun(_, Ch) ->
            (event_opts(Ch))#{
                label => Ch#ch.label, protocol => Ch#ch.protocol, state => Ch#ch.state
            }
        end,
        Chs
    ).

%%====================================================================
%% Engine contract
%%====================================================================

-spec handle_packet(binary(), integer(), dcep()) -> {dcep(), [action()]}.
handle_packet(Bin, Now, #dc{sctp = S} = D) ->
    {S1, Acts} = webrtc_sctp_assoc:handle_packet(Bin, Now, S),
    finish(Now, assoc_actions(Acts, Now, D#dc{sctp = S1})).

-spec handle_timeout(integer(), dcep()) -> {dcep(), [action()]}.
handle_timeout(Now, #dc{sctp = S} = D) ->
    {S1, Acts} = webrtc_sctp_assoc:handle_timeout(Now, S),
    finish(Now, assoc_actions(Acts, Now, D#dc{sctp = S1})).

-spec next_timeout(dcep()) -> integer() | infinity.
next_timeout(#dc{sctp = S}) ->
    webrtc_sctp_assoc:next_timeout(S).

%%====================================================================
%% Association events
%%====================================================================

assoc_actions([], _Now, D) ->
    D;
assoc_actions([{send, _} = A | Rest], Now, D) ->
    assoc_actions(Rest, Now, out(A, D));
assoc_actions([{event, E} | Rest], Now, D) ->
    assoc_actions(Rest, Now, assoc_event(E, Now, D)).

assoc_event({connected, Info}, _Now, #dc{channels = Chs} = D) ->
    D1 = event({connected, Info}, D#dc{connected = true}),
    lists:foldl(fun announce/2, D1, lists:sort(maps:keys(Chs)));
assoc_event({message, Id, ?PPID_DCEP, Bin}, Now, D) ->
    dcep_message(Id, decode(Bin), Now, D);
assoc_event({message, Id, Ppid, Data}, Now, #dc{channels = Chs} = D) ->
    case Chs of
        #{Id := #ch{state = closing}} ->
            D;
        #{Id := Ch} ->
            user_message(Ch#ch{heard = true}, Ppid, Data, Now, D);
        _ ->
            %% RFC 8832 §6: user data on an unused stream is an error.
            reset_unknown(Id, Now, D)
    end;
assoc_event({stream_reset, Ids}, Now, #dc{channels = Chs} = D) ->
    Affected =
        case Ids of
            [] -> maps:keys(Chs);
            _ -> [I || I <- Ids, maps:is_key(I, Chs)]
        end,
    lists:foldl(
        fun(Id, Acc) ->
            Ch = maps:get(Id, Acc#dc.channels),
            Ch1 = Ch#ch{in_reset = true},
            case Ch1#ch.state of
                closing -> maybe_closed(Ch1, Acc);
                _ -> reset_out(Ch1, Now, Acc)
            end
        end,
        D,
        Affected
    );
assoc_event({outgoing_stream_reset, Ids}, _Now, #dc{channels = Chs} = D) ->
    lists:foldl(
        fun(Id, Acc) ->
            case Chs of
                #{Id := Ch} -> maybe_closed(Ch#ch{out_reset = true}, Acc);
                _ -> Acc
            end
        end,
        D,
        Ids
    );
assoc_event({stream_reset_failed, Ids, _}, _Now, #dc{channels = Chs} = D) ->
    %% The peer refused the reset: report the channel closed.
    lists:foldl(
        fun(Id, Acc) ->
            case Chs of
                #{Id := Ch} -> maybe_closed(Ch#ch{out_reset = true, in_reset = true}, Acc);
                _ -> Acc
            end
        end,
        D,
        Ids
    );
assoc_event({buffered_amount_low, Id}, _Now, D) ->
    event({buffered_amount_low, Id}, D);
assoc_event({Ev, _} = E, _Now, #dc{channels = Chs} = D) when Ev =:= closed; Ev =:= restarted ->
    D1 = lists:foldl(
        fun(Id, Acc) -> event({channel_closed, Id}, Acc) end, D, lists:sort(maps:keys(Chs))
    ),
    event(E, D1#dc{channels = #{}, connected = Ev =:= restarted});
assoc_event(E, _Now, D) ->
    event(E, D).

%% DATA_CHANNEL_OPEN / DATA_CHANNEL_ACK (RFC 8832 §6).
dcep_message(Id, {ok, {open, M}}, Now, #dc{channels = Chs, role = Role} = D) ->
    PeerParity = 1 - own_parity(Role),
    case maps:is_key(Id, Chs) orelse Id rem 2 =/= PeerParity orelse Id > ?MAX_ID of
        true ->
            reset_unknown(Id, Now, D);
        false ->
            #{ordered := O, reliability := R, priority := P, label := L, protocol := Proto} = M,
            Ch = #ch{
                id = Id,
                label = L,
                protocol = Proto,
                ordered = O,
                reliability = R,
                priority = P,
                initiator = remote,
                state = open,
                heard = true
            },
            D1 = D#dc{channels = Chs#{Id => Ch}},
            D2 = dcep_send(Id, encode(ack), Now, D1),
            event({channel_open, Id, L, Proto, event_opts(Ch)}, D2)
    end;
dcep_message(Id, {ok, ack}, _Now, #dc{channels = Chs} = D) ->
    case Chs of
        #{Id := #ch{initiator = local, negotiated = false} = Ch} ->
            D#dc{channels = Chs#{Id := Ch#ch{heard = true}}};
        _ ->
            D
    end;
dcep_message(Id, {error, _}, Now, #dc{channels = Chs} = D) ->
    case Chs of
        #{Id := Ch} -> reset_out(Ch, Now, D);
        _ -> reset_unknown(Id, Now, D)
    end.

user_message(Ch, Ppid, Data, Now, D) ->
    Id = Ch#ch.id,
    case Ppid of
        ?PPID_STRING ->
            deliver(Ch, text, Data, D);
        ?PPID_BINARY ->
            deliver(Ch, binary, Data, D);
        ?PPID_STRING_EMPTY ->
            deliver(Ch, text, <<>>, D);
        ?PPID_BINARY_EMPTY ->
            deliver(Ch, binary, <<>>, D);
        P when P =:= ?PPID_STRING_PARTIAL; P =:= ?PPID_BINARY_PARTIAL ->
            %% Deprecated PPID based fragmentation, accepted on receive.
            Bytes = Ch#ch.partial_bytes + byte_size(Data),
            case Bytes > D#dc.local_max of
                true ->
                    reset_out(Ch#ch{partial = [], partial_bytes = 0}, Now, D);
                false ->
                    Ch1 = Ch#ch{partial = [Data | Ch#ch.partial], partial_bytes = Bytes},
                    D#dc{channels = (D#dc.channels)#{Id := Ch1}}
            end;
        _ ->
            %% RFC 8831 §6.6: unsupported PPID, close the channel.
            reset_out(Ch, Now, D)
    end.

deliver(#ch{partial = []} = Ch, Type, Data, D) ->
    D1 = D#dc{channels = (D#dc.channels)#{Ch#ch.id := Ch}},
    event({channel_message, Ch#ch.id, Type, Data}, D1);
deliver(#ch{partial = Parts} = Ch, Type, Data, D) ->
    Full = iolist_to_binary(lists:reverse([Data | Parts])),
    deliver(Ch#ch{partial = [], partial_bytes = 0}, Type, Full, D).

%%====================================================================
%% Closing (RFC 8831 §6.7)
%%====================================================================

reset_out(#ch{out_reset = true} = Ch, _Now, D) ->
    maybe_closed(Ch#ch{state = closing}, D);
reset_out(#ch{id = Id} = Ch, Now, #dc{connected = true, sctp = S} = D) ->
    case webrtc_sctp_assoc:reset_streams([Id], Now, S) of
        {ok, S1, Acts} ->
            D1 = assoc_actions(Acts, Now, D#dc{sctp = S1}),
            D1#dc{channels = (D1#dc.channels)#{Id => Ch#ch{state = closing}}};
        {error, _} ->
            %% No stream reconfiguration (or association going away):
            %% nothing more can be done for this stream.
            maybe_closed(Ch#ch{state = closing, out_reset = true, in_reset = true}, D)
    end;
reset_out(Ch, _Now, D) ->
    %% Not connected yet: nothing was sent on the stream.
    maybe_closed(Ch#ch{state = closing, out_reset = true, in_reset = true}, D).

maybe_closed(#ch{id = Id, out_reset = true, in_reset = true}, D) ->
    event({channel_closed, Id}, D#dc{channels = maps:remove(Id, D#dc.channels)});
maybe_closed(#ch{id = Id} = Ch, D) ->
    D#dc{channels = (D#dc.channels)#{Id => Ch}}.

%% A stream with no channel received something invalid: reset our
%% side so the peer learns the channel setup failed.
reset_unknown(Id, Now, #dc{connected = true, sctp = S} = D) when Id =< ?MAX_ID ->
    case webrtc_sctp_assoc:reset_streams([Id], Now, S) of
        {ok, S1, Acts} -> assoc_actions(Acts, Now, D#dc{sctp = S1});
        {error, _} -> D
    end;
reset_unknown(_Id, _Now, D) ->
    D.

%%====================================================================
%% Helpers
%%====================================================================

%% Local channels become usable once the association is up.
announce(Id, #dc{channels = Chs} = D) ->
    case Chs of
        #{Id := #ch{initiator = local, state = connecting} = Ch} ->
            Ch1 = Ch#ch{state = open},
            D1 = D#dc{channels = Chs#{Id := Ch1}},
            event({channel_open, Id, Ch#ch.label, Ch#ch.protocol, event_opts(Ch1)}, D1);
        _ ->
            D
    end.

event_opts(#ch{} = Ch) ->
    Base = #{
        ordered => Ch#ch.ordered,
        priority => Ch#ch.priority,
        negotiated => Ch#ch.negotiated,
        initiator => Ch#ch.initiator
    },
    case Ch#ch.reliability of
        reliable -> Base;
        {K, V} -> Base#{K => V}
    end.

%% DCEP messages are ordered and reliable on the channel's stream.
dcep_send(Id, Msg, Now, #dc{sctp = S} = D) ->
    case webrtc_sctp_assoc:send(Id, ?PPID_DCEP, Msg, #{ordered => true}, Now, S) of
        {ok, S1, Acts} -> assoc_actions(Acts, Now, D#dc{sctp = S1});
        {error, _} -> D
    end.

event(E, #dc{acts = A} = D) -> D#dc{acts = [{event, E} | A]}.
out(Act, #dc{acts = A} = D) -> D#dc{acts = [Act | A]}.

finish(_Now, #dc{acts = A} = D) ->
    {D#dc{acts = []}, lists:reverse(A)}.
