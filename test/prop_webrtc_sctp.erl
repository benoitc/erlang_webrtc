%% PropEr properties for the SCTP codec (webrtc_sctp_chunk,
%% webrtc_sctp_param, webrtc_sctp_crc32c).
%%
%% Generators are plain functions named gen_* so other properties in this
%% file can reuse them.
-module(prop_webrtc_sctp).

-include_lib("proper/include/proper.hrl").
-include("webrtc_sctp.hrl").

-export([
    prop_chunk_roundtrip/0,
    prop_tlv_roundtrip/0,
    prop_packet_roundtrip/0,
    prop_decode_never_crashes/0
]).

-export([
    gen_u8/0,
    gen_u16/0,
    gen_u32/0,
    gen_small_binary/0,
    gen_chunk/0,
    gen_data_chunk/0,
    gen_idata_chunk/0,
    gen_init_chunk/0,
    gen_sack_chunk/0,
    gen_packet/0,
    gen_param/0,
    gen_cause/0,
    gen_reconf_param/0,
    gen_reconf_result/0,
    gen_mutated_packet/0,
    normalise_chunk/1,
    normalise_packet/1
]).

%%====================================================================
%% Properties
%%====================================================================

%% Every chunk term encodes to a padded chunk that decodes back to it.
prop_chunk_roundtrip() ->
    numtests(
        1000,
        ?FORALL(
            Chunk,
            gen_chunk(),
            begin
                Bin = webrtc_sctp_chunk:encode_chunk(Chunk),
                Expected = normalise_chunk(Chunk),
                ?WHENFAIL(
                    io:format("chunk ~p~nbin ~p~n", [Chunk, Bin]),
                    byte_size(Bin) rem 4 =:= 0 andalso
                        byte_size(Bin) =:= webrtc_sctp_chunk:chunk_size(Chunk) andalso
                        webrtc_sctp_chunk:decode_chunks(Bin) =:= {ok, [Expected]}
                )
            end
        )
    ).

%% Parameter, cause and RE-CONFIG parameter lists round trip.
prop_tlv_roundtrip() ->
    numtests(
        500,
        ?FORALL(
            {Params, Causes, Reconf},
            {list(gen_param()), list(gen_cause()), list(gen_reconf_param())},
            webrtc_sctp_param:decode_params(webrtc_sctp_param:encode_params(Params)) =:=
                {ok, Params} andalso
                webrtc_sctp_param:decode_causes(webrtc_sctp_param:encode_causes(Causes)) =:=
                    {ok, Causes} andalso
                webrtc_sctp_param:decode_reconf_params(
                    webrtc_sctp_param:encode_reconf_params(Reconf)
                ) =:= {ok, Reconf}
        )
    ).

%% Packets encode with a valid CRC32c and decode back.
prop_packet_roundtrip() ->
    numtests(
        300,
        ?FORALL(
            Packet,
            gen_packet(),
            begin
                Bin = webrtc_sctp_chunk:encode(Packet),
                <<_:8/binary, Csum:32/little, _/binary>> = Bin,
                Expected = (normalise_packet(Packet))#sctp_packet{checksum = Csum},
                Zero = webrtc_sctp_chunk:encode(Packet, #{checksum => zero}),
                ?WHENFAIL(
                    io:format("packet ~p~nbin ~p~n", [Packet, Bin]),
                    webrtc_sctp_chunk:checksum_ok(Bin, false) andalso
                        webrtc_sctp_chunk:checksum_ok(Zero, true) andalso
                        Csum =:= webrtc_sctp_crc32c:crc32c(Zero) andalso
                        webrtc_sctp_chunk:decode(Bin) =:= {ok, Expected}
                )
            end
        )
    ).

%% Decoders return {ok, _} or {error, _} on any input and never raise.
%% A successful decode re-encodes to a packet that decodes the same.
prop_decode_never_crashes() ->
    numtests(
        3000,
        ?FORALL(
            Bin,
            oneof([binary(), gen_mutated_packet()]),
            ?WHENFAIL(io:format("input ~p~n", [Bin]), decode_is_safe(Bin))
        )
    ).

decode_is_safe(Bin) ->
    try
        Area = binary:part(Bin, min(12, byte_size(Bin)), byte_size(Bin) - min(12, byte_size(Bin))),
        _ = webrtc_sctp_chunk:checksum_ok(Bin, true),
        ok_or_error(webrtc_sctp_chunk:decode_chunks(Area)) andalso
            ok_or_error(webrtc_sctp_param:decode_params(Bin)) andalso
            ok_or_error(webrtc_sctp_param:decode_causes(Bin)) andalso
            ok_or_error(webrtc_sctp_param:decode_reconf_params(Bin)) andalso
            case webrtc_sctp_chunk:decode(Bin) of
                {ok, #sctp_packet{} = P} ->
                    webrtc_sctp_chunk:decode(webrtc_sctp_chunk:encode(P)) =:=
                        {ok, P#sctp_packet{
                            checksum = wire_checksum(webrtc_sctp_chunk:encode(P))
                        }};
                {error, _} ->
                    true
            end
    catch
        Class:Reason:Stack ->
            io:format("~p:~p~n~p~n", [Class, Reason, Stack]),
            false
    end.

ok_or_error({ok, L}) when is_list(L) -> true;
ok_or_error({error, _}) -> true.

wire_checksum(<<_:8/binary, Csum:32/little, _/binary>>) -> Csum.

%%====================================================================
%% Normalisation of fields not carried on the wire
%%====================================================================

normalise_packet(#sctp_packet{chunks = Chunks} = P) ->
    P#sctp_packet{chunks = [normalise_chunk(C) || C <- Chunks]}.

normalise_chunk(#sctp_data{idata = false} = D) ->
    D#sctp_data{fsn = 0};
normalise_chunk(#sctp_data{idata = true, beginning = true} = D) ->
    D#sctp_data{fsn = 0};
normalise_chunk(#sctp_data{idata = true, beginning = false} = D) ->
    D#sctp_data{ppid = 0};
normalise_chunk(Chunk) ->
    Chunk.

%%====================================================================
%% Generators
%%====================================================================

gen_u8() -> integer(0, 16#FF).

gen_u16() -> frequency([{1, oneof([0, 1, 16#FFFF])}, {4, integer(0, 16#FFFF)}]).

gen_u32() -> frequency([{1, oneof([0, 1, 16#FFFFFFFF])}, {4, integer(0, 16#FFFFFFFF)}]).

gen_small_binary() ->
    ?LET(N, integer(0, 40), binary(N)).

gen_bool() -> boolean().

gen_chunk() ->
    frequency([
        {4, gen_data_chunk()},
        {4, gen_idata_chunk()},
        {3, gen_init_chunk()},
        {3, gen_sack_chunk()},
        {1, {heartbeat, gen_small_binary()}},
        {1, {heartbeat_ack, gen_small_binary()}},
        {2, {abort, gen_bool(), short_list(gen_cause())}},
        {1, {shutdown, gen_u32()}},
        {1, shutdown_ack},
        {1, cookie_ack},
        {2, {op_error, short_list(gen_cause())}},
        {1, {cookie_echo, gen_small_binary()}},
        {1, {shutdown_complete, gen_bool()}},
        {2, {forward_tsn, gen_u32(), short_list({gen_u16(), gen_u16()})}},
        {2, {i_forward_tsn, gen_u32(), short_list({gen_u16(), gen_bool(), gen_u32()})}},
        {3, {reconfig, non_empty(short_list(gen_reconf_param()))}},
        {1, {pad, integer(0, 64)}},
        {2, gen_unknown_chunk()}
    ]).

gen_data_chunk() ->
    ?LET(
        {Tsn, Sid, Ssn, Ppid, {U, B, E, I}, Fsn, Data},
        {gen_u32(), gen_u16(), gen_u16(), gen_u32(), data_flags(), gen_u32(), gen_small_binary()},
        #sctp_data{
            idata = false,
            tsn = Tsn,
            sid = Sid,
            mid = Ssn,
            fsn = Fsn,
            ppid = Ppid,
            unordered = U,
            beginning = B,
            ending = E,
            immediate = I,
            data = Data
        }
    ).

gen_idata_chunk() ->
    ?LET(
        {Tsn, Sid, Mid, Ppid, {U, B, E, I}, Fsn, Data},
        {gen_u32(), gen_u16(), gen_u32(), gen_u32(), data_flags(), gen_u32(), gen_small_binary()},
        #sctp_data{
            idata = true,
            tsn = Tsn,
            sid = Sid,
            mid = Mid,
            fsn = Fsn,
            ppid = Ppid,
            unordered = U,
            beginning = B,
            ending = E,
            immediate = I,
            data = Data
        }
    ).

data_flags() ->
    {gen_bool(), gen_bool(), gen_bool(), gen_bool()}.

gen_init_chunk() ->
    ?LET(
        {Ack, Tag, Rwnd, Os, Mis, Tsn, Params},
        {
            gen_bool(),
            gen_u32(),
            gen_u32(),
            gen_u16(),
            gen_u16(),
            gen_u32(),
            short_list(gen_param())
        },
        #sctp_init{
            ack = Ack, tag = Tag, a_rwnd = Rwnd, os = Os, mis = Mis, tsn = Tsn, params = Params
        }
    ).

gen_sack_chunk() ->
    ?LET(
        {Cum, Rwnd, Gaps, Dups},
        {gen_u32(), gen_u32(), short_list({gen_u16(), gen_u16()}), short_list(gen_u32())},
        #sctp_sack{cum_tsn = Cum, a_rwnd = Rwnd, gaps = Gaps, dups = Dups}
    ).

gen_unknown_chunk() ->
    ?LET(
        {Type, Flags, Value},
        {
            ?SUCHTHAT(T, gen_u8(), not lists:member(T, known_chunk_types())),
            gen_u8(),
            gen_small_binary()
        },
        {unknown_chunk, Type, Flags, Value}
    ).

known_chunk_types() ->
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14, 64, 130, 132, 192, 194].

gen_packet() ->
    ?LET(
        {Src, Dst, Vtag, Csum, Chunks},
        {
            gen_u16(),
            gen_u16(),
            gen_u32(),
            gen_u32(),
            ?SIZED(S, resize(min(S, 8), list(gen_chunk())))
        },
        #sctp_packet{src_port = Src, dst_port = Dst, vtag = Vtag, checksum = Csum, chunks = Chunks}
    ).

gen_param() ->
    oneof([
        {ipv4_address, {gen_u8(), gen_u8(), gen_u8(), gen_u8()}},
        {ipv6_address, {
            gen_u16(), gen_u16(), gen_u16(), gen_u16(), gen_u16(), gen_u16(), gen_u16(), gen_u16()
        }},
        {state_cookie, gen_small_binary()},
        {unrecognized_param, gen_small_binary()},
        {cookie_preservative, gen_u32()},
        {host_name, gen_small_binary()},
        {supported_address_types, short_list(gen_u16())},
        ecn_capable,
        {zero_checksum_acceptable, gen_u32()},
        {padding, integer(0, 40)},
        {supported_extensions, short_list(gen_u8())},
        forward_tsn_supported,
        {unknown_param, ?SUCHTHAT(T, gen_u16(), not lists:member(T, known_param_types())),
            gen_small_binary()}
    ]).

known_param_types() ->
    [5, 6, 7, 8, 9, 11, 12, 16#8000, 16#8001, 16#8005, 16#8008, 16#C000].

gen_reconf_param() ->
    oneof([
        {out_reset, gen_u32(), gen_u32(), gen_u32(), short_list(gen_u16())},
        {in_reset, gen_u32(), short_list(gen_u16())},
        {tsn_reset, gen_u32()},
        {reconf_response, gen_u32(), gen_reconf_result(),
            oneof([undefined, {gen_u32(), gen_u32()}])},
        {add_out_streams, gen_u32(), gen_u16()},
        {add_in_streams, gen_u32(), gen_u16()},
        {unknown_param, ?SUCHTHAT(T, gen_u16(), T < 13 orelse T > 18), gen_small_binary()}
    ]).

gen_reconf_result() ->
    oneof([
        success_nothing_to_do,
        success_performed,
        denied,
        error_wrong_ssn,
        error_request_in_progress,
        error_bad_sequence_number,
        in_progress,
        integer(7, 16#FFFFFFFF)
    ]).

gen_cause() ->
    oneof([
        {invalid_stream, gen_u16()},
        {missing_param, short_list(gen_u16())},
        {stale_cookie, gen_u32()},
        out_of_resource,
        {unresolvable_address, gen_small_binary()},
        {unrecognized_chunk, gen_small_binary()},
        invalid_mandatory_param,
        {unrecognized_params, gen_small_binary()},
        {no_user_data, gen_u32()},
        cookie_while_shutting_down,
        {restart_new_addresses, gen_small_binary()},
        {user_abort, gen_small_binary()},
        {protocol_violation, gen_small_binary()},
        {unknown_cause, ?SUCHTHAT(C, gen_u16(), C < 1 orelse C > 13), gen_small_binary()}
    ]).

%% A valid packet with random byte flips, truncations, insertions and
%% extensions applied to its wire form.
gen_mutated_packet() ->
    ?LET(
        {Packet, Mutations},
        {gen_packet(), non_empty(short_list(gen_mutation()))},
        lists:foldl(fun mutate/2, webrtc_sctp_chunk:encode(Packet), Mutations)
    ).

gen_mutation() ->
    oneof([
        {flip, non_neg_integer(), integer(1, 255)},
        {set, non_neg_integer(), gen_u8()},
        {truncate, non_neg_integer()},
        {insert, non_neg_integer(), gen_small_binary()},
        {extend, gen_small_binary()}
    ]).

mutate(_, <<>>) ->
    <<>>;
mutate({flip, Pos, X}, Bin) ->
    P = Pos rem byte_size(Bin),
    <<Pre:P/binary, B, Post/binary>> = Bin,
    <<Pre/binary, (B bxor X), Post/binary>>;
mutate({set, Pos, X}, Bin) ->
    P = Pos rem byte_size(Bin),
    <<Pre:P/binary, _, Post/binary>> = Bin,
    <<Pre/binary, X, Post/binary>>;
mutate({truncate, Pos}, Bin) ->
    binary:part(Bin, 0, Pos rem byte_size(Bin));
mutate({insert, Pos, Ins}, Bin) ->
    P = Pos rem byte_size(Bin),
    <<Pre:P/binary, Post/binary>> = Bin,
    <<Pre/binary, Ins/binary, Post/binary>>;
mutate({extend, Ext}, Bin) ->
    <<Bin/binary, Ext/binary>>.

short_list(G) ->
    ?SIZED(S, resize(min(S, 6), list(G))).
