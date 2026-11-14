%% Property tests for webrtc_sdp and webrtc_sdp_candidate.
-module(prop_webrtc_sdp).
-include_lib("proper/include/proper.hrl").
-include("webrtc_sdp.hrl").

-export([
    prop_encode_parse/0,
    prop_random_bytes/0,
    prop_mutated_sample/0,
    prop_random_lines/0,
    prop_random_attribute/0,
    prop_candidate_roundtrip/0,
    prop_candidate_random/0
]).

%%--------------------------------------------------------------------
%% Properties
%%--------------------------------------------------------------------

%% A generated record encodes to text that parses back to the same record.
prop_encode_parse() ->
    ?FORALL(
        Sdp,
        sdp(),
        begin
            Bin = webrtc_sdp:encode(Sdp),
            ?WHENFAIL(
                io:format("~s~n~p~n", [Bin, webrtc_sdp:parse(Bin)]),
                webrtc_sdp:parse(Bin) =:= {ok, Sdp}
            )
        end
    ).

prop_random_bytes() ->
    ?FORALL(Bin, binary(), is_result(webrtc_sdp:parse(Bin))).

%% Corrupting one byte of a real sample never crashes the parser.
prop_mutated_sample() ->
    Samples = [B || {_, B} <- webrtc_sdp_samples:all()],
    ?FORALL(
        {Bin, Pos, Byte},
        ?LET(B, oneof(Samples), {B, choose(0, byte_size(B) - 1), byte()}),
        begin
            <<Pre:Pos/binary, _, Post/binary>> = Bin,
            is_result(webrtc_sdp:parse(<<Pre/binary, Byte, Post/binary>>))
        end
    ).

%% Random lines with valid type letters exercise the field order checks.
prop_random_lines() ->
    Line = ?LET(
        {T, V},
        {elements("vosiuepcbtrzkam"), oneof([text(), elements(field_values())])},
        [T, $=, V, "\r\n"]
    ),
    ?FORALL(
        Lines,
        list(Line),
        is_result(webrtc_sdp:parse(iolist_to_binary(["v=0\r\n" | Lines])))
    ).

%% Random values for every known attribute: parse returns a result.
prop_random_attribute() ->
    Names = [
        <<"rtpmap">>, <<"fmtp">>, <<"rtcp-fb">>, <<"extmap">>, <<"msid">>, <<"msid-semantic">>,
        <<"ssrc">>, <<"ssrc-group">>, <<"rid">>, <<"simulcast">>, <<"mid">>, <<"group">>,
        <<"ice-ufrag">>, <<"ice-pwd">>, <<"ice-options">>, <<"candidate">>, <<"fingerprint">>,
        <<"setup">>, <<"tls-id">>, <<"connection">>, <<"sctp-port">>, <<"max-message-size">>,
        <<"sctpmap">>, <<"rtcp">>, <<"ptime">>, <<"maxptime">>, <<"framerate">>, <<"identity">>,
        <<"label">>, <<"content">>, <<"rtcp-mux">>, <<"sendrecv">>
    ],
    Piece = oneof([
        text(),
        token(),
        elements([<<" ">>, <<":">>, <<";">>, <<",">>, <<"/">>, <<"=">>, <<"~">>, <<"*">>, <<"-">>, <<".">>]),
        ?LET(N, choose(0, 70000), integer_to_binary(N)),
        elements([<<"send">>, <<"recv">>, <<"pt=">>, <<"typ">>, <<"raddr">>, <<"sha-256">>, <<"AB">>, <<"IN IP4">>])
    ]),
    ?FORALL(
        {Name, Parts},
        {elements(Names), list(Piece)},
        begin
            Value = iolist_to_binary(Parts),
            Bin = iolist_to_binary([
                "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 9 RTP/AVP 0\r\na=",
                Name, ":", Value, "\r\n"
            ]),
            is_result(webrtc_sdp:parse(Bin))
        end
    ).

prop_candidate_roundtrip() ->
    ?FORALL(
        C,
        candidate(),
        begin
            Bin = webrtc_sdp_candidate:encode(C),
            webrtc_sdp_candidate:parse(Bin) =:= {ok, C} andalso
                webrtc_sdp_candidate:parse(webrtc_sdp_candidate:encode_attr(C)) =:= {ok, C}
        end
    ).

prop_candidate_random() ->
    ?FORALL(
        Bin,
        oneof([binary(), ?LET(Ws, list(oneof([token(), elements([<<"typ">>, <<"raddr">>, <<"rport">>])])), iolist_to_binary(lists:join(" ", Ws)))]),
        case webrtc_sdp_candidate:parse(Bin) of
            {ok, #sdp_candidate{}} -> true;
            {error, _} -> true
        end
    ).

is_result({ok, #sdp{}}) -> true;
is_result({error, {L, _}}) when is_integer(L), L >= 1 -> true;
is_result(_) -> false.

field_values() ->
    [
        <<"0">>,
        <<"- 1 1 IN IP4 127.0.0.1">>,
        <<"-">>,
        <<"0 0">>,
        <<"IN IP4 0.0.0.0">>,
        <<"AS:30">>,
        <<"audio 9 UDP/TLS/RTP/SAVPF 111">>,
        <<"rtpmap:111 opus/48000/2">>,
        <<"candidate:1 1 udp 1 192.0.2.1 1 typ host">>,
        <<"7d 1h 0 25h">>,
        <<"2882844526 -1h">>,
        <<"prompt">>
    ].

%%--------------------------------------------------------------------
%% Lexical generators
%%--------------------------------------------------------------------

-define(TOKEN_CHARS, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-.^_`{|}~").
-define(ALNUM, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789").

chars(Set, Min, Max) ->
    ?LET(N, choose(Min, Max), ?LET(L, vector(N, elements(Set)), list_to_binary(L))).

token() -> chars(?TOKEN_CHARS, 1, 12).

token(Max) -> chars(?TOKEN_CHARS, 1, Max).

alnum(Min, Max) -> chars(?ALNUM, Min, Max).

ice_chars(Min, Max) -> chars(?ALNUM ++ "+/", Min, Max).

rid_id() -> chars(?ALNUM ++ "-_", 1, 8).

%% Any byte except NUL, CR and LF.
text() ->
    ?LET(L, list(?SUCHTHAT(C, byte(), C =/= 0 andalso C =/= $\r andalso C =/= $\n)), list_to_binary(L)).

nonempty_text() -> ?LET({C, T}, {elements(?ALNUM), text()}, <<C, T/binary>>).

non_ws() -> ?LET(L, non_empty(list(oneof([choose(16#21, 16#7E), choose(16#80, 16#FF)]))), list_to_binary(L)).

opt(G) -> oneof([undefined, G]).

small_list(G) -> ?LET(N, choose(0, 4), vector(N, G)).

small_nonempty_list(G) -> ?LET(N, choose(1, 4), vector(N, G)).

uint32() -> choose(0, 4294967295).

port() -> choose(0, 65535).

pt() -> choose(0, 127).

address() ->
    oneof([
        {byte(), byte(), byte(), byte()},
        vector(8, choose(0, 65535)),
        ?LET(H, chars(?ALNUM ++ "-.", 3, 20), <<"h", H/binary>>),
        ?LET(H, alnum(4, 12), <<H/binary, ".local">>)
    ]).

ip_or_host() ->
    ?LET(A, address(), case A of L when is_list(L) -> list_to_tuple(L); _ -> A end).

%% time = POS-DIGIT 9*DIGIT / "0"
sdp_time_value() -> oneof([0, choose(1000000000, 99999999999)]).

typed_time() ->
    ?LET({N, U}, {choose(0, 100000), elements(["", "d", "h", "m", "s"])}, iolist_to_binary([integer_to_binary(N), U])).

repeat() ->
    ?LET(
        {I, U, Rest},
        {choose(1, 100000), elements(["", "d", "h", "m", "s"]), ?LET(N, choose(2, 4), vector(N, typed_time()))},
        [iolist_to_binary([integer_to_binary(I), U]) | Rest]
    ).

zone() ->
    {sdp_time_value(), ?LET({Neg, T}, {boolean(), typed_time()}, case Neg of true -> <<"-", T/binary>>; false -> T end)}.

key() ->
    oneof([
        <<"prompt">>,
        ?LET(T, text(), <<"clear:", T/binary>>),
        ?LET(B, binary(), <<"base64:", (base64:encode(B))/binary>>),
        ?LET(U, non_ws(), <<"uri:", U/binary>>)
    ]).

%%--------------------------------------------------------------------
%% Record generators
%%--------------------------------------------------------------------

sdp() ->
    ?LET(
        {O, Name, Info, Uri, Emails, Phones, Conn, Bws, Times, Key, Attrs, Media},
        {
            origin(),
            text(),
            opt(text()),
            opt(non_ws()),
            small_list(nonempty_text()),
            small_list(nonempty_text()),
            opt(connection()),
            small_list(bandwidth()),
            small_nonempty_list(sdp_time()),
            opt(key()),
            small_list(attribute()),
            small_list(media())
        },
        #sdp{
            origin = O,
            session_name = Name,
            information = Info,
            uri = Uri,
            emails = Emails,
            phones = Phones,
            connection = Conn,
            bandwidths = Bws,
            times = Times,
            key = Key,
            attributes = Attrs,
            media = Media
        }
    ).

origin() ->
    ?LET(
        {U, Id, Ver, N, T, A},
        {non_ws(), choose(0, 18446744073709551615), choose(0, 18446744073709551615), token(), token(), non_ws()},
        #sdp_origin{username = U, sess_id = Id, sess_version = Ver, nettype = N, addrtype = T, address = A}
    ).

connection() ->
    ?LET({N, T, A}, {token(), token(), non_ws()}, #sdp_connection{nettype = N, addrtype = T, address = A}).

bandwidth() -> {token(), choose(0, 10000000)}.

sdp_time() ->
    ?LET(
        {S, E, Rs, Zs},
        {sdp_time_value(), sdp_time_value(), small_list(repeat()), small_list(zone())},
        #sdp_time{start = S, stop = E, repeats = Rs, zones = Zs}
    ).

media() ->
    ?LET(
        {M, Port, Count, Proto, Fmts, Info, Conns, Bws, Key, Attrs},
        {
            token(),
            port(),
            opt(choose(1, 65535)),
            ?LET(Ps, small_nonempty_list(token()), iolist_to_binary(lists:join("/", Ps))),
            small_nonempty_list(token()),
            opt(text()),
            small_list(connection()),
            small_list(bandwidth()),
            opt(key()),
            ?SIZED(S, resize(min(S, 20), list(attribute())))
        },
        #sdp_media{
            media = M,
            port = Port,
            port_count = Count,
            proto = Proto,
            fmts = Fmts,
            information = Info,
            connections = Conns,
            bandwidths = Bws,
            key = Key,
            attributes = Attrs
        }
    ).

attribute() ->
    oneof([
        {?LET(T, token(), <<"x-", T/binary>>), oneof([undefined, text()])},
        {elements([extmap_allow_mixed, bundle_only, ice_lite, ice_mismatch, end_of_candidates, rtcp_mux, rtcp_mux_only, rtcp_rsize]), true},
        {direction, direction()},
        {rtpmap, ?LET({Pt, N, R, C}, {pt(), token(), choose(1, 200000), opt(choose(1, 8))}, #{pt => Pt, name => N, clock_rate => R, channels => C})},
        {fmtp, ?LET({F, Ps}, {oneof([pt(), ?LET(T, token(), <<"x", T/binary>>)]), small_nonempty_list(fmtp_param())}, #{fmt => F, params => Ps})},
        {rtcp_fb, ?LET({Pt, T, P}, {oneof([pt(), '*']), token(), opt(nonempty_text())}, #{pt => Pt, type => T, param => P})},
        {extmap, ?LET({Id, D, U, A}, {oneof([choose(1, 255), choose(4096, 4351)]), opt(direction()), non_ws(), opt(nonempty_text())}, #{id => Id, direction => D, uri => U, attributes => A})},
        {msid, ?LET({S, T}, {token(64), opt(token(64))}, #{stream => S, track => T})},
        {msid_semantic, ?LET({S, Ids}, {token(), small_list(token())}, #{semantic => S, ids => Ids})},
        {ssrc, ?LET({S, A, V}, {uint32(), token(), opt(text())}, #{ssrc => S, attribute => A, value => V})},
        {ssrc_group, ?LET({S, Ss}, {token(), small_list(uint32())}, #{semantics => S, ssrcs => Ss})},
        {rid, ?LET({Id, D, Pts, Ps}, {rid_id(), elements([send, recv]), small_list(pt()), small_list(rid_param())}, #{id => Id, direction => D, pts => Pts, params => Ps})},
        {simulcast, simulcast()},
        {mid, token()},
        {group, ?LET({S, Ms}, {token(), small_list(token())}, #{semantics => S, mids => Ms})},
        {ice_ufrag, ice_chars(4, 32)},
        {ice_pwd, ice_chars(22, 40)},
        {ice_options, small_nonempty_list(ice_chars(1, 12))},
        {candidate, candidate()},
        {fingerprint, fingerprint()},
        {setup, elements([actpass, active, passive, holdconn])},
        {tls_id, chars(?ALNUM ++ "+/-_", 20, 40)},
        {connection, elements([new, existing])},
        {sctp_port, port()},
        {max_message_size, choose(0, 4294967295)},
        {sctpmap, ?LET({P, Pr, S}, {port(), token(), opt(choose(1, 65535))}, #{port => P, protocol => Pr, streams => S})},
        {rtcp, ?LET({P, C}, {port(), opt(connection())}, #{port => P, connection => C})},
        {elements([ptime, maxptime, framerate]), num()},
        {identity, ?LET({A, Es}, {non_empty(binary()), small_list(non_ws())}, #{assertion => base64:encode(A), extensions => Es})},
        {label, token()},
        {content, small_nonempty_list(token())}
    ]).

direction() -> elements([sendrecv, sendonly, recvonly, inactive]).

num() ->
    oneof([choose(1, 1000), ?LET({I, F}, {choose(0, 1000), choose(1, 99)}, I + F / 100)]).

%% Keys and values that survive the `;' split and space trimming.
fmtp_param() ->
    oneof([
        {token(), oneof([<<>>, chars(?TOKEN_CHARS ++ "=/,:", 1, 12)])},
        token()
    ]).

rid_param() ->
    {?LET(N, chars(?ALNUM ++ "-", 1, 10), <<"x", N/binary>>), opt(chars(lists:seq(16#20, 16#3A) ++ lists:seq(16#3C, 16#7E), 0, 10))}.

simulcast() ->
    Streams = small_nonempty_list(small_nonempty_list({rid_id(), boolean()})),
    oneof([
        [{elements([send, recv]), Streams}],
        ?LET({A, B}, {Streams, Streams}, [{send, A}, {recv, B}]),
        ?LET({A, B}, {Streams, Streams}, [{recv, A}, {send, B}])
    ]).

fingerprint() ->
    oneof([
        ?LET(
            H,
            elements([{sha, 20}, {sha224, 28}, {sha256, 32}, {sha384, 48}, {sha512, 64}, {md5, 16}, {md2, 16}]),
            begin
                {Hash, N} = H,
                ?LET(V, binary(N), #{hash => Hash, value => V})
            end
        ),
        ?LET({T, V}, {chars("abcdefghijklmnopqrstuvwxyz-", 1, 8), non_empty(binary())}, #{hash => <<"x", T/binary>>, value => V})
    ]).

candidate() ->
    ?LET(
        {F, C, T, P, A, Port, Type, Rel, TcpType, Exts},
        {
            ice_chars(1, 32),
            choose(1, 256),
            oneof([<<"udp">>, <<"UDP">>, <<"tcp">>, token()]),
            choose(1, 2147483647),
            ip_or_host(),
            port(),
            oneof([host, srflx, prflx, relay, ?LET(X, token(), <<"x", X/binary>>)]),
            {opt(ip_or_host()), opt(port())},
            opt(elements([active, passive, so])),
            small_list({?LET(N, token(), <<"x", N/binary>>), non_ws()})
        },
        #sdp_candidate{
            foundation = F,
            component = C,
            transport = T,
            priority = P,
            address = A,
            port = Port,
            type = Type,
            raddr = element(1, Rel),
            rport = element(2, Rel),
            tcptype = TcpType,
            extensions = Exts
        }
    ).
