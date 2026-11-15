%% @doc Sans-IO DNS message codec for multicast DNS (RFC 1035 §4,
%% RFC 6762).
%%
%% Only what mDNS ICE candidates need (draft-ietf-mmusic-mdns-ice-candidates):
%% queries and responses with A and AAAA records. Other record types are
%% decoded with their raw RDATA.
%%
%% ```
%% Q = webrtc_mdns_msg:encode_query(0, [{<<"x.local">>, a, true}]),
%% {ok, #{questions := [#{name := <<"x.local">>, type := a, unicast := true}]}} =
%%     webrtc_mdns_msg:decode(Q).
%% '''
%%
%% Decoding is bounded and never raises: compression pointers must point
%% strictly backwards (so they cannot loop), a name follows at most
%% `?MAX_HOPS' pointers, names are at most 255 octets on the wire
%% (RFC 1035 §2.3.4) and every count is checked against the bytes left.
%% Names are returned lower-cased (RFC 6762 §16: ASCII case-insensitive),
%% labels joined with `.'; a `.' or `\' inside a label is escaped with
%% `\' so that distinct label sequences never give the same name.
%%
%% In questions the top bit of the class is the unicast-response (QU)
%% bit (RFC 6762 §5.4); in resource records it is the cache-flush bit
%% (RFC 6762 §10.2). Both are reported separately from the class.
-module(webrtc_mdns_msg).

-export([encode_query/2, encode_response/4, decode/1, name_labels/1, normalize_name/1]).

-export_type([message/0, question/0, rr/0, rr_type/0]).

-type rr_type() :: a | aaaa | ptr | txt | srv | nsec | any | 0..65535.
-type question() :: #{name := binary(), type := rr_type(), class := 0..32767, unicast := boolean()}.
-type rr() :: #{
    name := binary(),
    type := rr_type(),
    class := 0..32767,
    cache_flush := boolean(),
    ttl := non_neg_integer(),
    data := inet:ip_address() | binary()
}.
-type message() :: #{
    id := 0..65535,
    qr := boolean(),
    opcode := 0..15,
    aa := boolean(),
    tc := boolean(),
    rcode := 0..15,
    questions := [question()],
    answers := [rr()],
    authority := [rr()],
    additional := [rr()]
}.

-define(CLASS_IN, 1).
-define(MAX_HOPS, 64).
-define(MAX_NAME, 255).

%%====================================================================
%% Encoding
%%====================================================================

%% @doc A query with the given questions, class IN. `Unicast' sets the
%% QU bit. Names are written without compression.
-spec encode_query(0..65535, [{binary(), rr_type(), boolean()}]) -> binary().
encode_query(Id, Questions) ->
    Qs = [[enc_name(N), <<(type_code(T)):16, (qclass(U)):16>>] || {N, T, U} <- Questions],
    iolist_to_binary([<<Id:16, 0:16, (length(Questions)):16, 0:16, 0:16, 0:16>> | Qs]).

%% @doc An authoritative response (QR and AA set) repeating `Questions'
%% (needed for legacy unicast replies, RFC 6762 §6.7) with A or AAAA
%% answers `[{Name, IP, TTL, CacheFlush}]' and additional records. An
%% answer `{Name, {nsec, Types}, TTL, CacheFlush}' is the NSEC record
%% saying `Name' has only `Types' (RFC 6762 §6.1).
-spec encode_response(
    0..65535,
    [{binary(), rr_type()}],
    [{binary(), inet:ip_address() | {nsec, [rr_type()]}, non_neg_integer(), boolean()}],
    [{binary(), inet:ip_address() | {nsec, [rr_type()]}, non_neg_integer(), boolean()}]
) -> binary().
encode_response(Id, Questions, Answers, Additional) ->
    Qs = [[enc_name(N), <<(type_code(T)):16, ?CLASS_IN:16>>] || {N, T} <- Questions],
    Header = <<Id:16, 1:1, 0:4, 1:1, 0:10, (length(Questions)):16, (length(Answers)):16, 0:16,
        (length(Additional)):16>>,
    iolist_to_binary([Header, Qs, [enc_addr_rr(R) || R <- Answers], [enc_addr_rr(R) || R <- Additional]]).

enc_addr_rr({Name, {nsec, Types}, TTL, Flush}) ->
    %% RFC 6762 §6.1: the next domain name is the record's own name,
    %% then one bitmap window (RFC 4034 §4.1.2) for types below 256.
    Codes = [type_code(T) || T <- Types],
    Len = lists:max(Codes) div 8 + 1,
    Bitmap = << <<(case lists:member(B, Codes) of true -> 1; false -> 0 end):1>> || B <- lists:seq(0, Len * 8 - 1) >>,
    Rdata = iolist_to_binary([enc_name(Name), <<0, Len>>, Bitmap]),
    [enc_name(Name), <<47:16, (rrclass(Flush)):16, TTL:32, (byte_size(Rdata)):16>>, Rdata];
enc_addr_rr({Name, {_, _, _, _} = IP, TTL, Flush}) ->
    [enc_name(Name), <<1:16, (rrclass(Flush)):16, TTL:32, 4:16>>, enc_ip(IP)];
enc_addr_rr({Name, {_, _, _, _, _, _, _, _} = IP, TTL, Flush}) ->
    [enc_name(Name), <<28:16, (rrclass(Flush)):16, TTL:32, 16:16>>, enc_ip(IP)].

enc_ip({A, B, C, D}) -> <<A, B, C, D>>;
enc_ip(IP6) -> <<<<W:16>> || W <- tuple_to_list(IP6)>>.

qclass(true) -> 16#8000 bor ?CLASS_IN;
qclass(false) -> ?CLASS_IN.

rrclass(Flush) -> qclass(Flush).

enc_name(Name) ->
    case name_labels(Name) of
        {ok, Labels} -> [[<<(byte_size(L))>>, L] || L <- Labels] ++ [<<0>>];
        error -> erlang:error({bad_name, Name})
    end.

%% @doc Split a dotted host name into DNS labels: 1 to 63 octets each,
%% at most 255 octets on the wire. A trailing dot is accepted.
-spec name_labels(binary()) -> {ok, [binary()]} | error.
name_labels(Name) when is_binary(Name), byte_size(Name) > 0 ->
    Labels =
        case binary:split(Name, <<".">>, [global]) of
            Ls when byte_size(Name) > 1 ->
                case lists:last(Ls) of
                    <<>> -> lists:droplast(Ls);
                    _ -> Ls
                end;
            Ls ->
                Ls
        end,
    Wire = lists:sum([byte_size(L) + 1 || L <- Labels]) + 1,
    case lists:all(fun(L) -> byte_size(L) >= 1 andalso byte_size(L) =< 63 end, Labels) of
        true when Wire =< ?MAX_NAME -> {ok, Labels};
        _ -> error
    end;
name_labels(_) ->
    error.

%% @doc Canonical form used to compare names: lower-case, no trailing
%% dot. `error' for names that are not valid host names on the wire.
-spec normalize_name(binary()) -> {ok, binary()} | error.
normalize_name(Name) ->
    case name_labels(Name) of
        {ok, Labels} -> {ok, lower(iolist_to_binary(lists:join($., Labels)))};
        error -> error
    end.

type_code(a) -> 1;
type_code(ptr) -> 12;
type_code(txt) -> 16;
type_code(aaaa) -> 28;
type_code(srv) -> 33;
type_code(nsec) -> 47;
type_code(any) -> 255;
type_code(N) when is_integer(N), N >= 0, N =< 65535 -> N.

type_name(1) -> a;
type_name(12) -> ptr;
type_name(16) -> txt;
type_name(28) -> aaaa;
type_name(33) -> srv;
type_name(47) -> nsec;
type_name(255) -> any;
type_name(N) -> N.

%%====================================================================
%% Decoding
%%====================================================================

%% @doc Decode a DNS message. Never raises: malformed input gives
%% `{error, Reason}'.
-spec decode(binary()) -> {ok, message()} | {error, term()}.
decode(Msg) when is_binary(Msg) ->
    try
        decode_msg(Msg)
    catch
        throw:{dns, Why} -> {error, Why}
    end;
decode(_) ->
    {error, not_binary}.

decode_msg(<<Id:16, QR:1, Op:4, AA:1, TC:1, _RD:1, _RA:1, _Z:3, RCode:4, QD:16, AN:16, NS:16, AR:16,
    _/binary>> = Msg) ->
    {Qs, P1} = questions(QD, Msg, 12, []),
    {Ans, P2} = records(AN, Msg, P1, []),
    {Auth, P3} = records(NS, Msg, P2, []),
    {Add, _P4} = records(AR, Msg, P3, []),
    {ok, #{
        id => Id,
        qr => QR =:= 1,
        opcode => Op,
        aa => AA =:= 1,
        tc => TC =:= 1,
        rcode => RCode,
        questions => Qs,
        answers => Ans,
        authority => Auth,
        additional => Add
    }};
decode_msg(_) ->
    throw({dns, short_header}).

questions(0, _Msg, Pos, Acc) ->
    {lists:reverse(Acc), Pos};
questions(N, Msg, Pos, Acc) ->
    {Name, P1} = name(Msg, Pos),
    case Msg of
        <<_:P1/binary, Type:16, U:1, Class:15, _/binary>> ->
            Q = #{name => Name, type => type_name(Type), class => Class, unicast => U =:= 1},
            questions(N - 1, Msg, P1 + 4, [Q | Acc]);
        _ ->
            throw({dns, truncated_question})
    end.

records(0, _Msg, Pos, Acc) ->
    {lists:reverse(Acc), Pos};
records(N, Msg, Pos, Acc) ->
    {Name, P1} = name(Msg, Pos),
    case Msg of
        <<_:P1/binary, Type:16, F:1, Class:15, TTL:32, Len:16, RData:Len/binary, _/binary>> ->
            T = type_name(Type),
            RR = #{
                name => Name,
                type => T,
                class => Class,
                cache_flush => F =:= 1,
                ttl => TTL,
                data => rdata(T, RData)
            },
            records(N - 1, Msg, P1 + 10 + Len, [RR | Acc]);
        _ ->
            throw({dns, truncated_record})
    end.

rdata(a, <<A, B, C, D>>) -> {A, B, C, D};
rdata(a, _) -> throw({dns, bad_a_length});
rdata(aaaa, <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) -> {A, B, C, D, E, F, G, H};
rdata(aaaa, _) -> throw({dns, bad_aaaa_length});
rdata(_, Bin) -> Bin.

%% Returns the name and the position after it in the original stream
%% (after the first pointer, if any).
name(Msg, Pos) ->
    {Labels, End} = labels(Msg, Pos, Pos, undefined, 0, 1, []),
    {lower(iolist_to_binary(lists:join($., [escape(L) || L <- Labels]))), End}.

%% Limit: the position a pointer must stay strictly below. End: the
%% position after the name in the original stream, set at the first
%% pointer. Wire: octets of the name so far (RFC 1035 §2.3.4).
labels(Msg, Pos, Limit, End, Hops, Wire, Acc) ->
    case Msg of
        <<_:Pos/binary, 0, _/binary>> ->
            {lists:reverse(Acc), pick(End, Pos + 1)};
        <<_:Pos/binary, 2#11:2, Off:14, _/binary>> ->
            if
                Hops >= ?MAX_HOPS -> throw({dns, too_many_pointers});
                Off >= Limit -> throw({dns, forward_pointer});
                true -> labels(Msg, Off, Off, pick(End, Pos + 2), Hops + 1, Wire, Acc)
            end;
        <<_:Pos/binary, 0:2, Len:6, Label:Len/binary, _/binary>> ->
            Wire1 = Wire + Len + 1,
            case Wire1 > ?MAX_NAME of
                true -> throw({dns, name_too_long});
                false -> labels(Msg, Pos + 1 + Len, Limit, End, Hops, Wire1, [Label | Acc])
            end;
        <<_:Pos/binary, 0:2, _:6, _/binary>> ->
            throw({dns, truncated_label});
        <<_:Pos/binary, _:2, _:6, _/binary>> ->
            throw({dns, bad_label_type});
        _ ->
            throw({dns, truncated_name})
    end.

pick(undefined, P) -> P;
pick(End, _) -> End.

escape(L) ->
    case binary:match(L, [<<".">>, <<"\\">>]) of
        nomatch -> L;
        _ -> <<<<(esc(C))/binary>> || <<C>> <= L>>
    end.

esc($.) -> <<"\\.">>;
esc($\\) -> <<"\\\\">>;
esc(C) -> <<C>>.

lower(B) -> <<<<(lc(C))>> || <<C>> <= B>>.

lc(C) when C >= $A, C =< $Z -> C + 32;
lc(C) -> C.
