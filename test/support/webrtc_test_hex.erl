%% @doc Helpers to turn RFC hex dumps into binaries.
-module(webrtc_test_hex).
-export([b/1]).

%% Accepts whitespace, newlines and `}' annotations; anything after a run
%% of two or more spaces following hex is ignored per line.
-spec b(iodata()) -> binary().
b(Text) ->
    Lines = string:split(unicode:characters_to_list(Text), "\n", all),
    << <<(list_to_integer(H, 16))>> || L <- Lines, H <- line_hex(L) >>.

line_hex(L) ->
    Tokens = string:lexemes(L, " \t"),
    take_hex(Tokens).

take_hex([T | Rest]) ->
    case is_hex(T) of
        true when length(T) rem 2 =:= 0 -> pairs(T) ++ take_hex(Rest);
        _ -> []
    end;
take_hex([]) ->
    [].

pairs([A, B | R]) -> [[A, B] | pairs(R)];
pairs([]) -> [].

is_hex(S) ->
    S =/= [] andalso lists:all(fun(C) -> lists:member(C, "0123456789abcdefABCDEF") end, S).
