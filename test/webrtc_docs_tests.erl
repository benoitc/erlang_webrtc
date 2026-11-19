%%% -*- erlang -*-
%%%
%%% Copyright (c) 2026 Enki Multimedia and Benoit Chesneau
%%% Apache License 2.0
%%%
%% Documentation kept in sync with the code.
%%
%% The option tables of docs/REFERENCE.md must list exactly the keys the
%% code reads. Nothing in the code holds a list of the accepted keys
%% (unknown keys are ignored), so the keys are taken from the compiled
%% code itself (debug_info): every `maps:get/find/is_key/take' of a
%% literal key and every `maps:with' of literal keys on the options map,
%% and every key matched in a map pattern bound to it. Renaming the
%% options variable makes the documented keys look unread, so the test
%% fails rather than passing silently.
%%
%% The relative links of the top-level and docs/ markdown files must
%% point to files that exist.
-module(webrtc_docs_tests).

-include_lib("eunit/include/eunit.hrl").

%% Keys the peer connection adds to its own options map; not options.
-define(INTERNAL_PC_KEYS, [peer_sup, server_fallbacks, server_urls, servers_down]).

%%====================================================================
%% Options
%%====================================================================

peer_connection_options_test() ->
    Code = lists:usort(
        keys(webrtc, ['Opts'], [{new_peer_connection, 1}, {servers, 1}, {new_pc, 1}], [{servers, 1}, {new_pc, 1}]) ++
            keys(webrtc_pc, ['Opts', 'Opts0', 'O'], all, [])
    ) -- ?INTERNAL_PC_KEYS,
    check(<<"Peer connection options">>, Code).

transceiver_options_test() ->
    check(<<"Transceiver options">>, keys(webrtc_jsep, ['Opts'], [{add_transceiver, 3}], [])).

data_channel_options_test() ->
    check(<<"Data channel options">>, keys(webrtc_dcep, ['Opts'], [{channel_from_opts, 3}], [])).

check(Section, Code0) ->
    Code = lists:usort(Code0),
    Doc = table_keys(Section),
    ?assertNotEqual([], Code),
    ?assertNotEqual([], Doc),
    ?assertEqual({Section, read_but_not_documented, []}, {Section, read_but_not_documented, Code -- Doc}),
    ?assertEqual({Section, documented_but_not_read, []}, {Section, documented_but_not_read, Doc -- Code}).

%% The keys of the first column of the table under `## Section', up to
%% the next heading.
table_keys(Section) ->
    {ok, Bin} = file:read_file(filename:join([root(), "docs", "REFERENCE.md"])),
    Lines = binary:split(Bin, <<"\n">>, [global]),
    Heading = <<"## ", Section/binary>>,
    [_ | After] = lists:dropwhile(fun(L) -> string:trim(L, trailing) =/= Heading end, Lines),
    Body = lists:takewhile(fun(L) -> not is_heading(L) end, After),
    lists:usort([binary_to_atom(K) || L <- Body,
                                      {match, [K]} <- [re:run(L, "^\\|\\s*`([a-z0-9_]+)`", [{capture, all_but_first, binary}])]]).

is_heading(<<"#", _/binary>>) -> true;
is_heading(_) -> false.

%% Keys read from the options map in module `Mod': in the functions
%% `Funs' (or `all'), calls on a variable named in `Vars' or on
%% `St#st.opts', map patterns bound to such a variable, and the map
%% patterns in the clause heads of `HeadFuns'.
keys(Mod, Vars, Funs, HeadFuns) ->
    {ok, {Mod, [{abstract_code, {raw_abstract_v1, Forms}}]}} = beam_lib:chunks(beam(Mod), [abstract_code]),
    Fns = [F || {function, _, Name, Arity, _} = F <- Forms, Funs =:= all orelse lists:member({Name, Arity}, Funs)],
    Heads = [K || {function, _, Name, Arity, Clauses} <- Forms, lists:member({Name, Arity}, HeadFuns),
                  {clause, _, Ps, _, _} <- Clauses, K <- map_keys(Ps)],
    lists:usort(Heads ++ lists:flatmap(fun(F) -> walk(F, Vars) end, Fns)).

%% With cover on, code:which/1 says cover_compiled: read the beam file.
beam(Mod) ->
    case code:which(Mod) of
        Path when is_list(Path) -> Path;
        _ -> code:where_is_file(atom_to_list(Mod) ++ ".beam")
    end.

walk({call, _, {remote, _, {atom, _, maps}, {atom, _, F}}, [{atom, _, K}, M | _] = Args}, Vars)
  when F =:= get; F =:= find; F =:= is_key; F =:= take ->
    [K || opts(M, Vars)] ++ walk(Args, Vars);
walk({call, _, {remote, _, {atom, _, maps}, {atom, _, with}}, [List, M]} = Call, Vars) ->
    case opts(M, Vars) of
        true -> atoms(List);
        false -> []
    end ++ walk(tuple_to_list(Call), Vars);
walk({match, _, {map, _, _} = P, {var, _, V}} = Match, Vars) ->
    [K || lists:member(V, Vars), K <- map_keys(P)] ++ walk(tuple_to_list(Match), Vars);
walk({match, _, {var, _, V}, {map, _, _} = P} = Match, Vars) ->
    [K || lists:member(V, Vars), K <- map_keys(P)] ++ walk(tuple_to_list(Match), Vars);
walk(T, Vars) when is_tuple(T) ->
    walk(tuple_to_list(T), Vars);
walk(L, Vars) when is_list(L) ->
    lists:flatmap(fun(X) -> walk(X, Vars) end, L);
walk(_, _) ->
    [].

opts({var, _, V}, Vars) -> lists:member(V, Vars);
opts({record_field, _, _, st, {atom, _, opts}}, _) -> true;
opts(_, _) -> false.

atoms({cons, _, {atom, _, A}, T}) -> [A | atoms(T)];
atoms({cons, _, _, T}) -> atoms(T);
atoms(_) -> [].

%% Literal keys of the top-level map patterns in a pattern (or list).
map_keys({map, _, Fields}) -> [K || {map_field_exact, _, {atom, _, K}, _} <- Fields];
map_keys({match, _, A, B}) -> map_keys(A) ++ map_keys(B);
map_keys(L) when is_list(L) -> lists:flatmap(fun map_keys/1, L);
map_keys(_) -> [].

%%====================================================================
%% Links
%%====================================================================

markdown_links_test() ->
    Root = root(),
    Top = [F || F <- ["README.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md"],
                filelib:is_regular(filename:join(Root, F))],
    Docs = [F || F <- filelib:wildcard("docs/**/*.md", Root), not lists:prefix("docs/reviews/", F)],
    Broken = [{F, Link} || F <- Top ++ Docs, Link <- links(filename:join(Root, F)),
                           not filelib:is_file(target(Root, F, Link))],
    ?assertEqual([], Broken).

%% Relative link targets of a markdown file, outside code.
links(Path) ->
    {ok, Bin} = file:read_file(Path),
    Text = strip_code(Bin),
    Inline = [L || [L] <- matches(Text, "\\]\\(\\s*<?([^)\\s>]+)>?(?:\\s+\"[^\"]*\")?\\s*\\)")],
    Refs = [L || [L] <- matches(Text, "(?m)^\\s{0,3}\\[[^\\]]+\\]:\\s*<?([^\\s>]+)>?")],
    [L || L <- Inline ++ Refs, relative(L)].

matches(Text, Re) ->
    case re:run(Text, Re, [global, {capture, all_but_first, list}]) of
        {match, Ms} -> Ms;
        nomatch -> []
    end.

relative("#" ++ _) -> false;
relative("mailto:" ++ _) -> false;
relative(L) -> string:find(L, "://") =:= nomatch.

target(Root, File, Link) ->
    Path = uri_string:percent_decode(hd(string:split(hd(string:split(Link, "#")), "?"))),
    case Path of
        "/" ++ FromRoot -> filename:join(Root, FromRoot);
        _ -> filename:join(filename:dirname(filename:join(Root, File)), Path)
    end.

%% Fenced code blocks and inline code spans removed.
strip_code(Bin) ->
    Lines = binary:split(Bin, <<"\n">>, [global]),
    {Kept, _} = lists:foldl(
        fun(L, {Acc, InFence}) ->
            case re:run(L, "^\\s*(```|~~~)", [{capture, none}]) of
                match -> {Acc, not InFence};
                nomatch when InFence -> {Acc, InFence};
                nomatch -> {[L | Acc], InFence}
            end
        end,
        {[], false},
        Lines
    ),
    Text = iolist_to_binary(lists:join(<<"\n">>, lists:reverse(Kept))),
    re:replace(Text, "`[^`\\n]*`", "", [global, {return, list}]).

%%====================================================================
%% The project root: the first directory up from this file (or its
%% beam) that holds rebar.config and docs/.
%%====================================================================

root() ->
    Starts = [filename:dirname(?FILE), filename:dirname(beam(?MODULE)), element(2, file:get_cwd())],
    case [R || S <- Starts, R <- [up(filename:absname(S))], R =/= none] of
        [Root | _] -> Root;
        [] -> error(project_root_not_found)
    end.

up(Dir) ->
    case filelib:is_regular(filename:join(Dir, "rebar.config")) andalso
             filelib:is_dir(filename:join(Dir, "docs")) of
        true ->
            Dir;
        false ->
            case filename:dirname(Dir) of
                Dir -> none;
                Parent -> up(Parent)
            end
    end.
