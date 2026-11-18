%% @private Keep secrets out of logs and process status. The peer
%% connection and transport states hold the DTLS private key, ICE and
%% TURN credentials, DTLS traffic secrets and SRTP keys; OTP prints a
%% process's state, last message and exit reason (with the arguments of
%% the top stack frame) in crash reports and `sys:get_status/1'.
%%
%% <ul>
%% <li>`status/2' is the body of a `format_status/1' callback: the state
%%     is replaced by a summary, messages keep their tag only, the
%%     reason is redacted.</li>
%% <li>`guard/3' runs a callback. An exception is logged here, redacted,
%%     and stops the process with `{shutdown, {crashed, Class, Reason,
%%     Stack}}': OTP writes no crash report for a shutdown, so none can
%%     list a message that arrived after `terminate/2' emptied the
%%     queue. A `throw' keeps its gen_server meaning (a return
%%     value).</li>
%% </ul>
-module(webrtc_redact).

-export([guard/2, guard/3, status/2, reason/1, stack/1, flush/0]).

%% @doc Drop every queued message, at the end of `terminate/2': the
%% crash report of `proc_lib' lists the queue as it is then.
-spec flush() -> ok.
flush() ->
    receive _ -> flush()
    after 0 -> ok
    end.

%% @doc Run a gen_server callback; an error or exit becomes
%% `{stop, {Class, Reason, Stack}, State}' with nothing but atoms, tags
%% and the module, function and arity of each frame.
-spec guard(fun(() -> term()), term()) -> term().
guard(Fun, St) ->
    guard(Fun, St, fun(_) -> #{} end).

%% @doc The same, logging the crash with `Summary(State)'.
-spec guard(fun(() -> term()), term(), fun((term()) -> map())) -> term().
guard(Fun, St, Summary) ->
    try
        Fun()
    catch
        throw:Value ->
            Value;
        Class:Reason:Stack ->
            Crash = {Class, reason(Reason), stack(Stack)},
            logger:error(#{label => {webrtc, crashed}, process => self(), crash => Crash,
                           state => try Summary(St) catch _:_ -> #{} end},
                         #{domain => [webrtc]}),
            {stop, {shutdown, {crashed, Crash}}, St}
    end.

%% @doc A `format_status/1' result: `Summary' for the state.
-spec status(map(), map()) -> map().
status(Summary, Status) ->
    maps:map(
        fun(state, _) -> Summary;
           (message, M) -> tag(M);
           (reason, R) -> reason(R);
           (log, L) when is_list(L) -> [tag(E) || E <- L];
           (queue, Q) when is_list(Q) -> [tag(E) || E <- Q];
           (_, V) -> V
        end,
        Status
    ).

%% @doc An exit or error reason with its values removed: atoms stay,
%% a tuple keeps its leading atom, a `{Reason, Stack}' pair keeps the
%% redacted stack.
-spec reason(term()) -> term().
reason(R) when is_atom(R) -> R;
reason({R, [{M, F, A, L} | _] = S}) when is_atom(M), is_atom(F), (is_list(A) orelse is_integer(A)), is_list(L) ->
    {reason(R), stack(S)};
reason({shutdown, R}) -> {shutdown, reason(R)};
reason(T) when is_tuple(T), tuple_size(T) > 0, is_atom(element(1, T)) -> {element(1, T), redacted};
reason(_) -> redacted.

%% @doc A stack trace with arities in place of arguments.
-spec stack(term()) -> term().
stack(S) when is_list(S) ->
    [case F of
         {M, Fn, A, L} when is_list(A) -> {M, Fn, length(A), L};
         _ -> F
     end || F <- S];
stack(_) ->
    [].

tag({'$gen_call', _From, M}) -> {'$gen_call', tag(M)};
tag({'$gen_cast', M}) -> {'$gen_cast', tag(M)};
tag(M) when is_atom(M) -> M;
tag(M) when is_tuple(M), tuple_size(M) > 0, is_atom(element(1, M)) -> element(1, M);
tag(_) -> redacted.
