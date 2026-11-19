%% Transports of later offers (RFC 9429 §5.2.2, RFC 9143 §7.5).
-module(webrtc_jsep_transport_tests).
-include_lib("eunit/include/eunit.hrl").

-define(T, webrtc_jsep_transport).

initial_offer_test() ->
    ?assertEqual([{<<"0">>, [<<"0">>, <<"1">>], true}], ?T:offer([], [<<"0">>, <<"1">>], [<<"0">>, <<"1">>], true)),
    ?assertEqual([{<<"0">>, [<<"0">>], false}, {<<"1">>, [<<"1">>], false}],
                 ?T:offer([], [<<"0">>, <<"1">>], [<<"0">>, <<"1">>], false)).

%% An unbundled answer keeps every section on its own transport, even
%% when we would bundle; new sections get their own too.
unbundled_answer_kept_test() ->
    Neg = [{<<"0">>, [<<"0">>], false}, {<<"1">>, [<<"1">>], false}],
    Order = [<<"0">>, <<"1">>, <<"2">>],
    ?assertEqual(Neg ++ [{<<"2">>, [<<"2">>], false}], ?T:offer(Neg, Order, Order, true)).

%% New sections join the first BUNDLE group; other groups stay.
new_section_joins_bundle_test() ->
    Neg = [{<<"0">>, [<<"0">>], false}, {<<"1">>, [<<"1">>, <<"2">>], true}],
    Order = [<<"0">>, <<"1">>, <<"2">>, <<"3">>],
    ?assertEqual([{<<"0">>, [<<"0">>], false}, {<<"1">>, [<<"1">>, <<"2">>, <<"3">>], true}],
                 ?T:offer(Neg, Order, Order, true)),
    ?assertEqual([{<<"0">>, [<<"0">>], false}, {<<"1">>, [<<"1">>, <<"2">>], true}, {<<"3">>, [<<"3">>], false}],
                 ?T:offer(Neg, Order, Order, false)).

%% A rejected section leaves its transport; a group whose tag is
%% rejected is named by its next section.
rejected_sections_test() ->
    Neg = [{<<"0">>, [<<"0">>, <<"1">>], true}, {<<"2">>, [<<"2">>], false}],
    Order = [<<"0">>, <<"1">>, <<"2">>],
    ?assertEqual([{<<"1">>, [<<"1">>], true}], ?T:offer(Neg, [<<"1">>], Order, true)).
