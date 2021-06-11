%%--------------------------------------------------------------------
%% Copyright (c) 2020-2021 EMQ Technologies Co., Ltd. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%% http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------

-module(emqx_authorization_SUITE).

-compile(nowarn_export_all).
-compile(export_all).

-include("emqx_authorization.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("common_test/include/ct.hrl").

all() ->
    emqx_ct:all(?MODULE).

groups() ->
    [].

init_per_suite(Config) ->
    ok = emqx_ct_helpers:start_apps([emqx_authorization], fun set_special_configs/1),
    Config.

end_per_suite(_Config) ->
    emqx_ct_helpers:stop_apps([emqx_authorization]).

set_special_configs(emqx) ->
    application:set_env(emqx, allow_anonymous, true),
    application:set_env(emqx, enable_acl_cache, false),
    ok;

set_special_configs(_App) ->
    ok.

-define(RULE1, #{<<"principal">> => all,
                 <<"topics">> => [<<"#">>],
                 <<"action">> => pubsub,
                 <<"access">> => deny}
       ).
-define(RULE2, #{<<"principal">> =>
                    #{<<"ipaddress">> => <<"127.0.0.1">>},
                 <<"topics">> =>
                        [#{<<"eq">> => <<"#">>},
                         #{<<"eq">> => <<"+">>}
                        ] ,
                 <<"action">> => pubsub,
                 <<"access">> => allow}
       ).
-define(RULE3,#{<<"principal">> => 
                    #{<<"and">> => [#{<<"username">> => "^test?"},
                                    #{<<"clientid">> => "^test?"}
                                   ]},
                <<"topics">> => [<<"test">>],
                <<"action">> => pub,
                <<"access">> => allow}
       ).
-define(RULE4,#{<<"principal">> => 
                    #{<<"or">> => [#{<<"username">> => <<"^test">>},
                                   #{<<"clientid">> => <<"test?">>}
                                  ]},
                <<"topics">> => [<<"%u">>,<<"%c">>],
                <<"action">> => pub,
                <<"access">> => deny}
       ).


%%------------------------------------------------------------------------------
%% Testcases
%%------------------------------------------------------------------------------
t_compile(_) ->
    ?assertEqual(#{<<"access">> => deny,
                   <<"action">> => pubsub,
                   <<"principal">> => all,
                   <<"topics">> => [['#']]
                  },emqx_authorization:compile(?RULE1)),
    ?assertEqual(#{<<"access">> => allow,
                   <<"action">> => pubsub,
                   <<"principal">> =>
                        #{<<"ipaddress">> => {{127,0,0,1},{127,0,0,1},32}},
                   <<"topics">> => [#{<<"eq">> => ['#']},
                                    #{<<"eq">> => ['+']}]
                  }, emqx_authorization:compile(?RULE2)),
    ?assertMatch(
       #{<<"access">> := allow,
         <<"action">> := pub,
         <<"principal">> := 
                #{<<"and">> := [#{<<"username">> := {re_pattern, _, _, _, _}},
                                #{<<"clientid">> := {re_pattern, _, _, _, _}}
                               ]
                 },
         <<"topics">> := [[<<"test">>]]
        }, emqx_authorization:compile(?RULE3)),
    ?assertMatch(
       #{<<"access">> := deny,
         <<"action">> := pub,
         <<"principal">> :=
                #{<<"or">> := [#{<<"username">> := {re_pattern, _, _, _, _}},
                               #{<<"clientid">> := {re_pattern, _, _, _, _}}
                              ]
                 },
              <<"topics">> := [#{<<"pattern">> := [<<"%u">>]},
                               #{<<"pattern">> := [<<"%c">>]}
                              ]
        }, emqx_authorization:compile(?RULE4)),
    ok.

t_authorization(_) ->
    ClientInfo1 = #{clientid => <<"test">>,
                    username => <<"test">>,
                    peerhost => {127,0,0,1}
                   },
    ClientInfo2 = #{clientid => <<"test">>,
                    username => <<"test">>,
                    peerhost => {192,168,0,10}
                   },
    ClientInfo3 = #{clientid => <<"test">>,
                    username => <<"fake">>
                   },
    ClientInfo4 = #{clientid => <<"fake">>,
                    username => <<"test">>
                   },

    Rules1 = [emqx_authorization:compile(Rule) || Rule <- [?RULE1, ?RULE2]],
    Rules2 = [emqx_authorization:compile(Rule) || Rule <- [?RULE2, ?RULE1]],
    Rules3 = [emqx_authorization:compile(Rule) || Rule <- [?RULE3, ?RULE4]],
    Rules4 = [emqx_authorization:compile(Rule) || Rule <- [?RULE4, ?RULE1]],

    ?assertEqual(deny,
        emqx_authorization:check_authorization(#{}, subscribe, <<"#">>, deny, [])),
    ?assertEqual({ok, deny},
        emqx_authorization:check_authorization(ClientInfo1, subscribe, <<"+">>, deny, Rules1)),
    ?assertEqual({ok, allow},
        emqx_authorization:check_authorization(ClientInfo1, subscribe, <<"+">>, deny, Rules2)),
    ?assertEqual({ok, allow},
        emqx_authorization:check_authorization(ClientInfo1, publish, <<"test">>, deny, Rules3)),
    ?assertEqual({ok, deny},
        emqx_authorization:check_authorization(ClientInfo1, publish, <<"test">>, deny, Rules4)),
    ?assertEqual({ok, deny},
        emqx_authorization:check_authorization(ClientInfo2, subscribe, <<"#">>, deny, Rules2)),
    ?assertEqual({ok, deny},
        emqx_authorization:check_authorization(ClientInfo3, publish, <<"test">>, deny, Rules3)),
    ?assertEqual({ok, deny},
        emqx_authorization:check_authorization(ClientInfo3, publish, <<"fake">>, deny, Rules4)),
    ?assertEqual({ok, deny},
        emqx_authorization:check_authorization(ClientInfo4, publish, <<"test">>, deny, Rules3)),
    ?assertEqual({ok, deny},
        emqx_authorization:check_authorization(ClientInfo4, publish, <<"fake">>, deny, Rules4)),
    ok.