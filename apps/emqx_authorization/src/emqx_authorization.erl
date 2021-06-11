%%--------------------------------------------------------------------
%% Copyright (c) 2020-2021 EMQ Technologies Co., Ltd. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------

-module(emqx_authorization).

-include("emqx_authorization.hrl").

-export([ init/0
        , compile/1
        , lookup/0
        , update/1
        , check_authorization/5
        ]).

init() ->
    % {ok, Conf} = hocon:load("etc/plugins/emqx_authorization.conf",#{format => richmap}),
    RawConf = proplists:get_value(rules, application:get_all_env(?APP), []),
    {ok, MapConf} = hocon:binary(jsx:encode(#{rules => RawConf}), #{format => richmap}),
    CheckConf = hocon_schema:check(emqx_authorization_schema, MapConf),
    #{<<"rules">> := Rules} = hocon_schema:richmap_to_map(CheckConf),
    ok = application:set_env(?APP, rules, Rules),
    NRules = [compile(Rule) || Rule <- Rules],
    ok = emqx_hooks:add('client.check_acl', {?MODULE, check_authorization, [NRules]},  -1).

lookup() ->
    application:get_env(?APP, rules, []).

update(Rules) ->
    ok = application:set_env(?APP, rules, Rules),
    NRules = [compile(Rule) || Rule <- Rules],
    Action = find_action_in_hooks(),
    ok = emqx_hooks:del('client.check_acl', Action),
    ok = emqx_hooks:add('client.check_acl', {?MODULE, check_authorization, [NRules]},  -1),
    ok = emqx_acl_cache:empty_acl_cache().

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------

find_action_in_hooks() ->
    Callbacks = emqx_hooks:lookup('client.check_acl'),
    [Action] = [Action || {callback,{?MODULE, check_authorization, _} = Action, _, _} <- Callbacks ],
    Action.

-spec(compile(rule()) -> rule()).
compile(#{<<"topics">> := Topics,
          <<"action">> := Action,
          <<"access">> := Access,
          <<"principal">> := Principal
         } = Rule ) when ?ALLOW_DENY(Access), ?PUBSUB(Action), is_list(Topics) ->
    NTopics = [compile_topic(Topic) || Topic <- Topics],
    Rule#{<<"principal">> => compile_principal(Principal),
          <<"topics">> => NTopics
         };
compile(Rule) -> Rule.

compile_principal(all) -> all;
compile_principal(#{<<"username">> := Username}) ->
    {ok, MP} = re:compile(bin(Username)),
    #{<<"username">> => MP};
compile_principal(#{<<"clientid">> := Clientid}) ->
    {ok, MP} = re:compile(bin(Clientid)),
    #{<<"clientid">> => MP};
compile_principal(#{<<"ipaddress">> := IpAddress}) ->
    #{<<"ipaddress">> => esockd_cidr:parse(binary_to_list(IpAddress), true)};
compile_principal(#{<<"and">> := Principals}) when is_list(Principals) ->
    #{<<"and">> => [compile_principal(Principal) || Principal <- Principals]};
compile_principal(#{<<"or">> := Principals}) when is_list(Principals) ->
    #{<<"or">> => [compile_principal(Principal) || Principal <- Principals]}.

compile_topic(#{<<"eq">> := Topic}) ->
    #{<<"eq">> => emqx_topic:words(bin(Topic))};
compile_topic(Topic) when is_binary(Topic)->
    Words = emqx_topic:words(bin(Topic)),
    case pattern(Words) of
        true  -> #{<<"pattern">> => Words};
        false -> Words
    end.

pattern(Words) ->
    lists:member(<<"%u">>, Words) orelse lists:member(<<"%c">>, Words).

bin(L) when is_list(L) ->
    list_to_binary(L);
bin(B) when is_binary(B) ->
    B.

%%--------------------------------------------------------------------
%% ACL callbacks
%%--------------------------------------------------------------------

%% @doc Check ACL
-spec(check_authorization(emqx_types:clientinfo(), emqx_types:pubsub(), emqx_topic:topic(), emqx_access_rule:acl_result(), rules())
      -> {ok, allow} | {ok, deny} | deny).
check_authorization(Client, PubSub, Topic, DefaultResult,
                    [Rule = #{<<"access">> := Access} | Tail]) ->
    case match(Client, PubSub, Topic, Rule) of
        true -> {ok, Access};
        false -> check_authorization(Client, PubSub, Topic, DefaultResult, Tail)
    end;
check_authorization(_Client, _PubSub, _Topic, DefaultResult, []) -> DefaultResult.

match(Client, PubSub, Topic,
      #{<<"principal">> := Principal,
        <<"topics">> := TopicFilters,
        <<"action">> := Action
       }) ->
    match_action(PubSub, Action) andalso
    match_principal(Client, Principal) andalso
    match_topics(Client, Topic, TopicFilters).

match_action(publish, pub) -> true;
match_action(subscribe, sub) -> true;
match_action(_, pubsub) -> true;
match_action(_, _) -> false.

match_principal(_, all) -> true;
match_principal(#{username := undefined}, #{<<"username">> := _MP}) ->
    false;
match_principal(#{username := Username}, #{<<"username">> := MP}) ->
    case re:run(Username, MP) of
        {match, _} -> true;
        _ -> false
    end;
match_principal(#{clientid := Clientid}, #{<<"clientid">> := MP}) ->
    case re:run(Clientid, MP) of
        {match, _} -> true;
        _ -> false
    end;
match_principal(#{peerhost := undefined}, #{<<"ipaddress">> := _CIDR}) ->
    false;
match_principal(#{peerhost := IpAddress}, #{<<"ipaddress">> := CIDR}) ->
    esockd_cidr:match(IpAddress, CIDR);
match_principal(ClientInfo, #{<<"and">> := Principals}) when is_list(Principals) ->
    lists:foldl(fun(Principal, Access) ->
                  match_principal(ClientInfo, Principal) andalso Access
                end, true, Principals);
match_principal(ClientInfo, #{<<"or">> := Principals}) when is_list(Principals) ->
    lists:foldl(fun(Principal, Access) ->
                  match_principal(ClientInfo, Principal) orelse Access
                end, false, Principals);
match_principal(_, _) -> false.

match_topics(_ClientInfo, _Topic, []) ->
    false;
match_topics(ClientInfo, Topic, [#{<<"pattern">> := PatternFilter}|Filters]) ->
    TopicFilter = feed_var(ClientInfo, PatternFilter),
    match_topic(emqx_topic:words(Topic), TopicFilter)
        orelse match_topics(ClientInfo, Topic, Filters);
match_topics(ClientInfo, Topic, [TopicFilter|Filters]) ->
   match_topic(emqx_topic:words(Topic), TopicFilter)
       orelse match_topics(ClientInfo, Topic, Filters).

match_topic(Topic, #{<<"eq">> := TopicFilter}) ->
    Topic == TopicFilter;
match_topic(Topic, TopicFilter) ->
    emqx_topic:match(Topic, TopicFilter).

feed_var(ClientInfo, Pattern) ->
    feed_var(ClientInfo, Pattern, []).
feed_var(_ClientInfo, [], Acc) ->
    lists:reverse(Acc);
feed_var(ClientInfo = #{clientid := undefined}, [<<"%c">>|Words], Acc) ->
    feed_var(ClientInfo, Words, [<<"%c">>|Acc]);
feed_var(ClientInfo = #{clientid := ClientId}, [<<"%c">>|Words], Acc) ->
    feed_var(ClientInfo, Words, [ClientId |Acc]);
feed_var(ClientInfo = #{username := undefined}, [<<"%u">>|Words], Acc) ->
    feed_var(ClientInfo, Words, [<<"%u">>|Acc]);
feed_var(ClientInfo = #{username := Username}, [<<"%u">>|Words], Acc) ->
    feed_var(ClientInfo, Words, [Username|Acc]);
feed_var(ClientInfo, [W|Words], Acc) ->
    feed_var(ClientInfo, Words, [W|Acc]).