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

-module(emqx_authorization_api).

-include("emqx_authorization.hrl").

-rest_api(#{name   => lookup_authorization,
            method => 'GET',
            path   => "/authorization",
            func   => lookup_authorization,
            descr  => "Lookup Authorization"
           }).

-rest_api(#{name   => update_authorization,
            method => 'PUT',
            path   => "/authorization",
            func   => update_authorization,
            descr  => "Rewrite authorization list"
           }).

-rest_api(#{name   => append_authorization,
            method => 'POST',
            path   => "/authorization/append",
            func   => append_authorization,
            descr  => "Add a new rule at the end of the authorization list"
           }).

-rest_api(#{name   => push_authorization,
            method => 'POST',
            path   => "/authorization/push",
            func   => push_authorization,
            descr  => "Add a new rule at the start of the authorization list"
           }).

-export([ lookup_authorization/2
        , update_authorization/2
        , append_authorization/2
        , push_authorization/2
        ]).

lookup_authorization(_Bindings, _Params) ->
    minirest:return({ok, emqx_authorization:lookup()}).

update_authorization(_Bindings, Params) ->
    case check(Params) of
        {ok, Rules} ->
            minirest:return(emqx_authorization:update(Rules));
        Error -> minirest:return(Error)
    end.

append_authorization(_Bindings, Params) ->
    case check(Params) of
        {ok, Rules} ->
            NRules = lists:append(emqx_authorization:lookup(), Rules),
            minirest:return(emqx_authorization:update(NRules));
        Error -> minirest:return(Error)
    end.

push_authorization(_Bindings, Params) ->
    case check(Params) of
        {ok, Rules} ->
            NRules = lists:append(Rules, emqx_authorization:lookup()),
            minirest:return(emqx_authorization:update(NRules));
        Error -> minirest:return(Error)
    end.

%%------------------------------------------------------------------------------
%% Interval Funcs
%%------------------------------------------------------------------------------

check(Rules) ->
    check(Rules, []).

check([Rule | Tail], NRules) ->
    case check_rule(Rule) of
        {ok, NRule} -> check(Tail, [NRule | NRules]);
        {error, Error} -> {error, Error}
    end;
check([], NRules) ->
    {ok, lists:reverse(NRules)}.

check_rule(Rule) when is_list(Rule) ->
    NRule = maps:from_list(Rule),
    Principal = case maps:get(<<"principal">>, NRule, <<"all">>)of
                    [{<<"and">>, AndList}] ->
                         #{<<"and">> => [maps:from_list(P) || P <- AndList]};
                    #{<<"or">> := List} ->
                         #{<<"or">> => [maps:from_list(P) || P <- List]};
                    P when is_list(P) -> maps:from_list(P);
                    <<"all">> -> <<"all">>
                 end,
    Topics = case maps:get(<<"topics">>, NRule, []) of
                 T when is_tuple(T) orelse is_binary(T) -> T;
                 T when is_list(T) ->
                     [begin
                          case is_list(Topic) of
                              true -> maps:from_list(Topic);
                              false -> Topic
                          end
                      end || Topic <- T]
             end,
    check_rule(NRule#{<<"principal">> => Principal,
                      <<"topics">> => Topics});

check_rule(#{<<"principal">> := <<"all">> } = Rule ) ->
    check_rule(maps:remove(<<"principal">>, Rule));

check_rule(#{<<"principal">> := Principal,
             <<"topics">>:= Topics,
             <<"action">> := Action,
             <<"access">> := Access
            } = Rule ) when ?ALLOW_DENY(Access), ?PUBSUB(Action) ->
    case check_item(topics, Topics) andalso check_item(principal, Principal) of
       true -> {ok, Rule };
       false -> {error, data_format_check_failed}
    end ;
check_rule(#{<<"topics">> := Topics,
             <<"action">> := Action,
             <<"access">> := Access
            } = Rule ) when ?ALLOW_DENY(Access), ?PUBSUB(Action) ->
    case check_item(topics, Topics) of
        true -> {ok, Rule};
        false -> {error, data_format_check_failed}
    end;

check_rule(_) -> {error, data_format_check_failed}.

check_item(topics, Topics) when is_list(Topics) ->
    lists:foldl(fun(Topic, Acc) ->
                    check_item(topic, Topic) andalso Acc
                end, true, Topics);
check_item(topics, Topics) when is_binary(Topics) orelse is_tuple(Topics) ->
    check_item(topic, Topics);

check_item(topic, Topic) when is_binary(Topic) -> true;
check_item(topic, #{<<"eq">> := Topic}) when is_binary(Topic) -> true;

check_item(principal, <<"all">>) -> true;
check_item(principal, #{<<"username">> := Username}) when is_binary(Username) -> true;
check_item(principal, #{<<"clientid">> := Clientid}) when is_binary(Clientid) -> true;
check_item(principal, #{<<"ipaddress">> := IpAddress}) when is_binary(IpAddress) -> true;
check_item(principal, #{<<"and">> := List}) when is_list(List) ->
    lists:foldl(fun(Principal, Acc) ->
                    check_item(principal, Principal) andalso Acc
                end, true, List);
check_item(principal, #{<<"or">> := List}) when is_list(List) ->
    lists:foldl(fun(Principal, Acc) ->
                    check_item(principal, Principal) andalso Acc
                end, true, List);

check_item(_, _) -> false.

%%--------------------------------------------------------------------
%% EUnits
%%--------------------------------------------------------------------

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").


-endif.
