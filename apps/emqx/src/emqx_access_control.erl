%%--------------------------------------------------------------------
%% Copyright (c) 2017-2021 EMQ Technologies Co., Ltd. All Rights Reserved.
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

-module(emqx_access_control).

-include("emqx.hrl").

-export([authenticate/1]).

-type(result() :: #{auth_result := emqx_types:auth_result(),
                    anonymous := boolean()
                   }).

%%--------------------------------------------------------------------
%% APIs
%%--------------------------------------------------------------------

-spec(authenticate(emqx_types:clientinfo()) -> {ok, result()} | {error, term()}).
authenticate(ClientInfo = #{zone := Zone}) ->
    AuthResult = default_auth_result(Zone),
    case emqx_zone:get_env(Zone, bypass_auth_plugins, false) of
        true ->
            return_auth_result(AuthResult);
        false ->
            return_auth_result(run_hooks('client.authenticate', [ClientInfo], AuthResult))
    end.

default_auth_result(Zone) ->
    case emqx_zone:get_env(Zone, allow_anonymous, false) of
        true  -> #{auth_result => success, anonymous => true};
        false -> #{auth_result => not_authorized, anonymous => false}
    end.

-compile({inline, [run_hooks/3]}).
run_hooks(Name, Args, Acc) ->
    ok = emqx_metrics:inc(Name), emqx_hooks:run_fold(Name, Args, Acc).

-compile({inline, [return_auth_result/1]}).
return_auth_result(Result = #{auth_result := success}) ->
    {ok, Result};
return_auth_result(Result) ->
    {error, maps:get(auth_result, Result, unknown_error)}.
