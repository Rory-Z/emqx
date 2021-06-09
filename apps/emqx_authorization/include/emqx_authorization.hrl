-type(rule() :: #{binary() => any()}).
-type(rules() :: [rule()]).

-define(APP, emqx_authorization).

-define(ALLOW_DENY(A), ((A =:= allow) orelse (A =:= deny))).
-define(PUBSUB(A), ((A =:= sub) orelse (A =:= pub) orelse (A =:= pubsub))).

