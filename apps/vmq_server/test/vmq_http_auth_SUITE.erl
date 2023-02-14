-module(vmq_http_auth_SUITE).
-export([
         init_per_suite/1,
         end_per_suite/1,
         init_per_testcase/2,
         end_per_testcase/2,
         all/0
        ]).

-export([
          add_single_key/1,
		  no_double_keys/1,
		  test_expiry/1,
		  test_keyword_length/1
        ]).

init_per_suite(_Config) ->
    cover:start(),
    _Config.

end_per_suite(_Config) ->
    _Config.

init_per_testcase(_Case, Config) ->
    vmq_test_utils:setup(),
    Config.

end_per_testcase(_, Config) ->
    vmq_test_utils:teardown(),
    Config.

all() ->
    [add_single_key, no_double_keys, test_expiry,test_keyword_length].

add_single_key(_) ->
   ok = vmq_auth_apikey:add_api_key(<<"123456789012345678901234567890">>, "mgmt", undefined),
   ok = vmq_auth_apikey:add_api_key(<<"123456789012345678901234567890">>, "status", undefined),
   ok = vmq_auth_apikey:add_api_key(<<"123456789012345678901234567890">>, "metrics", undefined),
   ok.
   
no_double_keys(_) ->
   ok = vmq_auth_apikey:add_api_key(<<"123456789012345678901234567890">>, "mgmt", undefined),
   case vmq_auth_apikey:add_api_key(<<"123456789012345678901234567890">>, "mgmt", undefined) of
     {error, key_already_exists} -> ok
   end.
   
test_keyword_length(_) ->
  application:set_env(vmq_server, min_apikey_length, 50),
   case vmq_auth_apikey:add_api_key(<<"123456789012345678901234567890">>, "mgmt", undefined) of
     {error, invalid_key_length} -> ok
   end,
  application:set_env(vmq_server, min_apikey_length, 4),
  vmq_auth_apikey:add_api_key(<<"1234">>, "mgmt", undefined).


test_expiry(_) ->
  application:set_env(vmq_server, max_apikey_expiry_days, 10),
   case vmq_auth_apikey:add_api_key(<<"123456789012345678901234567890">>, "mgmt", "2044-02-18T17:00:00") of
     {error, invalid_expiry_date} -> ok
   end,
  case vmq_auth_apikey:add_api_key(<<"123456789012345678901234567890">>, "mgmt", undefined) of
     {error, invalid_expiry_date} -> ok
   end,
   application:set_env(vmq_server, max_apikey_expiry_days, undefined),
   vmq_auth_apikey:add_api_key(<<"1234567890123456789012345">>, "mgmt", "2044-02-18T17:00:00").
 

