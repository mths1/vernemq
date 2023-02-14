-module(vmq_auth_jwt_SUITE).

-export([
    %% suite/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2,
    all/0,
    validate_token_local/1,
    validate_token_local_wrong_key/1
]).

%% ===================================================================
%% common_test callbacks
%% ===================================================================
init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

all() -> [
    validate_token_local,validate_token_local_wrong_key
].

%
% TESTS
%

%% Tokens used for tests
%% test_jwt_1 -> Standard token, valid
%% test_jwt_expired -> expired token
%% test_jwt_without_exp -> token that does not have exp
%%

test_jwt_1() ->
    <<"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMTIzNDU2Nzg5MCIsImF1ZCI6IlZlcm5lTVFDbHVzdGVyMTAxIiwiaXNzIjoiVk1RIiwiYWxnIjoiZGlyIiwiZXhwIjozNzY3NzM2NTQ3MH0.uq0dBfNKKA9_RRHOWYXxOB9IutxMeIV1X-g8vfO9OF8">>.
test_jwt_expired() ->
    <<"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMTIzNDU2Nzg5MCIsImF1ZCI6IlZlcm5lTVFDbHVzdGVyMTAxIiwiaXNzIjoiVk1RIiwiYWxnIjoiZGlyIiwiZXhwIjoxNjc3NDI0NDAwfQ.RYWFcOeMcF5Pyv-WxOKUTrAgsdFkivgfociSFcLMvEw">>.
test_jwt_without_exp() ->
    <<"">>.


test_local_key_jwt_decode(Audience) ->
   [{local_keys, [{<<"MySuperDuperSecretKey">>, <<"VerneMQCluster101">>, <<"HS256">>}]}, {local_aud, Audience}].

test_local_key_jwt_decode_wrong_key() ->
    [{local_keys, [{<<"MySuperDuperSecretKeyWhichIsWrong">>, <<"VerneMQCluster101">>, <<"HS256">>}]}].

validate_token_local(_) ->
    % We test the first token against a valid key in jwt decode
    true = vmq_auth_jwt:validate_token(test_jwt_1(), test_local_key_jwt_decode([<<"VerneMQCluster101">>])),
    % Change the audience and it should fail
    {error,cannot_validate_auth_claim} = vmq_auth_jwt:validate_token(test_jwt_1(), test_local_key_jwt_decode([<<"VerneMQCluster102">>])),
    % Audience list should be ok
    true = vmq_auth_jwt:validate_token(test_jwt_1(), test_local_key_jwt_decode([<<"A1">>,<<"VerneMQCluster101">>, <<"A3">>])),
    % expired token
    {error, token_expired} = vmq_auth_jwt:validate_token(test_jwt_expired(), test_local_key_jwt_decode([<<"VerneMQCluster101">>])).



validate_token_local_wrong_key(_) ->
    {error,cannot_validate} = vmq_auth_jwt:validate_token(test_jwt_1(), test_local_key_jwt_decode_wrong_key()).
