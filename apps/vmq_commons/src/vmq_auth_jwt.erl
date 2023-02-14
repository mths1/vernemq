-module(vmq_auth_jwt).

-define(JWKS_FILE, "/path/to/jwks.json").
% 1 hr
-define(CACHE_REFRESH_INTERVAL, 3600000).

-include_lib("jose/include/jose.hrl").

-export(
    [
        fetch_jwks/1,
        load_jwks/1,
        validate_token/2,
        make_jwk/2,
        my_token/0 % MySuperSecretKey

    ]
).


check_cache() ->
    case ets:info(jwks_cache) of
        undefined ->
            reload_jwks();
        {_, _, _, _, _, _} = Info ->
            {_, _, _, _, _, LastUpdateTime} = Info,
            Now = os:timestamp(),
            case Now - LastUpdateTime >= ?CACHE_REFRESH_INTERVAL of
                true ->
                    ets:delete_all_objects(jwks_cache),
                    reload_jwks();
                false ->
                    ok
            end
    end.

make_jwk(hs256, Key) ->
    #{<<"k">> => base64:encode(Key), <<"kty">> => <<"oct">>}.

my_token() ->
    <<"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMTIzNDU2Nzg5MCIsImF1ZCI6IlZlcm5lTVFDbHVzdGVyMTAxIiwiaXNzIjoiVk1RIiwiYWxnIjoiZGlyIiwiZXhwIjoxNjgxMDAxMzI3fQ.ZzeZJdAv_qyPSsLl1NPaEc4wnOUhf7Sbngqw2Q94hLg">>.

check_exp(Exp) ->
        case Exp of
            undefined ->
                {error, cannot_validate_exp_claim};
            Exp when is_integer(Exp) -> case Exp > os:system_time(seconds) of
                                            true -> ok;
                                            _ -> {error, exp_claim_expired}
                                        end;
            _ ->
                {error, invalid_exp_claim}
        end.

validate_exp(JWT, JwtDecodeConfig) ->
    TokenPayload = jsx:decode(jose_jws:peek_payload(JWT)),
    CheckFlags = proplists:get_value(check_flags, JwtDecodeConfig, #{}),
    case maps:get(checkExp, CheckFlags, true) of
        true -> check_exp(maps:get(<<"exp">>, TokenPayload));
        false -> ok
    end.
check_aud(AudJwt, ExpectedAud)  when is_list(AudJwt), is_list(ExpectedAud) ->
    case AudJwt of
        undefined ->
            {error, <<"Missing or invalid 'aud' claim">>};
        Aud when is_list(Aud) ->
            case ExpectedAud of
                undefind ->
                    ok;
                LocalAud when is_list(LocalAud) ->
                    case lists:any(fun(X) -> lists:member(X, Aud) end, LocalAud) of
                        true -> ok;
                        false -> {error, cannot_validate_auth_claim}
                    end;
                _ ->
                    {error, cannot_validate_auth_claim}
            end;
        _ ->  {error, cannot_validate_auth_claim}
    end;
check_aud(AudJwt, ExpectedAud)  when is_binary(AudJwt), is_list(ExpectedAud) ->
    check_aud([AudJwt], ExpectedAud);
check_aud(AudJwt, ExpectedAud)  when is_binary(AudJwt), is_binary(ExpectedAud) ->
    check_aud([AudJwt], [ExpectedAud]);
check_aud(AudJwt, ExpectedAud)  when is_list(AudJwt), is_binary(ExpectedAud) ->
    check_aud(AudJwt, [ExpectedAud]).

validate_audience(JWT, JwtDecodeConfig) ->
    TokenPayload = jsx:decode(jose_jws:peek_payload(JWT)),
    CheckFlags = proplists:get_value(check_flags, JwtDecodeConfig, #{}),
    case maps:get(checkAud, CheckFlags, true) of
        true -> check_aud(maps:get(<<"aud">>, TokenPayload), proplists:get_value(local_aud, JwtDecodeConfig, undefined));
        false -> ok
    end.


validate_token(properties, JWT, JwtDecodeConfig) ->
    CheckFlags = proplists:get_value(check_flags, JwtDecodeConfig, #{}),
    TokenPayload = jsx:decode(jose_jws:peek_payload(JWT)),
    case maps:get(checkAud, CheckFlags, true) of
        true ->
            case proplists:get_value(<<"aud">>, TokenPayload) of
                undefined ->
                    {error, <<"Missing or invalid 'aud' claim">>};
                Aud when is_list(Aud) ->
                    case proplists:get_value(local_aud, JwtDecodeConfig) of
                        undefined ->
                            ok;
                        LocalAud when is_list(LocalAud) ->
                            case lists:member(Aud, LocalAud) of
                                true -> ok;
                                false -> {error, <<"Invalid 'aud' claim">>}
                            end;
                        _ ->
                            {error, <<"Invalid 'aud' claim">>}
                    end;
                _ ->
                    {error, <<"Invalid 'aud' claim">>}
            end;
        false ->
            ok
    end,
    case maps:get(checkIss, CheckFlags, true) of
        true ->
            case proplists:get_value(<<"iss">>, TokenPayload) of
                undefined ->
                    {error, <<"Missing or invalid 'iss' claim">>};
                Iss when is_binary(Iss) ->
                    case proplists:get_value(local_iss, JwtDecodeConfig) of
                        undefined -> ok;
                        <<LocalIss/binary>> when Iss == LocalIss -> ok;
                        _ -> {error, <<"Invalid 'iss' claim">>}
                    end;
                _ ->
                    {error, <<"Invalid 'iss' claim">>}
            end;
        false ->
            ok
    end,
    case maps:get(checkExp, CheckFlags, true) of
        true ->
            case proplists:get_value(<<"exp">>, TokenPayload) of
                undefined ->
                    {error, <<"Missing or invalid 'exp' claim">>};
                Exp when is_integer(Exp) ->
                    case proplists:get_value(local_exp, JwtDecodeConfig) of
                        undefined -> ok;
                        LocalExp when is_integer(LocalExp), Exp < LocalExp -> ok;
                        _ -> {error, <<"Token expired">>}
                    end;
                _ ->
                    {error, <<"Invalid 'exp' claim">>}
            end;
        false ->
            ok
    end,
    case maps:get(checkNbf, CheckFlags, true) of
        true ->
            case proplists:get_value(<<"nbf">>, TokenPayload) of
                undefined ->
                    {error, <<"Missing or invalid 'nbf' claim">>};
                Nbf when is_integer(Nbf) ->
                    case proplists:get_value(local_nbf, JwtDecodeConfig) of
                        undefined -> ok;
                        LocalNbf when is_integer(LocalNbf), Nbf >= LocalNbf -> ok;
                        _ -> {error, <<"Token not yet valid">>}
                    end;
                _ ->
                    {error, <<"Invalid 'nbf' claim">>}
            end;
        false ->
            ok
    end,
    true.

validate_token(JWT, JwtDecodeConfig) ->
    check_cache(),
    JWK = get_key(JWT, JwtDecodeConfig),
    lager:info("Key ~p", [JWK]),

    VerifyResult = jose_jwt:verify(JWK, jose_jws:expand(JWT)),
    case VerifyResult of
      {true, _, _} -> case (validate_audience(JWT, JwtDecodeConfig)) of
                          ok -> case validate_exp(JWT, JwtDecodeConfig) of
                                      ok -> true;
                                      Error -> Error
                                  end;
                          Error -> Error
                      end;
        _ -> {error, cannot_validate}
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Retrieve Key Stores either from a file or from the web
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

reload_jwks() ->
    ok.

load_jwks(Filename) ->
    case ets:info(jwks_cache) of
        [] -> ok;
        _ -> ets:delete_all_objects(jwks_cache)
    end,
    {ok, FileContent} = file:read_file(Filename),
    %    JwksJson = jsx:decode(FileContent),
    %
    %    [ets:insert(jwks_cache, Jwk) || Jwk <- Jwks],
    ok.

fetch_jwks(Url) ->
    case ets:info(jwks_cache) of
        [] -> ok;
        _ -> ets:delete_all_objects(jwks_cache)
    end,
    {ok, Response} = httpc:request("GET", {Url, []}, [], []),
    {ok, Body} = httpc:body(Response),
    Jwks = jwx_jwk:parse_jwks(Body),
    [ets:insert(jwks_cache, Jwk) || Jwk <- Jwks],
    ok.

%
% We load the keys in the following order:
% - First we check if there is a local key (configured) that matches the algorithm and audience.
% - If not we will check if there is something in the jwks_cache cache

get_key(Jwt, JwtDecodeConfig) ->
    Header = jsx:decode(jose_jws:peek_protected(Jwt)),
    Payload = jsx:decode(jose_jws:peek_payload(Jwt)),
    io:format("Header ~p", [Header]),
    io:format("Payload ~p", [Payload]),
    io:format("p2 ~p2", [proplists:get_value(local_keys, JwtDecodeConfig, [])]),
    case
        lists:filter(
            fun({_, Aud, Alg}) ->
                case maps:get(<<"aud">>, Payload, undefined) of
                    undefined -> false;
                    Audience -> Audience == Aud
                end andalso Alg == maps:get(<<"alg">>, Header, undefined)
            end,
            proplists:get_value(local_keys, JwtDecodeConfig, [])
        )
    of
        [{_, _, _} = LocalKey | _] ->
            make_jwk(list_to_atom(binary_to_list(string:lowercase(element(3, LocalKey)))), element(1, LocalKey));
        [] ->
            case maps:get(<<"alg">>, Header, undefined) of
                none ->
                    none;
                Alg ->
                    Kid = maps:get(<<"kid">>, Header, undefined),
                    Ad = maps:get(<<"aud">>, Payload, undefined),
                    case ets:lookup(jwks_cache, {Kid, Alg, Ad}) of
                        {ok, Jwk} -> Jwk;
                        error -> {error, <<"Could not find key in JWKS">>}
                    end
            end
    end.
