-module(emqttd_crl_srv).
-include_lib("public_key/include/public_key.hrl").

-behaviour(gen_server).

%% API
-export([start_link/0,
         check_crl/2]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-record(state, {refs=[]}).
-define(TAB, ?MODULE).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

check_crl(File, #'OTPCertificate'{tbsCertificate=TBSCert} = Cert) ->
    SerialNr = TBSCert#'OTPTBSCertificate'.serialNumber,
    case ets:lookup(?TAB, File) of
        [{_, Serials}] ->
            not lists:member(SerialNr, Serials);
        [] ->
            %% no clr loaded
            gen_server:call(?MODULE, {add_crl, File}),
            check_crl(File, Cert)
    end.



%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    ets:new(?TAB, [public, named_table, {read_concurrency, true}]),
    {ok, #state{}}.

handle_call({add_crl, File}, _From, State) ->
    {ok, Bin} = file:read_file(File),
    Serials =
    lists:flatten([begin
                       CRL = public_key:pem_entry_decode(E) ,
                       #'TBSCertList'{revokedCertificates=Revoked} = CRL#'CertificateList'.tbsCertList,
                       [SerialNr || #'TBSCertList_revokedCertificates_SEQOF'{userCertificate=SerialNr} <- Revoked]
                   end || E <- public_key:pem_decode(Bin)]),
    ets:insert(?TAB, {File, Serials}),
    Reply = ok,
    {reply, Reply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
