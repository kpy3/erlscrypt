-module(scrypt).
-on_load(init/0).

-behaviour(application).

-export([start/2, stop/1]).
-export([scrypt/6]).

-define(APPNAME, scrypt).
-define(LIBNAME, scrypt).

%%%-------------------------------------------------------------------
%%% Application callbacks
%%%-------------------------------------------------------------------

start(_StartType, _StartArgs) ->
    {ok, self()}.

stop(_State) ->
    ok.

%%%-------------------------------------------------------------------
%%% API
%%%-------------------------------------------------------------------

-spec scrypt(binary(), binary(), non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()) -> binary().
scrypt(_Passwd, _Salt, _N, _R, _P, _Buflen) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, ?LINE}]}).

%%%-------------------------------------------------------------------
%%% Internal
%%%-------------------------------------------------------------------

init() ->
    SoName = case code:priv_dir(?APPNAME) of
                 {error, bad_name} ->
                     case filelib:is_dir(filename:join(["..", priv])) of
                         true ->
                             filename:join(["..", priv, ?LIBNAME]);
                         _ ->
                             filename:join([priv, ?LIBNAME])
                     end;
                 Dir ->
                     filename:join(Dir, ?LIBNAME)
             end,
    erlang:load_nif(SoName, 0).
