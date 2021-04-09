-module(scrypt).
-on_load(init/0).

-behaviour(application).

-export([start/2, stop/1]).

-export([scrypt/6]).
-export([is_equal/2]).

-define(APPNAME, scrypt).
-define(LIBNAME, scrypt).

%%%-------------------------------------------------------------------
%%% API
%%%-------------------------------------------------------------------

-spec scrypt(
    binary(),
    binary(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer()
) -> binary().
scrypt(_Passwd, _Salt, _N, _R, _P, _Buflen) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, ?LINE}]}).

%% @doc Compares the two binaries in constant-time to avoid timing attacks.

-spec is_equal(binary(), binary()) -> boolean().
is_equal(A, B) when is_binary(A), is_binary(B) ->
    size(A) == size(B) andalso compare_binaries(A, B, 0) == 0.

%%%-------------------------------------------------------------------
%%% Internal
%%%-------------------------------------------------------------------

init() ->
    SoName =
        case code:priv_dir(?APPNAME) of
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

compare_binaries(<<>>, <<>>, Acc) ->
    Acc;
compare_binaries(
    <<A:1/unit:8, RestA/binary>>,
    <<B:1/unit:8, RestB/binary>>,
    Acc
) ->
    compare_binaries(RestA, RestB, Acc bor (A bxor B)).

%%%-------------------------------------------------------------------
%%% Application callbacks
%%%-------------------------------------------------------------------

start(_StartType, _StartArgs) ->
    {ok, self()}.

stop(_State) ->
    ok.
