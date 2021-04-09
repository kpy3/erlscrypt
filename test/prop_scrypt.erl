-module(prop_scrypt).
-include_lib("proper/include/proper.hrl").

-export([prop_scrypt_test/0]).
-export([prop_is_equal_test/0]).
-export([prop_is_not_equal_test/0]).

%%%%%%%%%%%%%%%%%%
%%% Properties %%%
%%%%%%%%%%%%%%%%%%

prop_scrypt_test() ->
    ?FORALL(PasswordSalt, {binary(), binary()}, validate_scrypt(PasswordSalt)).

prop_is_equal_test() ->
    ?FORALL(B, binary(), scrypt:is_equal(B, B)).

prop_is_not_equal_test() ->
    ?FORALL({A, B}, non_equal_binaries(), not scrypt:is_equal(A, B)).

%%%%%%%%%%%%%%%
%%% Helpers %%%
%%%%%%%%%%%%%%%

validate_scrypt({Password, Salt}) ->
    try scrypt:scrypt(Password, Salt, 16384, 8, 1, 64) of
        B when is_binary(B) -> true
    catch
        _:_ -> false
    end.

%%%%%%%%%%%%%%%%%%
%%% Generators %%%
%%%%%%%%%%%%%%%%%%

non_equal_binaries() ->
    ?LET(A, pos_integer(), {binary(A), binary(A)}).
