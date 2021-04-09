-module(prop_scrypt).
-include_lib("proper/include/proper.hrl").

-export([prop_test/0]).

%%%%%%%%%%%%%%%%%%
%%% Properties %%%
%%%%%%%%%%%%%%%%%%

prop_test() ->
    ?FORALL(PasswordSalt, password_salt(), validate_scrypt(PasswordSalt)).

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

password_salt() ->
    ?LET({Password, Salt}, {binary(), binary()}, {Password, Salt}).
