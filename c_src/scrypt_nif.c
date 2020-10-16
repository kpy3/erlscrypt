#include "erl_nif.h"

static
ERL_NIF_TERM
mk_atom(ErlNifEnv* env, const char* atom)
{
    ERL_NIF_TERM ret;

    if(!enif_make_existing_atom(env, atom, &ret, ERL_NIF_LATIN1))
    {
        return enif_make_atom(env, atom);
    }

    return ret;
}

static
ERL_NIF_TERM
mk_error(ErlNifEnv* env, const char* mesg)
{
    return enif_make_tuple2(env, mk_atom(env, "error"), mk_atom(env, mesg));
}

static ERL_NIF_TERM
scrypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    if(argc != 6)
    {
        return enif_make_badarg(env);
    }

    return mk_atom(env, "ok");
}

static ErlNifFunc nif_funcs[] = {
    {"scrypt", 6, scrypt, ERL_NIF_DIRTY_JOB_CPU_BOUND}
};

ERL_NIF_INIT(scrypt, nif_funcs, NULL, NULL, NULL, NULL);
