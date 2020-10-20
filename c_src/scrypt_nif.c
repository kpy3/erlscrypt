#include "scrypt_platform.h"
#include <stdlib.h>
#include <string.h>

#include "crypto_scrypt.h"
#include "erl_nif.h"

static ERL_NIF_TERM mk_atom(ErlNifEnv *env, const char *atom) {
  ERL_NIF_TERM ret;

  if (!enif_make_existing_atom(env, atom, &ret, ERL_NIF_LATIN1)) {
    return enif_make_atom(env, atom);
  }

  return ret;
}

static ERL_NIF_TERM mk_error(ErlNifEnv *env, const char *mesg) {
  return enif_make_tuple2(env, mk_atom(env, "error"), mk_atom(env, mesg));
}

static ERL_NIF_TERM scrypt(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  uint32_t N, r, p;
  size_t buf_len;
  ErlNifBinary passwd, salt, result;

  if (argc != 6) {
    return enif_make_badarg(env);
  }

  if (!enif_inspect_binary(env, argv[0], &passwd)) {
    return enif_make_badarg(env);
  }

  if (!enif_inspect_binary(env, argv[1], &salt)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_uint(env, argv[2], &N)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_uint(env, argv[3], &r)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_uint(env, argv[4], &p)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_ulong(env, argv[5], &buf_len)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(buf_len, &result)) {
    return enif_make_badarg(env);
  }

  if (crypto_scrypt(passwd.data, passwd.size, salt.data, salt.size, N, r, p, result.data, result.size)) {
    return enif_make_badarg(env);
  }

  return enif_make_binary(env, &result);
}

static ErlNifFunc nif_funcs[] = {
    {"scrypt", 6, scrypt, ERL_NIF_DIRTY_JOB_CPU_BOUND}};

ERL_NIF_INIT(scrypt, nif_funcs, NULL, NULL, NULL, NULL);
