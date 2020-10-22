#include <stdlib.h>
#include <string.h>
#include "erl_nif.h"

#include "scrypt_platform.h"
#include "crypto_scrypt.h"

static ERL_NIF_TERM mk_atom(ErlNifEnv *env, const char *atom) {
  ERL_NIF_TERM ret;

  if (!enif_make_existing_atom(env, atom, &ret, ERL_NIF_LATIN1)) {
    return enif_make_atom(env, atom);
  }

  return ret;
}

static ERL_NIF_TERM report_bad_param(ErlNifEnv *env, const char *param) {
  return enif_raise_exception(
      env, enif_make_tuple2(env, mk_atom(env, "bad_param"),
                            enif_make_string(env, param, ERL_NIF_LATIN1)));
}

static ERL_NIF_TERM report_allocation_error(ErlNifEnv *env) {
  return enif_raise_exception(env, mk_atom(env, "allocation_error"));
}

static ERL_NIF_TERM report_scrypt_error(ErlNifEnv *env) {
  return enif_raise_exception(env, mk_atom(env, "scrypt_error"));
}

static ERL_NIF_TERM scrypt(ErlNifEnv *env, int argc,
                           const ERL_NIF_TERM argv[]) {
  uint32_t N, r, p;
  size_t buf_len;
  ErlNifBinary passwd, salt, result;

  if (argc != 6) {
    return enif_make_badarg(env);
  }

  if (!enif_inspect_binary(env, argv[0], &passwd)) {
    return report_bad_param(env, "Passwd");
  }

  if (!enif_inspect_binary(env, argv[1], &salt)) {
    return report_bad_param(env, "Salt");
  }

  if (!enif_get_uint(env, argv[2], &N)) {
    return report_bad_param(env, "N");
  }

  if (!enif_get_uint(env, argv[3], &r)) {
    return report_bad_param(env, "R");
  }

  if (!enif_get_uint(env, argv[4], &p)) {
    return report_bad_param(env, "P");
  }

  if (!enif_get_ulong(env, argv[5], &buf_len)) {
    return report_bad_param(env, "Buflen");
  }

  if (!enif_alloc_binary(buf_len, &result)) {
    return report_allocation_error(env);
  }

  if (crypto_scrypt(passwd.data, passwd.size, salt.data, salt.size, N, r, p,
                    result.data, result.size)) {
    return report_scrypt_error(env);
  }

  return enif_make_binary(env, &result);
}

static ErlNifFunc nif_funcs[] = {
    {"scrypt", 6, scrypt, ERL_NIF_DIRTY_JOB_CPU_BOUND}};

ERL_NIF_INIT(erlscrypt, nif_funcs, NULL, NULL, NULL, NULL);
