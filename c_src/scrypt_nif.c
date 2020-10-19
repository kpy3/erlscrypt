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
  size_t passwdlen, saltlen, buflen;
  uint32_t N, r, p;
  uint8_t *passwd, *salt, *buf;
  ErlNifBinary passwd_bin, salt_bin, result;

  if (argc != 6) {
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

  if (!enif_get_ulong(env, argv[5], &buflen)) {
    return enif_make_badarg(env);
  }

  if (enif_inspect_binary(env, argv[0], &passwd_bin)) {
    passwd = (uint8_t *)malloc(passwd_bin.size);
    passwdlen = passwd_bin.size;
    memcpy(passwd, passwd_bin.data, passwd_bin.size);
  } else {
    return enif_make_badarg(env);
  }

  if (enif_inspect_binary(env, argv[1], &salt_bin)) {
    salt = (uint8_t *)malloc(salt_bin.size);
    saltlen = salt_bin.size;
    memcpy(salt, salt_bin.data, salt_bin.size);
  } else {
    free(passwd);
    return enif_make_badarg(env);
  }

  buf = calloc(1, buflen);
  if (buf == NULL) {
    free(passwd);
    free(salt);
    return enif_make_badarg(env);
  }

  if (crypto_scrypt(passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen)) {
    free(passwd);
    free(salt);
    free(buf);
    return enif_make_badarg(env);
  }

  free(passwd);
  free(salt);

  if (!enif_alloc_binary(buflen, &result)) {
    free(buf);
    return enif_make_badarg(env);
  }

  memcpy(result.data, buf, buflen);
  free(buf);
  return enif_make_binary(env, &result);
}

static ErlNifFunc nif_funcs[] = {
    {"scrypt", 6, scrypt, ERL_NIF_DIRTY_JOB_CPU_BOUND}};

ERL_NIF_INIT(scrypt, nif_funcs, NULL, NULL, NULL, NULL);
