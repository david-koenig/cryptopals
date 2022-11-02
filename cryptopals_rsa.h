#pragma once
#include "cryptopals_gmp.h"
#include "cryptopals_utils.h"

// User must run init_gmp(seed) before using the functions below, and must run
// cleanup_gmp() afterward.

typedef struct rsa_params rsa_params;

void free_rsa_params(rsa_params * params);
rsa_params * rsa_keygen();
byte_array * rsa_encrypt(const rsa_params * params, const byte_array * plain);
byte_array * rsa_decrypt(const rsa_params * params, const byte_array * cipher);
