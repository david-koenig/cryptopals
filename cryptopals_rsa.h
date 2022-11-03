#pragma once
#include "cryptopals_gmp.h"
#include "cryptopals_utils.h"

// User must run init_gmp(seed) before using the functions below, and must run
// cleanup_gmp() afterward.

// Includes private key. In real life, people decrypting or attacking would
// only have access to the public key.
typedef struct rsa_params rsa_params;

void free_rsa_params(rsa_params * params);

// Uses fixed encryption key of e=3 and generates modulus of fixed bit length.
rsa_params * rsa_keygen();

byte_array * rsa_encrypt(const rsa_params * params, const byte_array * plain);
byte_array * rsa_decrypt(const rsa_params * params, const byte_array * cipher);

// Requires 3 ciphertexts of same plaintext encrypted under pairwise coprime moduli.
byte_array * rsa_broadcast_attack(rsa_params * params[3], byte_array * cipher[3]);
