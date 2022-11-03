#pragma once
#include "cryptopals_gmp.h"
#include "cryptopals_utils.h"

// User must run init_gmp(seed) before using the functions below, and must run
// cleanup_gmp() afterward.

typedef struct rsa_private_key rsa_private_key;
typedef struct rsa_public_key rsa_public_key;
typedef struct rsa_params {
    const rsa_private_key * private;
    const rsa_public_key * public;
}
rsa_params;

void free_rsa_private_key(const rsa_private_key * private);
void free_rsa_public_key(const rsa_public_key * public);

// Uses fixed public key e=3, allocates both private and public key
rsa_params rsa_keygen(unsigned long mod_bits);

byte_array rsa_encrypt(const rsa_public_key * public, const byte_array plain);
byte_array rsa_decrypt(const rsa_private_key * private, const byte_array cipher);

// Requires 3 ciphertexts of same plaintext encrypted under pairwise coprime moduli.
byte_array rsa_broadcast_attack(const rsa_public_key * public[3], const byte_array cipher[3]);
