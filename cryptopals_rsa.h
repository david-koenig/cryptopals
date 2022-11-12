#pragma once
#include "cryptopals_gmp.h"
#include "cryptopals_utils.h"

// User must run init_gmp(seed) before using the functions below, and must run
// cleanup_gmp() afterward.

typedef struct rsa_private_key rsa_private_key;
typedef struct rsa_public_key rsa_public_key;
typedef struct rsa_key_pair {
    const rsa_private_key * private;
    const rsa_public_key * public;
}
rsa_key_pair;

void free_rsa_private_key(const rsa_private_key * private);
void free_rsa_public_key(const rsa_public_key * public);

// Uses fixed public key e=3, allocates both private and public key.
rsa_key_pair rsa_keygen(unsigned long bits);

byte_array rsa_encrypt(const rsa_public_key * public, const byte_array plain);
byte_array rsa_decrypt(const rsa_private_key * private, const byte_array cipher);

byte_array rsa_md4_sign_msg(const rsa_private_key * private, const byte_array msg);

// Flawed implementation of signature verification, susceptible to Bleichenbacher's e=3 attack
bool rsa_md4_verify_sig(const rsa_public_key * public, const byte_array msg, const byte_array sig);

// Requires 3 ciphertexts of same plaintext encrypted under pairwise coprime moduli.
byte_array rsa_broadcast_attack(const rsa_public_key * public[3], const byte_array cipher[3]);

// Decrypts message even if decrypter had safeguard to not decrypt same message more than once.
byte_array rsa_unpadded_message_recovery_oracle(rsa_key_pair kp, const byte_array cipher);

// Create a fake signature without the private key using Bleichenbacher's e=3 attack
byte_array hack_sig(const rsa_public_key * public, const byte_array msg);

bool rsa_parity_oracle_attack(bool hollywood);

bool rsa_padding_oracle_test();
bool rsa_padding_oracle_attack(unsigned long bits, const char * msg);
