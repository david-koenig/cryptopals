#pragma once
#include "cryptopals_gmp.h"
#include "cryptopals_utils.h"

// User must run init_gmp(seed) before using the functions below, and must run
// cleanup_gmp() afterward.

typedef struct dsa_params dsa_params;
typedef struct dsa_private_key dsa_private_key;
typedef struct dsa_public_key dsa_public_key;
typedef struct dsa_key_pair {
    const dsa_private_key * private;
    const dsa_public_key * public;
} dsa_key_pair;
typedef struct dsa_sig dsa_sig;

void free_dsa_params(const dsa_params *);
void free_dsa_private_key(const dsa_private_key *);
void free_dsa_public_key(const dsa_public_key *);
void free_dsa_sig(const dsa_sig *);

const dsa_params * dsa_paramgen();
dsa_key_pair dsa_keygen(const dsa_params *);
const dsa_sig * dsa_sign(const dsa_params *, const dsa_private_key *, const byte_array);
bool dsa_verify(const dsa_params *, const dsa_public_key *, const byte_array, const dsa_sig *);

bool challenge_43();
bool challenge_44();
