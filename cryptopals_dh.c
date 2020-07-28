#include <stdlib.h>
#include <gmp.h>
#include "cryptopals_dh.h"

#define MAX_SHARED_SECRET_LEN 500

static gmp_randstate_t state;

void init_gmp(unsigned long int seed) {
    gmp_randinit_default(state);
    gmp_randseed_ui(state, seed);
}

void cleanup_gmp() {
    gmp_randclear(state);
}

// struct sent by initiator of Diffie-Hellman connection
typedef struct dh_public_params {
    mpz_t p; // modulus
    mpz_t g; // generator
    mpz_t key; // public key
} dh_public_params;

typedef struct dh_private_params {
    mpz_t key; // private key
    char shared_secret[MAX_SHARED_SECRET_LEN+1];
    int	shared_secret_len;
} dh_private_params;

void print_keys(const char * prefix, const dh_params params) {
    gmp_printf("%s public key : %Zx\n", prefix, params.public->key);
    gmp_printf("%s private key: %Zx\n", prefix, params.private->key);
}

char * get_shared_secret(const dh_params params) {
    return params.private->shared_secret;
}

int get_shared_secret_len(const dh_params params) {
    return params.private->shared_secret_len;
}

void free_dh_params(dh_params params) {
    mpz_clear(params.public->p);
    mpz_clear(params.public->g);
    mpz_clear(params.public->key);
    mpz_clear(params.private->key);
    free(params.public);
    free(params.private);
}

// Helper function used by both initiator and responder. Allocates memory for private and public keys.
// Calculates a random private key and derives public key from it. Modulus and generator must already be set.
static inline void calculate_private_and_public_keys(dh_params params) {
    mpz_init(params.private->key);
    mpz_urandomm(params.private->key, state, params.public->p);

    mpz_init(params.public->key);
    mpz_powm(params.public->key, params.public->g, params.private->key, params.public->p);
}

dh_params prehandshake(const char * p_hex_str, unsigned int g) {
    dh_params params;
    params.public = malloc(sizeof(dh_public_params));
    params.private = malloc(sizeof(dh_private_params));
    mpz_init_set_str(params.public->p, p_hex_str, 16);
    mpz_init_set_ui(params.public->g, g);

    calculate_private_and_public_keys(params);

    return params;
}

dh_params prehandshake_g_hex_str(const char * p_hex_str, const char * g_hex_str) {
    dh_params params;
    params.public = malloc(sizeof(dh_public_params));
    params.private = malloc(sizeof(dh_private_params));
    mpz_init_set_str(params.public->p, p_hex_str, 16);
    mpz_init_set_str(params.public->g, g_hex_str, 16);

    calculate_private_and_public_keys(params);

    return params;
}

dh_public_params * hacked_params(const char * p_hex_str, unsigned int g) {
    dh_public_params * public = malloc(sizeof(dh_public_params));
    mpz_init_set_str(public->p, p_hex_str, 16);
    mpz_init_set(public->key, public->p);
    mpz_init_set_ui(public->g, g);
    return public;
}

void free_hacked_params(dh_public_params * public) {
    mpz_clear(public->key);
    mpz_clear(public->p);
    mpz_clear(public->g);
    free(public);
}

// shared secret written as hex string to aid in deriving key
static void calculate_shared_secret(dh_params params, const mpz_t * other_side_public_key) {
    mpz_t secret;
    mpz_init(secret);
    mpz_powm(secret, *other_side_public_key, params.private->key, params.public->p);
    params.private->shared_secret_len = gmp_sprintf(params.private->shared_secret, "%Zx", secret);
    mpz_clear(secret);
    if (params.private->shared_secret_len > MAX_SHARED_SECRET_LEN) abort();
}

dh_params handshake1(const dh_public_params * initiator_public) {
    dh_params params;
    params.public = malloc(sizeof(dh_public_params));
    params.private = malloc(sizeof(dh_private_params));

    // copy parameters from initiator side
    mpz_init_set(params.public->p, initiator_public->p);
    mpz_init_set(params.public->g, initiator_public->g);

    calculate_private_and_public_keys(params);
    calculate_shared_secret(params, &initiator_public->key);
    return params;
}

void handshake2(dh_params params, const dh_public_params * responder_public) {
    calculate_shared_secret(params, &responder_public->key);
}
