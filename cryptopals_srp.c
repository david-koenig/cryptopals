#include "cryptopals_srp.h"
#include "cryptopals_gmp_private.h"
#include "sha256.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_STRING_LEN 100

typedef struct srp_server_private_params {
    mpz_t v;
    mpz_t b; // private key
} srp_server_private_params;

typedef	struct srp_client_private_params {
    mpz_t a; //private key
} srp_client_private_params;


typedef struct srp_params {
    mpz_t N; // NIST Prime to be used as modulus
    mpz_t g;
    mpz_t k;
    mpz_t A; // client's public key
    mpz_t B; // server's public key
    byte_array * email;
    byte_array * password;
    byte_array * salt;
    srp_server_private_params server;
    srp_client_private_params client;
} srp_params;

srp_params * init_srp(const char * N_hex, unsigned int g, unsigned int k, const char * email, const char * password, const byte_array * salt) {
    srp_params * params = malloc(sizeof(srp_params));
    params->email = cstring_to_bytes(email);
    params->password = cstring_to_bytes(password);
    params->salt = copy_byte_array(salt);
    mpz_init_set_str(params->N, N_hex, 16);
    mpz_init_set_ui(params->g, g);
    mpz_init_set_ui(params->k, k);
    // initialize but do not set
    mpz_init(params->server.v);
    mpz_init(params->server.b);
    mpz_init(params->client.a);
    mpz_init(params->A);
    mpz_init(params->B);
    return params;
}

void free_srp_params(srp_params * params) {
    free_byte_array(params->email);
    free_byte_array(params->password);
    free_byte_array(params->salt);
    mpz_clear(params->N);
    mpz_clear(params->g);
    mpz_clear(params->k);
    mpz_clear(params->server.v);
    mpz_clear(params->server.b);
    mpz_clear(params->client.a);
    mpz_clear(params->A);
    mpz_clear(params->B);
    free(params);
}


void calculate_server_v(srp_params * params) {
    // x = SHA256(salt|password)
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, params->salt->bytes, params->salt->len);
    sha256_update(&ctx, params->password->bytes, params->password->len);
    byte_array * sha_out = alloc_byte_array(SHA256_BLOCK_SIZE);
    sha256_final(&ctx, sha_out->bytes);

    // convert x to mpz_t
    byte_array * sha_out_hex = print_byte_array_hex_to_new_byte_array(sha_out);
    mpz_t x;
    mpz_init_set_str(x, (const char *)sha_out_hex->bytes, 16);

    // v = (g ** x) (mod N), store in server params
    mpz_powm(params->server.v, params->g, x, params->N);

    // throw away x
    mpz_clear(x);
    free_byte_array(sha_out);
    free_byte_array(sha_out_hex);
}

void calculate_client_keys(srp_params * params) {
    mpz_urandomm(params->client.a, cryptopals_gmp_randstate, params->N);
    mpz_powm(params->A, params->g, params->client.a, params->N);
}

void calculate_server_keys(srp_params * params) {
    mpz_urandomm(params->server.b, cryptopals_gmp_randstate, params->N);
    // B = (kv + g ** b) mod N
    mpz_mul(params->B, params->k, params->server.v);
    mpz_t temp;
    mpz_init(temp);
    mpz_powm(temp, params->g, params->server.b, params->N);
    mpz_add(params->B, params->B, temp);
    mpz_mod(params->B, params->B, params->N);
    mpz_clear(temp);
}
