#include "cryptopals_srp.h"
#include "cryptopals_gmp_private.h"
#include "sha256.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

typedef struct srp_server_private_params {
    mpz_t v;
    mpz_t b; // private key
    mpz_t S; // shared secret
    byte_array * K; // SHA256(S)
} srp_server_private_params;

typedef	struct srp_client_private_params {
    mpz_t a; // private key
    mpz_t S; // shared secret
    byte_array * K; // SHA256(S)
} srp_client_private_params;

typedef struct srp_params {
    mpz_t N; // NIST Prime to be used as modulus
    mpz_t g;
    mpz_t k;
    mpz_t A; // client's public key
    mpz_t B; // server's public key
    mpz_t u; // SHA256(A|B)
    byte_array * email;
    byte_array * salt;
    srp_server_private_params server;
    srp_client_private_params client;
} srp_params;

srp_params * init_srp(const char * N_hex,
                      unsigned int g,
                      unsigned int k) {
    srp_params * params = malloc(sizeof(srp_params));
    mpz_init_set_str(params->N, N_hex, 16);
    mpz_init_set_ui(params->g, g);
    mpz_init_set_ui(params->k, k);
    // setting to null makes free_byte_array safe if they don't get set
    params->email = NULL;
    params->salt = NULL;
    params->server.K = NULL;
    params->client.K = NULL;
    // initialize but do not set
    mpz_init(params->server.v);
    mpz_init(params->server.b);
    mpz_init(params->client.a);
    mpz_init(params->A);
    mpz_init(params->B);
    mpz_init(params->u);
    mpz_init(params->server.S);
    mpz_init(params->client.S);
    return params;
}

void free_srp_params(srp_params * params) {
    free_byte_array(params->email);
    free_byte_array(params->salt);
    free_byte_array(params->server.K);
    free_byte_array(params->client.K);
    mpz_clear(params->N);
    mpz_clear(params->g);
    mpz_clear(params->k);
    mpz_clear(params->server.v);
    mpz_clear(params->server.b);
    mpz_clear(params->client.a);
    mpz_clear(params->A);
    mpz_clear(params->B);
    mpz_clear(params->u);
    mpz_clear(params->server.S);
    mpz_clear(params->client.S);
    free(params);
}

// Initializes mpz_t in first argument. Be sure to call mpz_clear on it later.
static void convert_byte_array_to_mpz_init(mpz_t out, byte_array * in) {
    byte_array * hex_bytes = print_byte_array_hex_to_new_byte_array(in);
    mpz_init_set_str(out, (const char *)hex_bytes->bytes, 16);
    free_byte_array(hex_bytes);
}

// Same as previous, but assumes mpz_t in first argument is already initialized.
static void convert_byte_array_to_mpz(mpz_t out, byte_array * in) {
    byte_array * hex_bytes = print_byte_array_hex_to_new_byte_array(in);
    mpz_set_str(out, (const char *)hex_bytes->bytes, 16);
    free_byte_array(hex_bytes);
}

// Initializes byte array that is returned. Be sure to call free_byte_array on it later.
static byte_array * convert_mpz_to_byte_array(mpz_t in) {
    // Normally need 2 more than mpz_sizeinbase, for possible negative sign
    // and null byte. We're only dealing with positive integers, so probably
    // could just use 1 more, but just playing it safe.
    size_t size_needed = 2 + mpz_sizeinbase(in, 16);
    byte_array * hex = alloc_byte_array(size_needed);
    size_t len = gmp_snprintf((char *)hex->bytes, size_needed, "%Zx", in);
    if (len >= size_needed) {
        fprintf(stderr, "%s: mpz_sizeinbase incorrectly determined size of mpz\n", __func__);
        exit(1);
    }
    // mpz_sizeinbase does not include negative sign in its count, but gmp_snprintf does
    hex->len = len + 1;
    byte_array * out = hex_to_bytes((const char *)hex->bytes);
    free_byte_array(hex);
    return out;
}

void test_convert_functions(const char * hex) {
    printf("%-11s = %s\n", "input", hex);
    mpz_t in;
    mpz_init_set_str(in, hex, 16);
    gmp_printf("%-11s = %Zx\n", "as mpz", in);
    byte_array * bytes = convert_mpz_to_byte_array(in);
    printf("%-11s = ", "as bytes");
    print_byte_array(bytes);
    mpz_t copy;
    convert_byte_array_to_mpz_init(copy, bytes);
    gmp_printf("%-11s = %Zx\n", "back to mpz", copy);
    assert(!mpz_cmp(in, copy));
    printf("tests passed!\n");
    mpz_clear(in);
    mpz_clear(copy);
    free_byte_array(bytes);
}

// SHA256(a|b)
static byte_array * sha256_appended_byte_arrays(const byte_array * a, const byte_array * b) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, a->bytes, a->len);
    sha256_update(&ctx, b->bytes, b->len);
    byte_array * sha_out = alloc_byte_array(SHA256_BLOCK_SIZE);
    sha256_final(&ctx, sha_out->bytes);
    return sha_out;
}

void register_user_server(srp_params * params,
                          const char * email,
                          const char * password,
                          const byte_array * salt) {
    const byte_array password_ba = {(uint8_t *)password, strlen(password)};
    // x = SHA256(salt|password)
    byte_array * sha_out = sha256_appended_byte_arrays(salt, &password_ba);
    mpz_t x;
    convert_byte_array_to_mpz_init(x, sha_out);

    // v = (g ** x) mod N, store in server params
    mpz_powm(params->server.v, params->g, x, params->N);

    // In real life, server stores each user's (salt, v) indexed by email
    // (or other username). This is all that will be needed to verify the
    // password later. To simplify the code, we will just verify that the
    // email user gives us later is the one we already know before returning
    // the salt, and otherwise stop. In practice, this would create a system
    // which could only have one user.
    params->salt = copy_byte_array(salt);
    params->email = cstring_to_bytes(email);

    // throw away x, this must be done for security
    mpz_clear(x);
    free_byte_array(sha_out);
}

void calculate_client_keys(srp_params * params) {
    mpz_urandomm(params->client.a, cryptopals_gmp_randstate, params->N);

    // A = (g ** a) mod N
    mpz_powm(params->A, params->g, params->client.a, params->N);
}

void calculate_server_keys(srp_params * params) {
    mpz_urandomm(params->server.b, cryptopals_gmp_randstate, params->N);

    // B = (kv + g ** b) mod N
    mpz_mul(params->B, params->k, params->server.v);
    mpz_t g_to_the_b;
    mpz_init(g_to_the_b);
    mpz_powm(g_to_the_b, params->g, params->server.b, params->N);
    mpz_add(params->B, params->B, g_to_the_b);
    mpz_mod(params->B, params->B, params->N);
    mpz_clear(g_to_the_b);
}

void calculate_u(srp_params * params) {
    // u = SHA256(A|B). Both server and client calculate this individually,
    // based on both public keys. Since it's only based on public information
    // it is trivial that they will arrive at same value. Since I'm not implementing
    // the networking aspect of this, but only the cryptography, I'm only bothering
    // to calculate it once.
    byte_array * A_bytes = convert_mpz_to_byte_array(params->A);
    byte_array * B_bytes = convert_mpz_to_byte_array(params->B);
    byte_array * u_bytes = sha256_appended_byte_arrays(A_bytes, B_bytes);
    convert_byte_array_to_mpz(params->u, u_bytes);
    free_byte_array(A_bytes);
    free_byte_array(B_bytes);
    free_byte_array(u_bytes);
}

void calculate_client_shared_secret(srp_params * params,
                                    const char * password,
                                    const byte_array * salt) {
    // x = SHA256(salt|password), same as server calculated and threw out
    const byte_array password_ba = {(uint8_t *)password, strlen(password)};
    byte_array * sha_out = sha256_appended_byte_arrays(salt, &password_ba);
    mpz_t x;
    convert_byte_array_to_mpz_init(x, sha_out);

    // exponent = (a + u * x)
    mpz_t exponent;
    mpz_init_set(exponent, params->client.a);
    mpz_addmul(exponent, params->u, x);

    // base = (B - k * g**x)
    mpz_t temp;
    mpz_init(temp);
    mpz_powm(temp, params->g, x, params->N);
    mpz_t base;
    mpz_init_set(base, params->B);
    mpz_submul(base, params->k, temp);

    // S = (B - k * g**x) ** (B - k * g**x) mod N
    mpz_powm(params->client.S, base, exponent, params->N);

    mpz_clear(x);
    mpz_clear(exponent);
    mpz_clear(temp);
    mpz_clear(base);
    free_byte_array(sha_out);
}

void calculate_server_shared_secret(srp_params * params) {
    // base = (A * v**u)
    mpz_t base;
    mpz_init(base);
    mpz_powm(base, params->server.v, params->u, params->N);
    mpz_mul(base, base, params->A);

    // S = (A * v**u) ** b mod N
    mpz_powm(params->server.S, base, params->server.b, params->N);

    mpz_clear(base);
}

// This is cheating, but just for debugging purposes along the way.
void compare_shared_secrets(srp_params * params) {
    //gmp_printf("server secret = %Zx\n", params->server.S);
    //gmp_printf("client secret = %Zx\n", params->client.S);
    if (mpz_cmp(params->server.S, params->client.S)) {
        printf("Secrets differ! :-(\n");
    } else {
        printf("Secrets match! :-)\n");
    }
}
