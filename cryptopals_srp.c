#include "cryptopals_srp.h"
#include "cryptopals_gmp_private.h"
#include "sha256.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

// In real life, this would be a hash table indexed by emails (or other usernames)
// storing (salt, v) pairs.
typedef struct srp_server_private_storage {
    byte_array * email;
    byte_array * salt;
    mpz_t v;
} srp_server_private_storage;

typedef struct srp_params {
    mpz_t N;
    mpz_t g;
    mpz_t k;
    srp_server_private_storage server;
} srp_params;

void free_srp_params(srp_params * params) {
    mpz_clear(params->N);
    mpz_clear(params->g);
    mpz_clear(params->k);
    mpz_clear(params->server.v);
    free_byte_array(params->server.email);
    free_byte_array(params->server.salt);
    free(params);
}

srp_params * init_srp(const char * N_hex,
                      unsigned int g,
                      unsigned int k) {
    srp_params * params = malloc(sizeof(srp_params));
    mpz_init_set_str(params->N, N_hex, 16);
    mpz_init_set_ui(params->g, g);
    mpz_init_set_ui(params->k, k);
    // initialize but do not set
    mpz_init(params->server.v);
    // setting to null makes free_byte_array safe if they don't get set
    params->server.email = NULL;
    params->server.salt = NULL;
    return params;
}


typedef struct srp_client_session {
    mpz_t A; // client's public key
    mpz_t B; // server's public key
    mpz_t a; // client's private key
    mpz_t S; // shared secret
} srp_client_session;

typedef struct srp_client_handshake {
    mpz_t A; // client's public key
    byte_array * email;
} srp_client_handshake;

typedef struct srp_server_session {
    mpz_t A; // client's public key
    mpz_t B; // server's public key
    mpz_t b; // server's private key
    mpz_t S; // shared secret
} srp_server_session;

typedef struct srp_server_handshake {
    mpz_t B; // server's public key
    byte_array * salt;
} srp_server_handshake;

srp_client_handshake * init_srp_client_session(srp_client_session ** client,
                                               srp_params * params,
                                               const char * email) {

    srp_client_session * my_client = malloc(sizeof(srp_client_session));
    mpz_init(my_client->a);
    mpz_init(my_client->A);
    mpz_init(my_client->B);
    mpz_init(my_client->S);

    // Generate client's random ephemeral private key. (Just for this login.)
    mpz_urandomm(my_client->a, cryptopals_gmp_randstate, params->N);

    // Give public key to server. A = (g ** a) mod N
    mpz_powm(my_client->A, params->g, my_client->a, params->N);

    srp_client_handshake * handshake = malloc(sizeof(srp_client_handshake));
    handshake->email = cstring_to_bytes(email);
    mpz_init_set(handshake->A, my_client->A);

    *client = my_client;
    return handshake;
}

void free_srp_client_session(srp_client_session * client) {
    mpz_clear(client->a);
    mpz_clear(client->A);
    mpz_clear(client->B);
    mpz_clear(client->S);
    free(client);
}

void free_srp_client_handshake(srp_client_handshake * handshake) {
    free_byte_array(handshake->email);
    mpz_clear(handshake->A);
    free(handshake);
}

// Initializes mpz_t in first argument. Be sure to call mpz_clear on it later.
static void byte_array_to_mpz_init(mpz_t out, byte_array * in) {
    byte_array * hex = byte_array_to_hex_byte_array(in);
    mpz_init_set_str(out, (const char *)hex->bytes, 16);
    free_byte_array(hex);
}

// Same as previous, but assumes mpz_t in first argument is already initialized.
static void byte_array_to_mpz(mpz_t out, byte_array * in) {
    byte_array * hex = byte_array_to_hex_byte_array(in);
    mpz_set_str(out, (const char *)hex->bytes, 16);
    free_byte_array(hex);
}

// Initializes byte array that is returned. Be sure to call free_byte_array on it later.
static byte_array * mpz_to_byte_array(mpz_t in) {
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

void test_conversion_functions(const char * hex) {
    printf("%-11s = %s\n", "input", hex);
    mpz_t in;
    mpz_init_set_str(in, hex, 16);
    gmp_printf("%-11s = %Zx\n", "as mpz", in);
    byte_array * bytes = mpz_to_byte_array(in);
    printf("%-11s = ", "as bytes");
    print_byte_array(bytes);
    mpz_t copy;
    byte_array_to_mpz_init(copy, bytes);
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
    byte_array_to_mpz_init(x, sha_out);

    // v = (g ** x) mod N, store in server params
    mpz_powm(params->server.v, params->g, x, params->N);

    // In real life, server stores each user's (salt, v) indexed by email
    // (or other username). This is all that will be needed to verify the
    // password later. To simplify the code, we will just verify that the
    // email user gives us later is the one we already know before returning
    // the salt, and otherwise stop. In practice, this would create a system
    // which could only have one user.
    params->server.salt = copy_byte_array(salt);
    params->server.email = cstring_to_bytes(email);

    // throw away x, this must be done for security
    mpz_clear(x);
    free_byte_array(sha_out);
}

srp_server_handshake * receive_client_handshake(srp_server_session ** server,
                                                srp_params * params,
                                                srp_client_handshake * handshake) {
    if (!byte_arrays_equal(handshake->email, params->server.email)) {
        fprintf(stderr, "%s: Username not found\n", __func__);
        return NULL;
    }
    srp_server_session * my_server = malloc(sizeof(srp_server_session));
    mpz_init_set(my_server->A, handshake->A);
    mpz_init(my_server->B);
    mpz_init(my_server->b);
    mpz_init(my_server->S);

    mpz_urandomm(my_server->b, cryptopals_gmp_randstate, params->N);

    // B = (kv + g ** b) mod N
    mpz_mul(my_server->B, params->k, params->server.v);
    mpz_t g_to_the_b;
    mpz_init(g_to_the_b);
    mpz_powm(g_to_the_b, params->g, my_server->b, params->N);
    mpz_add(my_server->B, my_server->B, g_to_the_b);
    mpz_mod(my_server->B, my_server->B, params->N);
    mpz_clear(g_to_the_b);

    srp_server_handshake * my_handshake = malloc(sizeof(srp_server_handshake));
    mpz_init_set(my_handshake->B, my_server->B);
    my_handshake->salt = copy_byte_array(params->server.salt);

    *server = my_server;
    return my_handshake;
}

void free_srp_server_session(srp_server_session * server) {
    mpz_clear(server->A);
    mpz_clear(server->B);
    mpz_clear(server->b);
    mpz_clear(server->S);
    free(server);
}

void free_srp_server_handshake(srp_server_handshake * handshake) {
    mpz_clear(handshake->B);
    free_byte_array(handshake->salt);
    free(handshake);
}

// u = SHA256(A|B)
static void calculate_u_init(mpz_t u, mpz_t A, mpz_t B) {
    mpz_init(u);
    byte_array * A_bytes = mpz_to_byte_array(A);
    byte_array * B_bytes = mpz_to_byte_array(B);
    byte_array * u_bytes = sha256_appended_byte_arrays(A_bytes, B_bytes);
    byte_array_to_mpz(u, u_bytes);
    free_byte_array(A_bytes);
    free_byte_array(B_bytes);
    free_byte_array(u_bytes);
}

void calculate_client_shared_secret(srp_client_session * client,
                                    srp_params * params,
                                    srp_server_handshake * handshake,
                                    const char * password) {
    mpz_set(client->B, handshake->B);

    // x = SHA256(salt|password), same as server calculated and threw out
    const byte_array password_ba = {(uint8_t *)password, strlen(password)};
    byte_array * sha_out = sha256_appended_byte_arrays(handshake->salt, &password_ba);
    mpz_t x;
    byte_array_to_mpz_init(x, sha_out);

    mpz_t u;
    calculate_u_init(u, client->A, client->B);
    
    // exponent = (a + u * x)
    mpz_t exponent;
    mpz_init_set(exponent, client->a);
    mpz_addmul(exponent, u, x);

    // base = (B - k * g**x)
    mpz_t temp;
    mpz_init(temp);
    mpz_powm(temp, params->g, x, params->N);
    mpz_t base;
    mpz_init_set(base, client->B);
    mpz_submul(base, params->k, temp);

    // S = (B - k * g**x) ** (B - k * g**x) mod N
    mpz_powm(client->S, base, exponent, params->N);

    mpz_clear(x);
    mpz_clear(u);
    mpz_clear(exponent);
    mpz_clear(temp);
    mpz_clear(base);
    free_byte_array(sha_out);
}

void calculate_server_shared_secret(srp_server_session * server,
                                    srp_params * params) {
    mpz_t u;
    calculate_u_init(u, server->A, server->B);

    // base = (A * v**u)
    mpz_t base;
    mpz_init(base);
    mpz_powm(base, params->server.v, u, params->N);
    mpz_mul(base, base, server->A);

    // S = (A * v**u) ** b mod N
    mpz_powm(server->S, base, server->b, params->N);

    mpz_clear(u);
    mpz_clear(base);
}

// This is cheating, but just for debugging purposes along the way.
void compare_shared_secrets(srp_client_session * client, srp_server_session * server) {
    //gmp_printf("client secret = %Zx\n", client->S);
    //gmp_printf("server secret = %Zx\n", server->S);
    if (mpz_cmp(client->S, server->S)) {
        printf("Secrets differ! :-(\n");
    } else {
        printf("Secrets match! :-)\n");
    }
}
