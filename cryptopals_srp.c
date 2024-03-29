#include "cryptopals_srp.h"
#include "cryptopals_gmp_private.h"
#include "cryptopals_hash.h"
#include "cryptopals_hmac.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// In real life, this would be a hash table indexed by emails (or other usernames)
// storing (salt, v) pairs.
typedef struct srp_server_private_storage {
    byte_array email;
    byte_array salt; // Server will hand this to client before verifying password.
    mpz_t v; // (g ** SHA256(salt|password)) mod N, i.e., the password hash
} srp_server_private_storage;

typedef struct srp_params {
    mpz_t N; // modulus, a NIST prime
    mpz_t g; // generator
    mpz_t k; // another public parameter, usually k=3
    srp_server_private_storage server;
} srp_params;

void free_srp_params(srp_params * params) {
    mpz_clears(params->N, params->g, params->k, params->server.v, (mpz_ptr)NULL);
    free_byte_arrays(params->server.email, params->server.salt, NO_BA);
    free(params);
}

srp_params * init_srp(const char * N_hex,
                      unsigned int g,
                      unsigned int k) {
    srp_params * params = malloc(sizeof(srp_params));
    mpz_init_set_str(params->N, N_hex, 16);
    mpz_init_set_ui(params->g, g);
    mpz_init_set_ui(params->k, k);
    // Initialize but do not set.
    mpz_init(params->server.v);
    // Setting to NO_BA makes free_byte_array safe if they don't get set.
    params->server.email = NO_BA;
    params->server.salt = NO_BA;
    return params;
}

void register_user_server(srp_params * params,
                          const char * email,
                          const char * password,
                          const byte_array salt) {
    const byte_array password_ba = {(uint8_t *)password, strlen(password)};
    // x = SHA256(salt|password)
    byte_array sha_out = sha256_cat(salt, password_ba);
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

    // Throw away x. This must be done for security.
    mpz_clear(x);
    free_byte_array(sha_out);
}

typedef struct srp_client_session {
    mpz_t A; // client's public key
    mpz_t a; // client's private key
} srp_client_session;

typedef struct srp_server_session {
    mpz_t A; // client's public key
    mpz_t B; // server's public key
    mpz_t b; // server's private key
} srp_server_session;

typedef struct srp_client_handshake {
    mpz_t A; // client's public key
    byte_array email;
} srp_client_handshake;

typedef struct srp_server_handshake {
    mpz_t B; // server's public key
    byte_array salt;
} srp_server_handshake;

srp_client_handshake * construct_client_handshake(srp_client_session ** client,
                                                  const srp_params * params,
                                                  const char * email) {

    srp_client_session * my_client = malloc(sizeof(srp_client_session));
    mpz_init(my_client->a);
    mpz_init(my_client->A);

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

srp_client_handshake * forge_client_handshake(const char * A_hex,
                                              unsigned int multiplier,
                                              const char * email) {
    srp_client_handshake * handshake = malloc(sizeof(srp_client_handshake));
    mpz_init_set_str(handshake->A, A_hex, 16);
    mpz_mul_ui(handshake->A, handshake->A, multiplier);
    handshake->email = cstring_to_bytes(email);
    return handshake;
}

void free_srp_client_session(srp_client_session * client) {
    mpz_clears(client->a, client->A, (mpz_ptr)NULL);
    free(client);
}

void free_srp_client_handshake(srp_client_handshake * handshake) {
    free_byte_array(handshake->email);
    mpz_clear(handshake->A);
    free(handshake);
}

srp_server_handshake * receive_client_handshake(srp_server_session ** server,
                                                const srp_params * params,
                                                const srp_client_handshake * handshake) {
    if (!byte_arrays_equal(handshake->email, params->server.email)) {
        fprintf(stderr, "%s: Username not found\n", __func__);
        return NULL;
    }
    srp_server_session * my_server = malloc(sizeof(srp_server_session));
    mpz_init_set(my_server->A, handshake->A);
    mpz_inits(my_server->B, my_server->b, (mpz_ptr)NULL);

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

srp_server_handshake * forge_server_handshake(unsigned int B,
                                              const byte_array salt) {
    srp_server_handshake * handshake = malloc(sizeof(srp_server_handshake));
    mpz_init_set_ui(handshake->B, B);
    handshake->salt = copy_byte_array(salt);
    return handshake;
}

void free_srp_server_session(srp_server_session * server) {
    mpz_clears(server->A, server->B, server->b, (mpz_ptr)NULL);
    free(server);
}

void free_srp_server_handshake(srp_server_handshake * handshake) {
    mpz_clear(handshake->B);
    free_byte_array(handshake->salt);
    free(handshake);
}

const byte_array get_salt_const_p(const srp_server_handshake * handshake) {
    return (const byte_array)handshake->salt;
}

// u = SHA256(A|B)
static void calculate_u_init(mpz_t u, const mpz_t A, const mpz_t B) {
    mpz_init(u);
    byte_array A_bytes = mpz_to_byte_array(A);
    byte_array B_bytes = mpz_to_byte_array(B);
    byte_array u_bytes = sha256_cat(A_bytes, B_bytes);
    byte_array_to_mpz(u, u_bytes);
    free_byte_arrays(A_bytes, B_bytes, u_bytes, NO_BA);
}

// HMAC-SHA256(SHA256(S), salt)
static byte_array hmac_secret(const mpz_t secret, const byte_array salt) {
    byte_array secret_ba = mpz_to_byte_array(secret);
    byte_array K = sha256(secret_ba);
    byte_array hmac = hmac_sha256(K, salt);
    free_byte_arrays(secret_ba, K, NO_BA);
    return hmac;
}

byte_array forge_hmac(const char * secret_hex, const byte_array salt) {
    mpz_t S;
    mpz_init_set_str(S, secret_hex, 16);
    byte_array hmac = hmac_secret(S, salt);
    mpz_clear(S);
    return hmac;
}

byte_array calculate_client_hmac(srp_client_session * client,
                                 const srp_params * params,
                                 const srp_server_handshake * handshake,
                                 const char * password) {
    // x = SHA256(salt|password), same as server calculated and threw out
    const byte_array password_ba = {(uint8_t *)password, strlen(password)};
    byte_array sha_out = sha256_cat(handshake->salt, password_ba);
    mpz_t x;
    byte_array_to_mpz_init(x, sha_out);

    mpz_t u;
    calculate_u_init(u, client->A, handshake->B);
    
    // exponent = (a + u * x)
    mpz_t exponent;
    mpz_init_set(exponent, client->a);
    mpz_addmul(exponent, u, x);

    // base = (B - k * g**x)
    mpz_t temp;
    mpz_init(temp);
    mpz_powm(temp, params->g, x, params->N);
    mpz_t base;
    mpz_init_set(base, handshake->B);
    mpz_submul(base, params->k, temp);

    // Cryptographic shared secret generated by both client and server
    mpz_t S;
    mpz_init(S);

    // S = (B - k * g**x) ** (a + u * x) mod N
    mpz_powm(S, base, exponent, params->N);

    mpz_clears(x, u, exponent, temp, base, (mpz_ptr)NULL);
    free_byte_array(sha_out);

    byte_array hmac = hmac_secret(S, handshake->salt);
    mpz_clear(S);
    return hmac;
}

bool hack_client_hmac(const srp_params * params,
                      const srp_client_handshake * handshake, // for A
                      const byte_array client_hmac,
                      const char * password_guess) {
    // x = SHA256(password)
    const byte_array password_ba = {(uint8_t *)password_guess, strlen(password_guess)};
    byte_array sha_pw = sha256(password_ba);

    mpz_t x;
    byte_array_to_mpz_init(x, sha_pw);

    // Using B = g
    mpz_t u;
    calculate_u_init(u, handshake->A, params->g);

    // v = g ** SHA256(password) mod N
    mpz_t v;
    mpz_init(v);
    mpz_powm(v, params->g, x, params->N);

    // S = (A * v**u) mod N
    mpz_t S;
    mpz_init(S);
    mpz_powm(S, v, u, params->N);
    mpz_mul(S, S, handshake->A);
    mpz_mod(S, S, params->N);

    const byte_array empty = {"", 0};
    byte_array hmac_guess = hmac_secret(S, empty);
    bool ret = byte_arrays_equal(client_hmac, hmac_guess);

    mpz_clears(x, u, v, S, (mpz_ptr)NULL);
    free_byte_arrays(hmac_guess, sha_pw, NO_BA);

    return ret;
}

static void calculate_server_shared_secret_init(mpz_t S,
                                                const srp_server_session * server,
                                                const srp_params * params) {
    mpz_t u;
    calculate_u_init(u, server->A, server->B);

    // base = (A * v**u)
    mpz_t base;
    mpz_init(base);
    mpz_powm(base, params->server.v, u, params->N);
    mpz_mul(base, base, server->A);

    // S = (A * v**u) ** b mod N
    mpz_init(S);
    mpz_powm(S, base, server->b, params->N);

    mpz_clears(u, base, (mpz_ptr)NULL);
}

bool validate_client_hmac(const srp_server_session * server,
                          const srp_params * params,
                          const byte_array client_hmac) {
    // Cryptographic shared secret generated by both client and server
    mpz_t S;

    calculate_server_shared_secret_init(S, server, params);

    byte_array server_hmac = hmac_secret(S, params->server.salt);
    bool ret = byte_arrays_equal(client_hmac, server_hmac);
    free_byte_array(server_hmac);
    mpz_clear(S);
    return ret;
}
