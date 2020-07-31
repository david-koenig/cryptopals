#include "cryptopals_srp.h"
#include "cryptopals_gmp_private.h"
#include "cryptopals_sha256.h"
#include "cryptopals_hmac.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// In real life, this would be a hash table indexed by emails (or other usernames)
// storing (salt, v) pairs.
typedef struct srp_server_private_storage {
    byte_array * email;
    byte_array * salt; // Server will hand this to client before verifying password.
    mpz_t v; // (g ** SHA256(salt|password)) mod N, i.e., the password hash
} srp_server_private_storage;

typedef struct srp_params {
    mpz_t N; // modulus, a NIST prime
    mpz_t g; // generator
    mpz_t k; // another public parameter, usually k=3
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
    // Initialize but do not set.
    mpz_init(params->server.v);
    // Setting to null makes free_byte_array safe if they don't get set.
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

void register_user_server(srp_params * params,
                          const char * email,
                          const char * password,
                          const byte_array * salt) {
    const byte_array password_ba = {(uint8_t *)password, strlen(password)};
    // x = SHA256(salt|password)
    byte_array * sha_out = sha256_2_byte_arrays(salt, &password_ba);
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
    byte_array * u_bytes = sha256_2_byte_arrays(A_bytes, B_bytes);
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
    byte_array * sha_out = sha256_2_byte_arrays(handshake->salt, &password_ba);
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

// HMAC-SHA256(SHA256(S), salt)
static byte_array * hmac_secret(const mpz_t secret, const byte_array * salt) {
    byte_array * secret_ba = mpz_to_byte_array(secret);
    byte_array * K = sha256_byte_array(secret_ba);
    byte_array * hmac = hmac_sha256(K, salt);
    free_byte_array(secret_ba);
    free_byte_array(K);
    return hmac;
}

byte_array * hmac_client_secret(srp_client_session * client, byte_array * salt) {
    return hmac_secret(client->S, salt);
}

bool validate_client_hmac(srp_server_session * server, srp_params * params, const byte_array * client_hmac) {
    byte_array * server_hmac = hmac_secret(server->S, params->server.salt);
    bool ret = byte_arrays_equal(client_hmac, server_hmac);
    free_byte_array(server_hmac);
    return ret;
}
