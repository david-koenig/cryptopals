#pragma once
#include "cryptopals_utils.h"
#include "cryptopals_gmp.h"

// User must run init_gmp(seed) before using the functions below, and must run
// cleanup_gmp() afterward.

typedef struct srp_params srp_params;
typedef struct srp_client_session srp_client_session;
typedef struct srp_client_handshake srp_client_handshake;
typedef struct srp_server_session srp_server_session;
typedef struct srp_server_handshake srp_server_handshake;

void free_srp_params(srp_params * params);
void free_srp_client_session(srp_client_session * client);
void free_srp_client_handshake(srp_client_handshake * handshake);
void free_srp_server_session(srp_server_session * server);
void free_srp_server_handshake(srp_server_handshake * handshake);

srp_params * init_srp(const char * N, unsigned int g, unsigned int k);

void register_user_server(srp_params * params,
                          const char * email,
                          const char * password,
                          const byte_array * salt);

srp_client_handshake * init_srp_client_session(srp_client_session ** client,
                                               srp_params * params,
                                               const char * email);

srp_server_handshake * receive_client_handshake(srp_server_session ** server,
                                                srp_params * params,
                                                srp_client_handshake * handshake);

void calculate_client_shared_secret(srp_client_session * client,
                                    srp_params * params,
                                    srp_server_handshake * handshake,
                                    const char * password);

void calculate_server_shared_secret(srp_server_session * server,
                                    srp_params * params);

byte_array * hmac_client_secret(srp_client_session * client, byte_array * salt);

bool validate_client_hmac(srp_server_session * server, srp_params * params, const byte_array * client_hmac);
