#pragma once
#include "cryptopals_utils.h"
#include "cryptopals_gmp.h"

// User must run init_gmp(seed) before using the functions below, and must run
// cleanup_gmp() afterward.

typedef struct srp_params srp_params;
void free_srp_params(srp_params * params);

srp_params * init_srp(const char * N,
                      unsigned int g,
                      unsigned int k);

void register_user_server(srp_params * params,
                          const char * email,
                          const char * password,
                          const byte_array * salt);

void calculate_client_keys(srp_params * params);
void calculate_server_keys(srp_params * params);
void calculate_u(srp_params * params);

void calculate_client_shared_secret(srp_params * params,
                                    const char * password,
                                    const byte_array * salt);
void calculate_server_shared_secret(srp_params * params);

void compare_shared_secrets(srp_params * params);
