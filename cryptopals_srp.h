#pragma once
#include "cryptopals_utils.h"
#include "cryptopals_gmp.h"

// User must run init_gmp(seed) before using the functions below, and must run
// cleanup_gmp() afterward.

typedef struct srp_params srp_params;

srp_params * init_srp(const char * N,
                      unsigned int g,
                      unsigned int k,
                      const char * email,
                      const char * password,
                      const byte_array * salt);
void free_srp_params(srp_params * params);

void calculate_server_v(srp_params * params);
void calculate_client_keys(srp_params * params);
void calculate_server_keys(srp_params * params);
