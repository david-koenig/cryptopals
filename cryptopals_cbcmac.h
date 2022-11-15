#pragma once
#include "cryptopals_utils.h"

typedef struct request {
    long from;
    long to;
    long amount;
} request;

void init_serverclient(unsigned int seed);
void cleanup_serverclient();

// msg has format "from=#{from_id}&to=#{to_id}&amount=#{amount}"
// returns request in form message || IV || MAC
// as long as from and to are user controlled accounts
byte_array sign_request_iv(request req);

bool verify_request_iv(const byte_array signed_msg);
