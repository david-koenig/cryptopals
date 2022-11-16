#pragma once
#include "cryptopals_utils.h"
#include <stdarg.h>

typedef struct request_v1 {
    long from;
    long to;
    long amount;
} request_v1;

typedef struct transaction {
    long to;
    long amount;
} transaction;

#define TX_END (transaction){0, 0}

void init_serverclient(unsigned int seed);
void cleanup_serverclient();

// Message format "from=#{from_id}&to=#{to_id}&amount=#{amount}"
// returns request in form message || IV || MAC
// as long as from and to are user controlled accounts
byte_array sign_request_v1(request_v1 req);
bool verify_request_v1(const byte_array signed_msg);

// Message format "from=1&tx_list=2:100;3:500", etc.
// Account 1 sends 100 spacebucks to account 2, 500 spacebucks to account 3
// This version doesn't use IV, request is message || MAC.
// All arguments after the first should be transactions, with
// TX_END as the final argument.
byte_array sign_request_v2(long from, ...);
bool verify_request_v2(const byte_array signed_msg);

// uses zero IV
byte_array cbc_mac(const byte_array plain, const byte_array key);
