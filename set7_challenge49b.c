#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "cryptopals_cbcmac.h"

int main(int argc, char ** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s seed\nCBC-MAC message forgery\n", argv[0]);
        return 1;
    }
    unsigned int seed = atoi(argv[1]);
    init_serverclient(seed);

    // I control accounts 213, 867, 201, 917
    transaction tx1 = {.to = 867, .amount = 5000};
    transaction tx2 = {.to = 201, .amount = 7500};
    transaction tx3 = {.to = 917, .amount = 1000000};
    
    byte_array signed_msg = sign_request_v2(777, tx1, tx2, tx3, TX_END);
    assert(!signed_msg.bytes);

    signed_msg = sign_request_v2(213, tx1, tx2, tx3, TX_END);
    assert(signed_msg.bytes);

    assert(verify_request_v2(signed_msg));

    free_byte_array(signed_msg);
    cleanup_serverclient();
}
