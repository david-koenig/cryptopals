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

    // I control accounts 213 and 867, so client will sign requests involving
    // those accounts, but I want to steal money from account 777.
    request_v1 good_req = {.from = 213, .to = 867, .amount = 1000000};
    request_v1 bad_req = {.from = 777, .to = 867, .amount = 1000000};
    
    byte_array signed_msg = sign_request_v1(bad_req);
    assert(!signed_msg.bytes);

    signed_msg = sign_request_v1(good_req);
    assert(signed_msg.bytes);

    size_t block_size = 16;
    size_t msg_len = signed_msg.len - 2*block_size;
    byte_array msg_window = {signed_msg.bytes, msg_len};
    byte_array iv_window = {signed_msg.bytes+msg_len, block_size};
    byte_array forge_first_block = {"from=777", strlen("from=777")};
    byte_array xor = xor_byte_arrays(NO_BA, msg_window, forge_first_block);

    // Overwrite first block of signed message.
    memcpy(msg_window.bytes, forge_first_block.bytes, forge_first_block.len);

    // Does not work because of CBC-MAC check.
    assert(!verify_request_v1(signed_msg));
    
    // Modify IV accordingly.
    xor_block(iv_window.bytes, iv_window.bytes, xor.bytes, xor.len);

    // Jackpot!
    assert(verify_request_v1(signed_msg));

    free_byte_array(xor);
    free_byte_array(signed_msg);
    cleanup_serverclient();
    return 0;
}
