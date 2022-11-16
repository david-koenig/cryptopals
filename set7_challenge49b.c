#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "cryptopals_cbcmac.h"
#include "cryptopals.h"

int main(int argc, char ** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s seed\nCBC-MAC message forgery\n", argv[0]);
        return 1;
    }
    unsigned int seed = atoi(argv[1]);
    init_serverclient(seed);

    printf("Successful signed request between accounts I control:\n");
    transaction tx = {.to = 98765432109, .amount = 1000000};
    byte_array my_signed_msg = sign_request_v2(12345678901L, tx, TX_END);
    assert(my_signed_msg.bytes);
    assert(verify_request_v2(my_signed_msg));
    
    printf("\nSuccessful signed request by the victim, picked up on the wire:\n");
    transaction tx1 = {.to = 12121212121, .amount = 1000};
    transaction tx2 = {.to = 34343434343, .amount = 750};
    transaction tx3 = {.to = 56565656565, .amount = 1200};
    byte_array victim_signed_msg = sign_request_v2(77777777777L, tx1, tx2, tx3, TX_END);
    assert(victim_signed_msg.bytes);
    assert(verify_request_v2(victim_signed_msg));

    // Length Extension Attack

    // signed msg = victim msg || PKCS7 padding || victim MAC ^ first block of my msg || my MAC
    // This works because the first two chunks are exact same encryption as calculation of victim's
    // MAC. Then because of how CBC works, that value gets xor'ed with the next block, so the
    // state of the cipher block chain becomes exactly as if we started with my message and IV=0.
    // Final calculation of MAC will just be my MAC.

    // However, the underlying message parsed by the server will have gobbledygook bytes
    // (the two middle chunks) which we have to assume the parser will skip over. I intentionally
    // used a length 11 account number so that "from=12345678901" would be the first block, and
    // the second block would start "&tx_list=" and then implemented a bad server-side parser which
    // would tolerate these hijinks.

    size_t block_size = 16;
    byte_array first_block_my_msg_window = {my_signed_msg.bytes, block_size};
    // includes my MAC
    byte_array rest_of_my_msg_window = {my_signed_msg.bytes+block_size, my_signed_msg.len-block_size};

    size_t victim_msg_len = victim_signed_msg.len - block_size;
    byte_array victim_msg_window = {victim_signed_msg.bytes, victim_msg_len};
    byte_array victim_mac_window = {victim_signed_msg.bytes+victim_msg_len, block_size};

    byte_array padded_victim_msg = pkcs7_padding(victim_msg_window, block_size);
    byte_array xor = xor_byte_arrays(NO_BA, first_block_my_msg_window, victim_mac_window);
    byte_array extension = append_three_byte_arrays(padded_victim_msg, xor, rest_of_my_msg_window);

    printf("\nI hacked them together to make this successful request:\n");
    assert(verify_request_v2(extension));

    free_byte_array(my_signed_msg);
    free_byte_array(victim_signed_msg);
    free_byte_array(padded_victim_msg);
    free_byte_array(xor);
    free_byte_array(extension);
    cleanup_serverclient();
}
