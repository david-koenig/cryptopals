#include "cryptopals.h"
#include <stdio.h>
#include <stdlib.h>


int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s filename key_width\nCrack repeating key XOR encryption. Use 6.txt\n", argv[0]);
        return 1;
    }
    const size_t key_width = atol(argv[2]);
    byte_array * cipher = base64_file_to_bytes(argv[1]);

    size_t stripe_idx;
    byte_array * stripes[key_width];
    uint8_t * stripe_ptr[key_width];
    for (stripe_idx = 0; stripe_idx < key_width; stripe_idx++) {
        stripes[stripe_idx] = alloc_byte_array((cipher->len + key_width - 1 - stripe_idx)/key_width);
        stripe_ptr[stripe_idx] = stripes[stripe_idx]->bytes;
    }
    size_t byte_idx;
    
    for (byte_idx = 0; byte_idx < cipher->len ; byte_idx++) {
        *(stripe_ptr[byte_idx % key_width])++ = cipher->bytes[byte_idx];
    }

    for (stripe_idx = 0; stripe_idx < key_width; stripe_idx++) {
        printf("STRIPE %li\t", stripe_idx);
        score_single_byte_xor(stripes[stripe_idx], false);
        free_byte_array(stripes[stripe_idx]);
    }
    free_byte_array(cipher);
    return 0;
}
