#include "cryptopals.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char ** argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s string block_size\nAdd PKCS#7 padding to string\n", argv[0]);
        return 1;
    }
    size_t block_size = atol(argv[2]);
    byte_array ba = cstring_to_bytes(argv[1]);
    byte_array padded_ba = pkcs7_padding(ba, block_size);
    printf("Original byte array:\t0x");
    print_byte_array(ba);
    printf("Padded byte array:\t0x");
    print_byte_array(padded_ba);
    free_byte_array(ba);
    free_byte_array(padded_ba);
    return 0;
}
