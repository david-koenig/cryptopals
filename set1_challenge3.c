#include "cryptopals.h"
#include <stdio.h>

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s hex\nTests plaintext for single-byte XOR encryption\n", argv[0]);
        return 1;
    }
    byte_array cipher = hex_to_bytes(argv[1]);
    score_single_byte_xor(cipher, true);

    free_byte_array(cipher);
    return 0;
}
