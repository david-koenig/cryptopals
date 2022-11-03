#include "cryptopals_utils.h"
#include <stdio.h>

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s x y\nOutputs x ^ y\n", argv[0]);
        return 1;
    }
    byte_array x = hex_to_bytes(argv[1]);
    byte_array y = hex_to_bytes(argv[2]);
    byte_array z = xor_byte_arrays(NO_BA, x, y);
    print_byte_array(z);

    free_byte_array(x);
    free_byte_array(y);
    free_byte_array(z);
    return 0;
}

