#include "cryptopals_utils.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char ** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s hex\nConverts hex to base64\n", argv[0]);
        return 1;
    }
    uint8_t * base64_str = hex_to_base64(argv[1]);
    printf("%s\n", base64_str);
    free(base64_str);
    return 0;
}
