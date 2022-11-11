#include <stdio.h>
#include <stdlib.h>
#include "cryptopals_rsa.h"

int main(int argc, char ** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s seed\nRSA padding oracle attack\n", argv[0]);
        return 1;
    }
    unsigned int seed =	atoi(argv[1]);
    init_gmp(seed);
    bool ret = rsa_padding_oracle_test();
    cleanup_gmp();
    return !ret;
}
