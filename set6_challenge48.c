#include <stdio.h>
#include <stdlib.h>
#include "cryptopals_rsa.h"

int main(int argc, char ** argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s seed msg\nRSA padding oracle attack (complete case)\n", argv[0]);
        return 1;
    }
    unsigned int seed =	atoi(argv[1]);
    init_gmp(seed);
    bool ret = rsa_padding_oracle_attack(728, argv[2]);
    cleanup_gmp();
    return !ret;
}

