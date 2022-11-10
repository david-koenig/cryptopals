#include <stdio.h>
#include <stdlib.h>
#include "cryptopals_rsa.h"

int main(int argc, char ** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s seed [hollywood]\nRSA parity oracle attack\nRun this with an extra argument for Hollywood mode\n", argv[0]);
        return 1;
    }
    unsigned int seed =	atoi(argv[1]);
    init_gmp(seed);
    bool ret = rsa_parity_oracle_attack(argc > 2);
    cleanup_gmp();
    return !ret;
}
