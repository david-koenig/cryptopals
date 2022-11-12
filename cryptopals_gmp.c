#include "cryptopals_gmp.h"
#include "cryptopals_gmp_private.h"
#include <stdlib.h>

gmp_randstate_t cryptopals_gmp_randstate;

void init_gmp(unsigned long int seed) {
    gmp_randinit_default(cryptopals_gmp_randstate);
    gmp_randseed_ui(cryptopals_gmp_randstate, seed);
    srandom(seed);
}

void cleanup_gmp() {
    gmp_randclear(cryptopals_gmp_randstate);
}
