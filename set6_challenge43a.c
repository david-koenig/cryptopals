#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "cryptopals_dsa.h"

int main(int argc, char ** argv) {
    const char * desc = "DSA implementation";
    if (argc != 2) {
        fprintf(stderr, "Usage: %s seed\n%s\n", argv[0], desc);
        return 1;
    }
    unsigned int seed =	atoi(argv[1]);
    init_gmp(seed);

    byte_array msg = cstring_to_bytes(desc);
    const dsa_params * params = dsa_paramgen();
    dsa_key_pair kp = dsa_keygen(params);
    const dsa_sig * sig = dsa_sign(params, kp.private, msg);
    assert(dsa_verify(params, kp.public, msg, sig));
    printf("Signature verified!\n");
    
    free_byte_array(msg);
    free_dsa_params(params);
    free_dsa_private_key(kp.private);
    free_dsa_public_key(kp.public);
    free_dsa_sig(sig);
    cleanup_gmp();
    return 0;
}
