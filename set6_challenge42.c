#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "cryptopals_rsa.h"

int main(int argc, char ** argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s seed msg\nBleichenbacher's e=3 RSA Attack\n", argv[0]);
        return 1;
    }
    unsigned int seed =	atoi(argv[1]);
    init_gmp(seed);
    rsa_params params = rsa_keygen(1024);

    byte_array msg = cstring_to_bytes(argv[2]);
    byte_array sig = rsa_md4_sign_msg(params.private, msg);
    
    assert(rsa_md4_verify_sig(params.public, msg, sig));
    printf("Real signature verified!\n");

    byte_array fake_sig = hack_sig(params.public, msg);
    assert(rsa_md4_verify_sig(params.public, msg, fake_sig));
    printf("Fake signature verified!\n");

    free_byte_array(msg);
    free_byte_array(sig);
    free_byte_array(fake_sig);
    free_rsa_private_key(params.private);
    free_rsa_public_key(params.public);
    cleanup_gmp();
    return 0;
}
