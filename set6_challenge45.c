#include "cryptopals_dsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main(int argc, char ** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s seed\nDegenerate DSA cases\n", argv[0]);
        return 1;
    }
    unsigned int seed =	atoi(argv[1]);
    init_gmp(seed);

    const char * desc = "Hello, world";
    byte_array msg = cstring_to_bytes(desc);
    const char * str2 = "Goodbye, world";
    byte_array msg2 = cstring_to_bytes(str2);

    {
        printf("Case g=0 mod p: All signatures will have r=0 and all will verify\n");
        printf("regardless of public key used. Any pair (r=0,s=anything) will\n");
        printf("pass signature verification, regardless of the message.\n\n");
        printf("In this example, we don't do key generation, which would always\n");
        printf("give the obviously bad public key y=0, and instead just use a\n");
        printf("random number for the public key, because it doesn't matter.\n\n");

        const dsa_params * params = dsa_param_g0();
        dsa_key_pair key = random_key_pair(params);
        const dsa_sig * sig = dsa_sign(params, key.private, msg);
        printf("Signing \"%s\":\n", desc);
        print_sig(sig);

        printf("Verifying this signature using \"%s\"...", desc);
        assert(dsa_verify(params, key.public, msg, sig));
        printf("Verified!\n");

        printf("Verifying this signature using \"%s\"...", str2);
        assert(dsa_verify(params, key.public, msg2, sig));
        printf("Verified!\n");

        const dsa_sig * rand_sig = random_s_set_r(params, 0);
        printf("\nJust a random number s posing as a signature:\n");
        print_sig(rand_sig);

        printf("Verifying this signature using \"%s\"...", desc);
        assert(dsa_verify(params, key.public, msg, rand_sig));
        printf("Verified!\n");

        printf("Verifying this signature using \"%s\"...", str2);
        assert(dsa_verify(params, key.public, msg2, rand_sig));
        printf("Verified!\n\n");

        free_dsa_sig(sig);
        free_dsa_sig(rand_sig);
        free_dsa_public_key(key.public);
        free_dsa_private_key(key.private);
        free_dsa_params(params);
    }

    printf("---------------------------------------------------------------\n\n");
    
    {
        printf("Case g=1 mod p: In this case, key generation would always give\n");
        printf("y=1 and then any pair (r=1,s=anything) will pass verification\n");
        printf("regardless of the message, but only for the key y=1.\n\n");
        printf("However, we can give out a phony public key and produce magic\n");
        printf("signatures which always validate with that key, and those\n");
        printf("signatures don't have an obviously degenerate form.\n\n");
        
        const dsa_params * params = dsa_param_g1();

        printf("Creating a random public key and magic signature for that key:\n");
        dsa_key_pair kp = random_key_pair(params);
        const dsa_sig * magic_sig1 = magic_sig(params, kp.public);
        print_sig(magic_sig1);
        
        printf("Verifying this signature using \"%s\"...", desc);
        assert(dsa_verify(params, kp.public, msg, magic_sig1));
        printf("Verified!\n");

        printf("Verifying this signature using \"%s\"...", str2);
        assert(dsa_verify(params, kp.public, msg2, magic_sig1));
        printf("Verified!\n\n");
    
        const dsa_sig * magic_sig2 = magic_sig(params, kp.public);
        printf("A different magic signature for the same key:\n");
        print_sig(magic_sig2);

        printf("Verifying this signature using \"%s\"...", desc);
        assert(dsa_verify(params, kp.public, msg, magic_sig2));
        printf("Verified!\n");

        printf("Verifying this signature using \"%s\"...", str2);
        assert(dsa_verify(params, kp.public, msg2, magic_sig2));
        printf("Verified!\n\n");

        dsa_key_pair kp2 = random_key_pair(params);
        printf("But these signatures don't verify with a different public key:\n");

        printf("Retrying first magic signature with \"%s\"...", desc);
        assert(!dsa_verify(params, kp2.public, msg, magic_sig1));
        printf("Failed!\n");

        printf("Retrying first magic signature with \"%s\"...", str2);
        assert(!dsa_verify(params, kp2.public, msg2, magic_sig1));
        printf("Failed!\n\n");

        printf("Retrying second magic signature with \"%s\"...", desc);
        assert(!dsa_verify(params, kp2.public, msg, magic_sig2));
        printf("Failed!\n");

        printf("Retrying second magic signature with \"%s\"...", str2);
        assert(!dsa_verify(params, kp2.public, msg2, magic_sig2));
        printf("Failed!\n");
        
        free_dsa_params(params);
        free_dsa_private_key(kp.private);
        free_dsa_public_key(kp.public);
        free_dsa_private_key(kp2.private);
        free_dsa_public_key(kp2.public);
        free_dsa_sig(magic_sig1);
        free_dsa_sig(magic_sig2);
    }

    free_byte_array(msg);
    free_byte_array(msg2);
    
    cleanup_gmp();
    return 0;
}
