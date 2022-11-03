#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "cryptopals_rsa.h"

const char * desc = "E=3 RSA broadcast attack";

int main(int argc, char ** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s seed\n%s\n", argv[0], desc);
        return 1;
    }
    unsigned int seed =	atoi(argv[1]);
    init_gmp(seed);
    byte_array * plain = cstring_to_bytes(desc);

    const rsa_public_key * public[3];
    const byte_array * cipher[3];
    
    for (int idx = 0 ; idx < 3 ; idx++) {
        // This doesn't check that the generated moduli are pairwise coprime.
        // But as long as the random number generation is reasonable, the chance
        // of that is negligible.
        rsa_params params = rsa_keygen(256);
        free_rsa_private_key(params.private);
        public[idx] = params.public;
        cipher[idx] = rsa_encrypt(params.public, plain);
    }
    
    byte_array * cracked_plain = rsa_broadcast_attack(public, cipher);
    printf("Plaintext: ");
    print_byte_array_ascii(plain);
    printf("Cracked! : ");
    print_byte_array_ascii(cracked_plain);
    assert(byte_arrays_equal(plain, cracked_plain));
    
    for (int idx = 0; idx < 3 ; idx++) {
        free_rsa_public_key(public[idx]);
        free_byte_array((byte_array *)cipher[idx]);
    }
    free_byte_array(cracked_plain);
    free_byte_array(plain);
    cleanup_gmp();
    return 0;
}
