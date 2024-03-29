#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "cryptopals_rsa.h"

int main(int argc, char ** argv) {
    const char * desc = "E=3 RSA broadcast attack";
    if (argc != 2) {
        fprintf(stderr, "Usage: %s seed\n%s\n", argv[0], desc);
        return 1;
    }
    unsigned int seed =	atoi(argv[1]);
    init_gmp(seed);
    byte_array plain = cstring_to_bytes(desc);

    const rsa_public_key * public[3];
    byte_array cipher[3];
    
    for (int idx = 0 ; idx < 3 ; idx++) {
        // This doesn't check that the generated moduli are pairwise coprime.
        // But as long as the random number generation is reasonable, the chance
        // of that is negligible.
        rsa_key_pair kp = rsa_keygen(256);
        free_rsa_private_key(kp.private);
        public[idx] = kp.public;
        cipher[idx] = rsa_encrypt(kp.public, plain);
    }
    
    byte_array cracked_plain = rsa_broadcast_attack(public, cipher);
    printf("Plaintext: ");
    print_byte_array_ascii(plain);
    printf("Cracked! : ");
    print_byte_array_ascii(cracked_plain);
    assert(byte_arrays_equal(plain, cracked_plain));
    
    for (int idx = 0; idx < 3 ; idx++) {
        free_rsa_public_key(public[idx]);
        free_byte_array(cipher[idx]);
    }
    free_byte_arrays(cracked_plain, plain, NO_BA);
    cleanup_gmp();
    return 0;
}
