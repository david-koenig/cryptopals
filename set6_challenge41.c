#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "cryptopals_rsa.h"

int main(int argc, char ** argv) {
    const char * desc = "Unpadded message recovery oracle";
    if (argc != 2) {
        fprintf(stderr, "Usage: %s seed\n%s\n", argv[0], desc);
        return 1;
    }
    unsigned int seed =	atoi(argv[1]);
    init_gmp(seed);

    rsa_key_pair kp = rsa_keygen(512);
    byte_array plain = cstring_to_bytes(desc);
    byte_array cipher = rsa_encrypt(kp.public, plain);

    byte_array decrypt = rsa_unpadded_message_recovery_oracle(kp, cipher);
    printf("Plaintext: ");
    print_byte_array_ascii(plain);
    printf("Cracked! : ");
    print_byte_array_ascii(decrypt);
    assert(byte_arrays_equal(plain, decrypt));

    free_rsa_private_key(kp.private);
    free_rsa_public_key(kp.public);
    free_byte_arrays(plain, cipher, decrypt, NO_BA);
    cleanup_gmp();
    return 0;
}
