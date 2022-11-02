#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "cryptopals_rsa.h"

int main(int argc, char ** argv) {
        if (argc != 2) {
        fprintf(stderr, "Usage: %s seed\nRSA encryption of string\n", argv[0]);
        return 1;
    }
    unsigned int seed =	atoi(argv[1]);
    init_gmp(seed);
    rsa_params * params = rsa_keygen();

    byte_array * plain = cstring_to_bytes("Testing RSA encryption and decryption");
    byte_array * cipher = rsa_encrypt(params, plain);
    byte_array * decrypt = rsa_decrypt(params, cipher);

    printf("Plaintext: ");
    print_byte_array_ascii(plain);
    printf("Decrypted: ");
    print_byte_array_ascii(decrypt);
    assert(byte_arrays_equal(plain, decrypt));
    
    free_byte_array(plain);
    free_byte_array(cipher);
    free_byte_array(decrypt);
    free_rsa_params(params);
    cleanup_gmp();
    return 0;
}
