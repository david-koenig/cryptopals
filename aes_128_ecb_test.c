#include <stdio.h>
#include <stdlib.h>
#include "cryptopals.h"

int main(int argc, char **argv)
{
    int ret;
    if (argc != 2) {
        fprintf(stderr, "Usage: %s size\nEncrypt and then decrypt a string of 'A's of the specified size\n", argv[0]);
        return 1;
    }
    size_t len = atol(argv[1]);

    byte_array key = cstring_to_bytes("YELLOW SUBMARINE");

    byte_array plaintext = alloc_byte_array(len);
    set_all_bytes(plaintext, 'A');
    printf("input length = %li\ninput = ", len);
    print_byte_array_ascii(plaintext);

    init_openssl();

    printf("\nEncrypting...\n");
    byte_array cipher = encrypt_aes_128_ecb(plaintext, key);
    printf("cipher length = %li\ncipher = ", cipher.len);
    print_byte_array(cipher);

    printf("\nDecrypting...\n");
    byte_array plain2 = decrypt_aes_128_ecb(cipher, key);
    printf("output length = %li\noutput = ", plain2.len);
    print_byte_array_ascii(plain2);

    if (byte_arrays_equal(plaintext, plain2)) {
        printf("Plaintexts match! :-)\n");
        ret = 0;
    } else {
        printf("Plaintexts differ! :-(\n");
        ret = 1;
    }

    cleanup_openssl();
    free_byte_array(key);
    free_byte_array(plaintext);
    free_byte_array(cipher);
    free_byte_array(plain2);

    return ret;
}
