#include <stdio.h>
#include <string.h>
#include "cryptopals.h"

int main(int argc, char **argv)
{
    int ret;
    if (argc != 2) {
        fprintf(stderr, "Usage: %s filename\nDecrypt with AES-128 CBC mode\n", argv[0]);
        return 1;
    }
    byte_array * cipher = base64_file_to_bytes(argv[1]);
    byte_array * key = cstring_to_bytes("YELLOW SUBMARINE");
    byte_array * iv = alloc_byte_array(16); // defaults to zero

    init_openssl();

    byte_array * plaintext = decrypt_aes_128_cbc(cipher, key, iv);
    print_byte_array_ascii(plaintext);

    byte_array * cipher2 = encrypt_aes_128_cbc(plaintext, key, iv);
    if (byte_arrays_equal(cipher, cipher2)) {
        printf("Reencrypted cipher matches original cipher!\n");
        ret = 0;
    } else {
        printf("Reencrypted cipher differs from original cipher. :-(\n");
        ret = 1;
    }

    cleanup_openssl();
    free_byte_array(cipher);
    free_byte_array(key);
    free_byte_array(iv);
    free_byte_array(plaintext);
    free_byte_array(cipher2);
    return ret;
}
