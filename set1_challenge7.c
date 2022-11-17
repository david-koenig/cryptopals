#include <stdio.h>
#include "cryptopals.h"

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s filename\nDecrypt with AES-128 ECB mode\n", argv[0]);
        return 1;
    }
    byte_array cipher = base64_file_to_bytes(argv[1]);
    byte_array key = cstring_to_bytes("YELLOW SUBMARINE");

    init_openssl();

    byte_array plaintext = decrypt_aes_128_ecb(cipher, key);
    print_byte_array_ascii(plaintext);

    cleanup_openssl();
    free_byte_arrays(cipher, plaintext, key, NO_BA);
    return 0;
}
