#include "cryptopals.h"
#include <stdio.h>

int main(int argc, char ** argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s filename repeating_key\nApply repeating key to cipher. Use 6.txt\n", argv[0]);
        return 1;
    }
    byte_array cipher = base64_file_to_bytes(argv[1]);
    byte_array repeating_key = hex_to_bytes(argv[2]);
    byte_array plaintext = repeating_byte_xor(cipher, repeating_key);
    print_byte_array_ascii(plaintext);
    free_byte_array(cipher);
    free_byte_array(repeating_key);
    free_byte_array(plaintext);
    return 0;
}

