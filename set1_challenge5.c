#include "cryptopals.h"
#include <stdio.h>

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s string\nEncrypt string with repeating-key XOR value \"ICE\"\n", argv[0]);
        return 1;
    }
    byte_array * plaintext = cstring_to_bytes(argv[1]);
    char * repeating_key_str = "ICE";
    byte_array * repeating_key = cstring_to_bytes(repeating_key_str);

    byte_array * cipher = repeating_byte_xor(plaintext, repeating_key);
    print_byte_array(cipher);

    free_byte_array(plaintext);
    free_byte_array(repeating_key);
    free_byte_array(cipher);
    return 0;
}
