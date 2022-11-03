#include <stdio.h>
#include <stdlib.h>
#include "cryptopals_random.h"

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s filename seed\nBreak random access AES CTR\n", argv[0]);
        return 1;
    }
    init_random_encrypt(atoi(argv[2]));

    byte_array cipher = base64_file_to_bytes(argv[1]);
    byte_array key = cstring_to_bytes("YELLOW SUBMARINE");
    byte_array plaintext = decrypt_aes_128_ecb(cipher, key);

    byte_array ctr_cipher = encrypt_ctr_mystery_key(plaintext);

    byte_array zero_plain = alloc_byte_array(ctr_cipher.len);

    byte_array recovered_key_stream = edit_ciphertext_ctr_mystery_key(ctr_cipher, 0, zero_plain);
    byte_array recovered_plain = xor_byte_arrays(NO_BA, ctr_cipher, recovered_key_stream);

    print_byte_array_ascii(recovered_plain);

    cleanup_random_encrypt();
    free_byte_array(cipher);
    free_byte_array(plaintext);
    free_byte_array(key);
    free_byte_array(ctr_cipher);
    free_byte_array(zero_plain);
    free_byte_array(recovered_key_stream);
    free_byte_array(recovered_plain);
    return 0;
}
