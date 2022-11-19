#include "cryptopals_random.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

void recover_common_xor_key(byte_array key, byte_array ciphertexts[], size_t num_ciphertexts) {
    size_t pos;
    for (pos = 0 ; pos < key.len ; ++pos) {
        uint8_t key_byte;
        uint8_t key_guess = 0;
        size_t best_score = 0;
        do {
            size_t score = 0;
            size_t ciphertext_idx;
            for (ciphertext_idx = 0 ; ciphertext_idx < num_ciphertexts ; ++ciphertext_idx) {
                uint8_t plain_byte = key_guess ^ ciphertexts[ciphertext_idx].bytes[pos];
                if (isalpha(plain_byte) || ' ' == plain_byte) ++score;
            }
            if (score > best_score) {
                best_score = score;
                key_byte = key_guess;
            }
        } while (++key_guess);
        key.bytes[pos] = key_byte;
    }
}

int main(int argc, char ** argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s filename seed\n", argv[0]);
        return 1;
    }
    init_random_encrypt(atoi(argv[2]));

    size_t num_plaintexts;
    byte_array * plaintexts = base64_each_line_to_bytes(&num_plaintexts, argv[1]);
    byte_array ciphertexts[num_plaintexts];
    size_t shortest_cipher_len = 9999;

    size_t idx;
    for (idx = 0 ; idx < num_plaintexts ; ++idx) {
        ciphertexts[idx] = encrypt_ctr_mystery_key(plaintexts[idx]);
        shortest_cipher_len = ciphertexts[idx].len < shortest_cipher_len ? ciphertexts[idx].len : shortest_cipher_len;
    }
    free_array_of_byte_arrays(plaintexts, num_plaintexts);

    byte_array recovered_key = alloc_byte_array(shortest_cipher_len);
    recover_common_xor_key(recovered_key, ciphertexts, num_plaintexts);

    for (idx = 0 ; idx < num_plaintexts ; ++idx) {
        byte_array recovered_plain = xor_byte_arrays(NO_BA, recovered_key, ciphertexts[idx]);
        printf("%2li: ", idx);
        print_byte_array_ascii(recovered_plain);
        free_byte_arrays(recovered_plain, ciphertexts[idx], NO_BA);
    }
    free_byte_array(recovered_key);
    cleanup_random_encrypt();
    return 0;
}
