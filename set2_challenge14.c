#include "cryptopals_random.h"
#include "cryptopals_attack.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

bool find_repeated_block(size_t * matching_block_idx_p, size_t * unused_len_p, size_t block_size, byte_array (*encrypt)(const byte_array)) {
    size_t plain_len;
    size_t matching_block_idx;

    for (plain_len = block_size << 1 ; ; ++plain_len) {
        byte_array plain = alloc_byte_array(plain_len);
        set_all_bytes(plain, 'A');
        byte_array cipher = encrypt(plain);
        for (matching_block_idx = 0 ; matching_block_idx < cipher.len / block_size - 1 ; ++matching_block_idx) {
            if (!memcmp(cipher.bytes + block_size * matching_block_idx, cipher.bytes + block_size * (matching_block_idx + 1), block_size)) {
                printf("%s: First encryption with matching blocks: input len: %li, first matching block: %li\n", __func__, plain_len, matching_block_idx);
                free_byte_array(plain);
                free_byte_array(cipher);
                *matching_block_idx_p = matching_block_idx;
                *unused_len_p = plain_len % block_size;
                return true;
            }
        }
        free_byte_array(plain);
        free_byte_array(cipher);
        if (plain_len >= block_size * 3) {
            printf("%s: No matching blocks found. Possibly not ECB.\n", __func__);
            return false;
        }
    }

}

int main(int argc, char ** argv) {
    size_t block_size;
    size_t matching_block_idx;
    size_t unknown_len; // number of bytes of plain not provided by the attacker (junk_len + target_len)
    size_t unused_len;  // number of bytes at beginning of attacker-provided input that are just for spacing
    size_t junk_len;    // number of bytes of plain before attacker-provided input
    size_t target_len;  // number of bytes of plain after attacker-provided input (that we want to recover)

    if (argc != 2) {
        fprintf(stderr, "Usage: %s seed\nRecover plaintext using byte at a time ECB attack\n", argv[0]);
        return 1;
    }

    /* Setup: This sets up harder_mystery_encrypt() function with a random key, but the key will always be the
     * same if you reuse the seed as input. Try running the attack with different seeds.
     */
    init_random_encrypt(atoi(argv[1]));

    /* Part 1: Encrypt successively longer strings to determine block size and length of unknown string.
     * When cipher length jumps, you will know that the last block is all padding, and that the input
     * string and the unknown string will fill all the rest of the blocks.
     */
    if (find_block_size(&block_size, &unknown_len, 'A', harder_mystery_encrypt)) {

        /* Part 2: Encrypt longer plaintexts until we get a repeated block, which verifies ECB, allows us to know
         * how many of the unknown bytes come before our input (junk) and come after our input (target).
         * The block index where the repeat occurs is needed to know where to attack.
         */
        if (find_repeated_block(&matching_block_idx, &unused_len, block_size, harder_mystery_encrypt)) {
            junk_len = (matching_block_idx * block_size) - unused_len;
            target_len = unknown_len - junk_len;
            printf("Bytes at beginning of input not used in repeated blocks = %li\n", unused_len);
            printf("Prepended junk len = %li\n", junk_len);
            printf("Target len = %li\n\n", target_len);

            /* Part 3: Recover one byte of unknown text at a time, by spoofing input. */
            recover_bytes(target_len, 'A', unused_len, block_size, matching_block_idx, harder_mystery_encrypt);
        }
    }

    cleanup_random_encrypt();
    return 0;
}
