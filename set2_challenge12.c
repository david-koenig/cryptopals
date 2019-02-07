#include "cryptopals_random.h"
#include "cryptopals_attack.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

bool compare_first_two_blocks(const byte_array * ba, size_t block_size) {
    if (memcmp(ba->bytes, ba->bytes + block_size, block_size)) {
        printf("%s: First two blocks of cipher disagree, does not seem to be ECB\n", __func__);
        return false;
    }
    printf("%s: First two blocks of long_cipher agree, ECB verified\n\n", __func__);
    return true;
}

int main(int argc, char ** argv) {
    byte_array * long_plain = NULL;
    byte_array * long_cipher = NULL;
    size_t block_size;
    size_t target_len;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s seed\nRecover plaintext using byte at a time ECB attack\n", argv[0]);
        return 1;
    }

    /* Setup: This sets up mystery_encrypt() function with a random key, but the key will always be the
     * same if you reuse the seed as input. Try running the attack with different seeds.
     */
    init_random_encrypt(atoi(argv[1]));

    /* Part 1: Encrypt successively longer strings to determine block size and length of unknown string.
     * When cipher length jumps, you will know that the last block is all padding, and that the input
     * string and the unknown string will fill all the rest of the blocks.
     */
    if (find_block_size(&block_size, &target_len, 'A', mystery_encrypt)) {

        /* Part 2: Verify encryption is using ECB. */
        long_plain = alloc_byte_array(2*block_size);
        set_all_bytes(long_plain, 'A');
        long_cipher = mystery_encrypt(long_plain);
        if (compare_first_two_blocks(long_cipher, block_size)) {

            /* Part 3: Recover one byte of unknown text at a time, by spoofing input. */
            recover_bytes(target_len, 'A', 0, block_size, 0, mystery_encrypt);
        }
    }

    free_byte_array(long_plain);
    free_byte_array(long_cipher);
    cleanup_random_encrypt();
    return 0;
}
