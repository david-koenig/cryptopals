#include "cryptopals_random.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char ** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s seed\nDetermine whether random_encrypt is using CBC or ECB\n", argv[0]);
        return 1;
    }
    init_random_encrypt(atoi(argv[1]));

    byte_array * plain = alloc_byte_array(48);
    set_all_bytes(plain, 'A');

    byte_array * cipher = random_encrypt(plain);
    const size_t block_size = 16;
    print_byte_array_blocks(cipher, block_size, '\n');
    if (memcmp(cipher->bytes+block_size, cipher->bytes+(block_size << 1), block_size)) {
        printf("CBC mode!\n");
    } else {
        printf("ECB mode!\n");
    }

    free_byte_array(plain);
    free_byte_array(cipher);
    cleanup_random_encrypt();
    return 0;
}
