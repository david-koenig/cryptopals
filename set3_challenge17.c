#include "cryptopals_random.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main(int argc, char ** argv) {
    int ret = 0;
    if (argc != 2) {
        fprintf(stderr, "Usage: %s seed\nCBC padding oracle\n", argv[0]);
        return 1;
    }
    init_random_encrypt(atoi(argv[1]));

    int iterations = 30;
    int iter;
    for (iter = 0; !ret && iter < iterations; ++iter) {

        byte_array iv = NO_BA;
        byte_array spoof = NO_BA;
        byte_array plain = NO_BA;

        byte_array cipher = padding_oracle_encrypt(&iv);
        if (cipher.len < 32) {
            /* If cipher has only one block, the attack is a hybrid of the last block and
             * first block attacks here. You manipulate the IV and use the existing padding bytes.
             */
            fprintf(stderr, "Attack only implemented for cipher of at least 2 blocks.\n");
            ret = 1;
            goto DONE;
        }

        /* Step 1: flip bits in last block of plain until you break PKCS#7 padding
         * to determine padding length.
         */
        spoof = copy_byte_array(cipher);
        size_t cipher_idx = spoof.len - 32;

        do {
            spoof.bytes[cipher_idx++]++; // just mangling this byte in any way
        } while (padding_oracle_decrypt(spoof, iv));
        
        /* We added one extra to cipher_idx in last iteration of loop, so we need to subtract 1.
         * Also need to add 16 because cipher bytes we manipulated were one block before plain
         * bytes that were changed.
         */
        size_t plain_len = cipher_idx + 15;
        uint8_t real_pad_len = cipher.len - plain_len;
        printf("cipher len = %li, plain_len = %li, real_pad_len = %hhi\n", cipher.len, plain_len, real_pad_len);
    
        /* We mangled spoof, so let's get a clean copy of the cipher. Also allocate array for the
         * plain bytes that we will recover.
         */
        free_byte_array(spoof);
        spoof = copy_byte_array(cipher);
        plain = alloc_byte_array(plain_len);

        /* Step 2: Recover byte at a time of last block by changing padding number. */
        uint8_t fake_pad_len = real_pad_len + 1;
        size_t plain_idx = plain.len - 1;
        for ( ; fake_pad_len <= 16 ; ++fake_pad_len, --plain_idx) {

            /* Raise the padding number of existing padding by 1. */
            for (cipher_idx = cipher.len - real_pad_len ; cipher_idx < cipher.len ; cipher_idx++) {
                spoof.bytes[cipher_idx - 16] ^= fake_pad_len ^ (fake_pad_len - 1);
            }

            /* Keep manipulating next byte of plain until it matches padding number */
            uint32_t plain_xor = 0;
            while (!padding_oracle_decrypt(spoof, iv)) {
                spoof.bytes[plain_idx - 16] ^= plain_xor;
                ++plain_xor;
                spoof.bytes[plain_idx - 16] ^= plain_xor;

                if (plain_xor >= 256) {
                    fprintf(stderr, "Error, no hit!\n");
                    ret = 1;
                    goto DONE;
                }
            }

            plain.bytes[plain_idx] = fake_pad_len ^ plain_xor;
            //printf("hit when fake_pad_len = %hhi and plain_xor = %i so plain[%li] = %c\n", fake_pad_len, plain_xor, plain_idx, plain.bytes[plain_idx]);

            /* Set up bytes already spoofed for the next iteration of loop */
            size_t idx;
            for (idx = plain_idx ; idx < cipher.len - real_pad_len ; ++idx) {
                spoof.bytes[idx - 16] ^= fake_pad_len ^ (fake_pad_len + 1);
            }
        }

        /* Attack on a middle block. (No previous padding, able to tweak bits using previous block. */
        while(plain_idx > 15) {
            free_byte_array(spoof);
            spoof = sub_byte_array(cipher, 0, plain_idx+1);
            uint32_t plain_xor = 0;
            /* Usually padding_oracle_decrypt below will succeed only when last byte of manipulated plain
             * is 0x01, which is what we want. Small chance of false hit if for example the next byte down
             * is 0x02, or the next two bytes are 0x03, etc. Just need to keep two candidate values for that
             * rare eventuality.
             */
            uint32_t candidates[2] = {-1, -1};
            int candidate_num = 0;
            do {
                if (padding_oracle_decrypt(spoof, iv)) {
                    candidates[candidate_num++] = plain_xor;
                    //printf("hit! plain_xor = %i at plain[%li] is a candidate\n", plain_xor, plain_idx);
                    if (candidate_num >= 2) {
                        break;
                    }
                }
                spoof.bytes[plain_idx - 16] ^= plain_xor;
                ++plain_xor;
                spoof.bytes[plain_idx - 16] ^= plain_xor;

            } while (plain_xor < 256);

            size_t starting_plain_idx;
            bool bad_candidate = true;
            for (candidate_num = 0; bad_candidate && candidate_num < 2 && candidates[candidate_num] != -1; candidate_num++) {
                bad_candidate = false;

                free_byte_array(spoof);
                spoof = sub_byte_array(cipher, 0, plain_idx+1);

                starting_plain_idx = plain_idx;
                plain_xor = candidates[candidate_num];
                plain.bytes[plain_idx] = plain_xor ^ 1;
                //printf("assuming plain[%li] = %c\n", plain_idx, plain.bytes[plain_idx]);
                spoof.bytes[plain_idx - 16] ^= plain_xor ^ 1 ^ 2;
                for (fake_pad_len = 2, --plain_idx ; fake_pad_len <= 16 ; ++fake_pad_len, --plain_idx) {
                    plain_xor = 0;
                    while (!padding_oracle_decrypt(spoof, iv) && plain_xor < 256) {
                        spoof.bytes[plain_idx - 16] ^= plain_xor;
                        ++plain_xor;
                        spoof.bytes[plain_idx - 16] ^= plain_xor;
                    }
                    if (plain_xor == 256) {
                        printf("bad candidate discovered\n");
                        bad_candidate = true;
                        plain_idx = starting_plain_idx;
                        break;
                    }
                    plain.bytes[plain_idx] = plain_xor ^ fake_pad_len;
                    //printf("hit when fake_pad_len = %hhi and plain_xor = %i so plain[%li] = %c\n", fake_pad_len, plain_xor, plain_idx, plain.bytes[plain_idx]);

                    size_t idx;
                    for (idx = plain_idx; idx <= starting_plain_idx; ++idx) {
                        spoof.bytes[idx - 16] ^= fake_pad_len ^ (fake_pad_len + 1);
                    }
                }
            }
            if (bad_candidate) {
                fprintf(stderr, "Attack on block ending in plain[%li] failed\n", starting_plain_idx);
                ret = 1;
                goto DONE;
            }
            //printf("Another block recovered! plain_idx = %li\n", plain_idx);
        }
        /* Step 3: Attack on final block. Same as other full blocks except that you need to manipulate bits of IV
         * to affect first block of plain. first_block_cipher takes place of spoof here, and all the manipulation
         * happens to the IV.
         */
        assert(plain_idx == 15);

        byte_array first_block_cipher = sub_byte_array(cipher, 0, 16);
        byte_array spoof_iv = copy_byte_array(iv);
        
        uint32_t candidates[2] = {-1, -1};
        int candidate_num = 0;
        uint32_t plain_xor = 0;
        do {
            if (padding_oracle_decrypt(first_block_cipher, spoof_iv)) {
                candidates[candidate_num++] = plain_xor;
                //printf("hit! plain_xor = %i at plain[%li] is a candidate\n", plain_xor, plain_idx);
                if (candidate_num >= 2) {
                    break;
                }
            }
            spoof_iv.bytes[15] ^= plain_xor;
            ++plain_xor;
            spoof_iv.bytes[15] ^= plain_xor;

        } while (plain_xor < 256);

        bool bad_candidate = true;
        for (candidate_num = 0; bad_candidate && candidate_num < 2 && candidates[candidate_num] != -1; candidate_num++) {
            bad_candidate = false;
            
            free_byte_array(spoof_iv);
            spoof_iv = copy_byte_array(iv);
            
            plain_xor = candidates[candidate_num];
            plain.bytes[15] = plain_xor ^ 1;
            //printf("assuming plain[15] = %c\n", plain.bytes[15]);
            spoof_iv.bytes[15] ^= plain_xor ^ 1 ^ 2;
            for (fake_pad_len = 2, plain_idx = 14 ; fake_pad_len <= 16 ; ++fake_pad_len, --plain_idx) {
                plain_xor = 0;
                while (!padding_oracle_decrypt(first_block_cipher, spoof_iv) && plain_xor < 256) {
                    spoof_iv.bytes[plain_idx] ^= plain_xor;
                    ++plain_xor;
                    spoof_iv.bytes[plain_idx] ^= plain_xor;
                }
                if (plain_xor == 256) {
                    printf("bad candidate discovered\n");
                    bad_candidate = true;
                    break;
                }
                plain.bytes[plain_idx] = plain_xor ^ fake_pad_len;
                //printf("hit when fake_pad_len = %hhi and plain_xor = %i so plain[%li] = %c\n", fake_pad_len, plain_xor, plain_idx, plain.bytes[plain_idx]);

                size_t idx;
                for (idx = plain_idx; idx <= 15; ++idx) {
                    spoof_iv.bytes[idx] ^= fake_pad_len ^ (fake_pad_len + 1);
                }
            }
        }
        if (bad_candidate) {
            fprintf(stderr, "Attack on first cipher block failed.\n");
            ret = 1;
        } else {
            printf("Entire plain recovered:\t");
            print_byte_array_ascii(plain);
        }


    DONE:
        free_byte_array(iv); iv = NO_BA;
        free_byte_array(cipher); cipher = NO_BA;
        free_byte_array(first_block_cipher); first_block_cipher = NO_BA;
        free_byte_array(spoof_iv); spoof_iv = NO_BA;
        free_byte_array(spoof); spoof = NO_BA;
        free_byte_array(plain); plain = NO_BA;

    }

    cleanup_random_encrypt();
    return ret;
}
