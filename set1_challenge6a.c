#include "cryptopals_utils.h"
#include <stdio.h>


int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s filename\nDetermine width of key for XOR encryption. Use 6.txt\n", argv[0]);
        return 1;
    }
    byte_array * cipher = base64_file_to_bytes(argv[1]);

    size_t key_width;
    const size_t num_intervals = 20;
    size_t interval_idx;
    for (key_width = 2; key_width <= 40; key_width++) {
        size_t hamming_score = 0;
        for (interval_idx = 0; interval_idx < num_intervals; interval_idx++) {
            byte_array * cipher0 = sub_byte_array(cipher, 2*interval_idx*key_width, (2*interval_idx+1)*key_width);
            byte_array * cipher1 = sub_byte_array(cipher, (2*interval_idx+1)*key_width, (2*interval_idx+2)*key_width);
            hamming_score += hamming_distance(cipher0, cipher1);
            free_byte_array(cipher0);
            free_byte_array(cipher1);
        }
        float score = hamming_score / (float) ( key_width * num_intervals);
        printf("key_width = %li\tscore = %f\n", key_width, score);
    }

    free_byte_array(cipher);
    return 0;
}
