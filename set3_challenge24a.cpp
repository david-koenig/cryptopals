#include "cryptopals_mersenne.h"
#include <iostream>
#include <sstream>
extern "C" {
#include "cryptopals_random.h"
}

int main(int argc, char ** argv) {
    uint16_t seed;
    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " 16_bit_seed" << std::endl;
        std::cout << "Break MT19937 stream cipher" << std::endl;
        return 1;
    } else {
        std::istringstream ss(argv[1]);
        if (!(ss >> seed)) {
            std::cerr << "Invalid number: " << argv[1] << std::endl;
            return 1;
        }
    }

    byte_array * cipher;
    const size_t num_As = 14; // far more bits of check than we need

    {
        init_random_encrypt((int) seed); // just for random_byte_array
        cryptopals::mt19937_cipher mtc(seed);
        seed = 0;

        byte_array * junk = random_byte_array();
        byte_array * plain = alloc_byte_array(num_As);
        set_all_bytes(plain, 'A');
        byte_array * input = append_byte_arrays(junk, plain);
        cipher = mtc.encrypt(input);

        free_byte_array(junk);
        free_byte_array(plain);
        free_byte_array(input);
        cleanup_random_encrypt();
    }
    /* We are assuming that attacker does not have access to the mt19937_cipher
     * object nor anything else other than the ciphertext and his own ability to
     * generate a Mersenne Twister.
     *
     * Enclosing the above code in a block causes the mt19337_cipher object to go
     * out of scope here and for the destructor to be called. Equivalently, we
     * could have made the block above a separate function.
     */

    size_t junk_len = cipher->len - num_As;
    cryptopals::mt19937 mt(seed);
    bool seed_recovered = false;

    do {
        size_t idx = 0;
        /* Advance to part of random stream we care about */
        for ( ; idx < junk_len ; ++idx) { mt.rand(); }
        /* Having cipher that matches in the lower byte of expected cipher is 1/(2^8) random event.
         * But matching in two bytes is 1/(2^16), and in three bytes is 1/(2^24), etc.
         * We need enough known bytes to check in order to make chances of a random survivor highly unlikely
         * among the 2^16 seed values we are exhausting. Note that if we were searching a larger seed space,
         * we would need more bits of check.
         */
        while (idx < cipher->len && ((uint8_t) mt.rand() ^ cipher->bytes[idx]) == 'A') {
            ++idx;
        }
        if (idx == cipher->len) {
            seed_recovered = true;
        } else {
            mt.srand(++seed);
        }
    } while (!seed_recovered && seed);

    int ret;
    if (seed_recovered) {
        std::cout << "Seed recovered: " << seed << std::endl;
        ret = 0;
    } else {
        std::cout << "Unable to recover seed!" << std::endl;
        ret = 1;
    }

    free_byte_array(cipher);
    return ret;
}
