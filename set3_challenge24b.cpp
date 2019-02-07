#include "cryptopals_mersenne.h"
#include <iostream>
#include <sstream>
#include <ctime>
#include <cassert>

class token_generator {
private:
    cryptopals::mt19937 byte_gen;

public:
    token_generator(uint32_t seed) : byte_gen(seed) {}

    // Assuming that plaintext token is 16 uppercase hex characters.
    // Use time_offset for generating tokens from different time.
    byte_array * generate(int32_t time_offset = 0) {
        char buf[17] = ""; // 16 + 1 for null byte
        sprintf(buf, "%08X%08X", byte_gen.rand(), byte_gen.rand());
        byte_array * plaintext_token = cstring_to_bytes(buf);

        cryptopals::mt19937_cipher mtc(time(NULL) - time_offset);
        byte_array * encrypted_token = mtc.encrypt(plaintext_token);
        free_byte_array(plaintext_token);
        return encrypted_token;
    }
};

bool is_hex_char(uint8_t byte) {
    return ('0' <= byte && byte <= '9') || ('A' <= byte && byte <= 'F');
}

/* Check whether this is valid token seeded in last little while. (default 5 minutes)
 * Returns true if valid, false if not. If valid and seed_p is not NULL, also writes
 * value of seed there.
 */
bool crack_time_token(uint32_t * seed_p, const byte_array * token, uint32_t seconds_ago = 300) {
    time_t now = time(NULL);
    uint32_t seed_guess = now - seconds_ago;
    cryptopals::mt19937 mt(seed_guess);

    while (seed_guess <= now) {
        size_t idx = 0;
        while (idx < token->len && is_hex_char((uint8_t) mt.rand() ^ token->bytes[idx])) {
            ++idx;
        }
        if (idx == token->len) {
            if (seed_p) {
                *seed_p = seed_guess;
            }
            return true;
        }
        mt.srand(++seed_guess);
    }
    return false;
}

int main(int argc, char ** argv) {
    // just used for random hex bytes in token
    // encryption seed is based on clock
    uint32_t token_seed;
    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " seed" << std::endl;
        std::cout << "Break MT19937 stream cipher: password reset token" << std::endl;
        return 1;
    } else {
        std::istringstream ss(argv[1]);
        if (!(ss >> token_seed)) {
            std::cerr << "Invalid number: " << argv[1] << std::endl;
            return 1;
        }
    }

    std::cout << "Testing three tokens. First two should be good, last one not." << std::endl;
    int32_t time_offsets[] = {0, 237, 2995};
    int num_tokens = sizeof(time_offsets)/sizeof(int32_t);
    token_generator t_gen(token_seed);

    for (int token_idx = 0 ; token_idx < num_tokens ; ++token_idx) {
        byte_array * token = t_gen.generate(time_offsets[token_idx]);

        uint32_t recovered_seed;
        if (crack_time_token(&recovered_seed, token)) {
            std::cout << "Token is valid! Seed = " << recovered_seed << std::endl;
            assert(token_idx <= 1);
        } else {
            std::cout << "Invalid token!" << std::endl;
            assert(token_idx == 2);
        }
        free_byte_array(token);
    }
    std::cout << "All tests pass!" << std::endl;
    return 0;
}
