#pragma once
extern "C" {
#include "cryptopals_utils.h"
}

#define N 624 // size of state array = degree of recurrence

namespace cryptopals {
    class mt19937 {
    public:
        // Initializes state array from seed.
        mt19937(uint32_t seed);

        // Alternate constructor: set entire state array.
        mt19937(uint32_t seed[N]);

        // Does the same thing as the first constructor, but by making
        // this a public method, we can reinitialize the same object.
        void srand(uint32_t seed);

        // Get a random value.
        uint32_t rand();

    private:
        uint32_t state[N];
        uint32_t next_state();
        void step_state();
        static uint32_t right_mult_A(uint32_t x);
        static uint32_t temper(uint32_t x);
    };

    // A bad stream cipher implemented naively from the RNG
    class mt19937_cipher {
    public:
        mt19937_cipher(uint32_t s) : seed(s) {}
        byte_array encrypt(const byte_array plain);
        byte_array decrypt(const byte_array cipher);

    private:
        uint32_t seed;
        byte_array encrypt_decrypt(const byte_array input);
    };
}
