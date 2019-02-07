#include "cryptopals_mersenne.h"

// implementation of MT19937 for 32 bit integers

cryptopals::mt19937::mt19937(uint32_t seed) { srand(seed); }
cryptopals::mt19937::mt19937(uint32_t seed[N]) { for (int idx = 0 ; idx < N ; ++idx) { state[idx] = seed[idx]; }}

void cryptopals::mt19937::srand(uint32_t seed) {
    const uint32_t f = 1812433253;  // multiplicative constant for initialization
    state[0] = seed;
    for (int idx = 1 ; idx < N ; ++idx) {
        // This is current standard initialization method, compatible with std::mt19937 in C++11 and later
        state[idx] = f * (state[idx-1] ^ (state[idx-1] >> 30)) + idx;

        // This method was used in original implementation, and cannot use a zero seed.
        // http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/VERSIONS/C-LANG/980409/mt19937int.c
        // They are not compatible. I put it here because I was checking my code against the original implementation.
        //state[idx] = 69069 * state[idx-1];
    }
}

uint32_t cryptopals::mt19937::rand() {
    step_state();
    return temper(state[N-1]);
}

uint32_t cryptopals::mt19937::right_mult_A(uint32_t x) {
    const uint32_t a = 0x9908B0DF;
    return (x >> 1) ^ (x & 1 ? a : 0);
}

uint32_t cryptopals::mt19937::next_state() {
    const uint32_t m = 397; // middle word
    return right_mult_A((state[0] & (1 << 31)) | (state[1] & ~(1 << 31))) ^ state[m];
}

void cryptopals::mt19937::step_state() {
    uint32_t new_state = next_state();
    for (int idx = 0 ; idx < N - 1 ; ++idx) {
        state[idx] = state[idx + 1];
    }
    state[N - 1] = new_state;
}

uint32_t cryptopals::mt19937::temper(uint32_t x) {
    const uint32_t b = 0x9D2C5680;
    const uint32_t c = 0xEFC60000;
    x ^= x >> 11;
    x ^= (x << 7) & b;
    x ^= (x << 15) & c;
    x ^= x >> 18;
    return x;
}

byte_array * cryptopals::mt19937_cipher::encrypt_decrypt(const byte_array * input) {
    byte_array * output = alloc_byte_array(input->len);
    cryptopals::mt19937 mt(seed);
    for (size_t idx = 0 ; idx < input->len ; ++idx) {
        /* just using low byte of random output for each key stream byte */
        output->bytes[idx] = (uint8_t) mt.rand();
    }
    xor_byte_arrays(output, output, input);
    return output;
}

byte_array * cryptopals::mt19937_cipher::encrypt(const byte_array * plain) {
    return encrypt_decrypt(plain);
}

byte_array * cryptopals::mt19937_cipher::decrypt(const byte_array * cipher) {
    return encrypt_decrypt(cipher);
}
