#include "cryptopals_mersenne.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cassert>

// inverse of cryptopals::mt19937::temper

uint32_t untemper(uint32_t x) {
    const uint32_t b = 0x9D2C5680;
    const uint32_t c = 0xEFC60000;
    uint32_t mask;
    // inverse of x ^= x >> 18
    x ^= x >> 18;
    // inverse of x ^= (x << 15) & c
    mask = 0x00007fff;
    x ^= ((x & mask) << 15) & c;
    x ^= ((x & ~mask) << 15) & c;
    // inverse of x ^= (x << 7) & b
    mask = 0x0000007f;
    x ^= ((x & mask) << 7) & b;
    x ^= ((x & (mask << 7)) << 7) & b;
    x ^= ((x & (mask << 14)) << 7) & b;
    x ^= ((x & (mask << 21)) << 7) & b;
    // inverse of x ^= x >> 11
    mask = 0xffe00000;
    x ^= (x & mask) >> 11;
    x ^= (x & ~mask) >> 11;
    return x;
}

int main(int argc, char ** argv) {
    uint32_t seed;
    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " seed" << std::endl;
        std::cout << "Clone mersenne twister from its outputs" << std::endl;
        return 1;
    } else {
        std::istringstream ss(argv[1]);
        if (!(ss >> seed)) {
            std::cerr << "Invalid number: " << argv[1] << std::endl;
            return 1;
        }
    }

    cryptopals::mt19937 mt(seed);
    seed = 0; // just to prove we are not using it

    uint32_t output[N];
    for (int idx = 0 ; idx < N ; ++idx) {
        output[idx] = untemper(mt.rand());
    }

    // This uses the alternate constructor which sets the state
    // array to have the same values as the input array.
    cryptopals::mt19937 mt_clone(output);

    for (int idx = 0 ; idx < 1000 ; ++idx) {
        assert(mt.rand() == mt_clone.rand());
    }
    std::cout << "Original RNG and clone have same outputs!" << std::endl;

    return 0;
}
