#include <iostream>
#include <iomanip>
#include <sstream>
#include <random>
#include <cassert>
#include "cryptopals_mersenne.h"

int main(int argc, char ** argv) {
    int seed;
    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " seed" << std::endl;
        std::cout << "Check mersenne twister implementation against C++ standard library" << std::endl;
        return 1;
    } else {
        std::istringstream ss(argv[1]);
        if (!(ss >> seed)) {
            std::cerr << "Invalid number: " << argv[1] << std::endl;
            return 1;
        }
    }

    std::mt19937 mt_std(seed); // C++ implementation
    cryptopals::mt19937 mt(seed);        // our implementation

    for (int x = 0 ; x < 24 ; ++x) {
        uint32_t output = mt.rand();
        assert(mt_std() == output);
        std::cout << std::setw(10) << output << "\t";
        if (x % 8 == 7) std::cout << std::endl;
    }
    std::cout << std::endl << "Values of C++ standard MT19937 implementation and ours agree!" << std::endl;

    return 0;
}
