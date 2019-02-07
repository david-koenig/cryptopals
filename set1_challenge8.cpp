#include <iostream>
#include <fstream>
#include <string>
#include <map>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " filename" << std::endl
                  << "Test all lines of file for AES-128 ECB. Use 8.txt"
                  << std::endl;
        return 1;
    }
    std::ifstream f;
    f.open(argv[1]);
    if (!f) {
        std::cerr << "Unable to open " << argv[1] << std::endl;
        return 1;
    }

    std::string line;
    size_t block_width = 32; // 32 hex characters = 16 bytes = 128 bits (block size of AES-128)
    while (std::getline(f, line)) {
        std::map<std::string, int> block_frequency;
        size_t len = line.size();
        size_t block_count = len/block_width;
        for (size_t idx = 0; idx + block_width <= len; idx += block_width) {
            ++block_frequency[line.substr(idx, block_width)];
        }
        if (block_frequency.size() < block_count) {
            std::cout << "Cipher with repeated blocks found: " << line << std::endl << std::endl;
            for (auto it = block_frequency.cbegin(); it != block_frequency.cend(); ++it) {
                std::cout << it->first << " : " << it->second << std::endl;
            }
        }
    }

    f.close();
    return 0;
}
