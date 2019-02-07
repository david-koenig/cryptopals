#include "cryptopals_uri.h"
#include <sstream>
#include <iostream>

void test_cipher(byte_array * cipher) {
    if (uri_decrypt_cbc(cipher)) {
        std::cout << "Admin access granted!" << std::endl;
    } else {
        std::cout << "Denied!!!" << std::endl;
    }
}

int main(int argc, char ** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " seed" << std::endl;
        std::cerr << "CBC bitflipping attack" << std::endl;
        return 1;
    }
    std::istringstream ss(argv[1]);
    int seed;
    if (!(ss >> seed)) {
        std::cerr << "Invalid number: " << argv[1] << std::endl;
        return 1;
    }
    init_random_encrypt(seed);

    std::string s("3admin5true");

    byte_array * cipher = uri_encrypt_cbc(s);

    test_cipher(cipher);

    std::cout << "Manipulating a few bits in the cipher before attempting decryption again..." << std::endl;

    cipher->bytes[16] ^= '3' ^ ';';
    cipher->bytes[22] ^= '5' ^ '=';

    test_cipher(cipher);

    free_byte_array(cipher);
    cleanup_random_encrypt();
    return 0;
}
