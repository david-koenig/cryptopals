#include "cryptopals_uri.h"
#include <sstream>
#include <iostream>

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

    byte_array * cipher = uri_encrypt_cbc_matching_iv(s);

    byte_array * cipher_1 = sub_byte_array(cipher, 0, 16);
    byte_array * zero_block = alloc_byte_array(16);

    // need to end in full cipher in order to pass PKCS#7 padding check
    byte_array * spoof_cipher = append_three_byte_arrays(cipher_1, zero_block, cipher);

    byte_array * spoof_decrypt = uri_decrypt_cbc_matching_iv(spoof_cipher);
    byte_array * plain_1 = sub_byte_array(spoof_decrypt, 0, 16);
    byte_array * plain_3 = sub_byte_array(spoof_decrypt, 32, 48);
    byte_array * key = xor_byte_arrays(NULL, plain_1, plain_3);

    printf("%s the key!\n", guess_key(key) ? "Cracked" : "Did not crack");

    free_byte_array(cipher);
    free_byte_array(cipher_1);
    free_byte_array(zero_block);
    free_byte_array(spoof_cipher);
    free_byte_array(spoof_decrypt);
    free_byte_array(plain_1);
    free_byte_array(plain_3);
    free_byte_array(key);

    cleanup_random_encrypt();
    return 0;
}
