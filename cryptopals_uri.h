#pragma once
#include <string>
#include "cryptopals_profile.h"

// Use init_random_encrypt(seed) before calling these functions and cleanup_random_encrypt() after

// CBC encrypt "comment1=cooking%20MCs;userdata=" + userdata + ";comment2=%20like%20a%20pound%20of%20bacon"
byte_array uri_encrypt_cbc(std::string & userdata);
byte_array uri_encrypt_ctr(std::string & userdata);
byte_array uri_encrypt_cbc_matching_iv(std::string & userdata); // key = IV

// Decrypt cipher from function above and return true if ";admin=true;" included in plain
bool uri_decrypt_cbc(byte_array cipher);
bool uri_decrypt_ctr(byte_array cipher);

byte_array uri_decrypt_cbc_matching_iv(byte_array cipher);
