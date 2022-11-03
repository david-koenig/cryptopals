#pragma once
extern "C" {
#include "cryptopals_random.h"
}
#include <map>
#include <string>

// print all elements of a map
void print_map(const std::map<std::string, std::string> & m);

// convert byte_array to C++ string
std::string bytes_to_string(const byte_array ba);

// Use init_random_encrypt(seed) before calling these functions and cleanup_random_encrypt() after

// provide an email address and get an encrypted profile back
byte_array generate_encrypted_profile(const std::string & email);

// decrypt encrypted profile, returns cryptopals_profile.object (map)
std::map<std::string, std::string> decrypt_profile(const byte_array cipher);
