#include "cryptopals_profile.h"
#include <iostream>

std::map<std::string, std::string> parse_kv_string(const std::string & kv) {
    size_t start = 0;
    size_t end = 0;
    std::map<std::string, std::string> m;
    while (end != std::string::npos) {
        if (end)
            start = end + 1;
        end = kv.find('&', start);
        auto pair = kv.substr(start, end-start);
        size_t pivot = pair.find('=');
        if (pivot == std::string::npos || pivot != pair.rfind('=')) {
            std::cerr << "Malformed string " << kv << std::endl;
            exit(1);
        }
        m[pair.substr(0, pivot)] = pair.substr(pivot+1);
    }
    return m;
}

std::string encode_kv_as_string(const std::map<std::string, std::string> & m) {
    std::string kv;
    for (auto it = m.cbegin(); it != m.cend(); ++it) {
        kv += it->first + '=' + it->second + '&';
    }
    kv.erase(kv.size()-1);
    return kv;
}

std::string profile_for(const std::string & email) {
    size_t at_sign_idx = email.find('@');
    if (at_sign_idx == std::string::npos ||
        at_sign_idx != email.rfind('@') ||
        email.find_first_of("&=") != std::string::npos) {
        std::cerr << "Malformed email" << std::endl;
        exit(1);
    }
    std::string p("email=");
    p += email + "&uid=10&role=user";
    return p;
}

void print_map(const std::map<std::string, std::string> & m) {
    for (auto it = m.cbegin(); it != m.cend(); ++it) {
        std::cout << it->first << " : " << it->second << std::endl;
    }
}

std::string bytes_to_string(const byte_array * ba) {
    std::string s;
    for (size_t idx = 0 ; idx < ba->len ; ++idx) {
        s += ba->bytes[idx];
    }
    return s;
}

byte_array * generate_encrypted_profile(const std::string & email) {
    std::string profile = profile_for(email);
    byte_array * plain = cstring_to_bytes(profile.c_str());
    byte_array * cipher = encrypt_ecb_mystery_key(plain);
    free_byte_array(plain);
    return cipher;
}

std::map<std::string, std::string> decrypt_profile(const byte_array * cipher) {
    byte_array * plain = decrypt_ecb_mystery_key(cipher);
    std::string profile = bytes_to_string(plain);
    free_byte_array(plain);
    return parse_kv_string(profile);
}
