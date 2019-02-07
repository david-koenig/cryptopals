#include "cryptopals_uri.h"
#include <sstream>
#include <iomanip>
#include <iostream>

std::string RESERVED_CHARS("!#$%&'()*+,/:;=?@[]");

std::string uri_encode(std::string s) {
    size_t pos = 0;
    while (std::string::npos != (pos = s.find_first_of(RESERVED_CHARS, pos))) {
        int c = (int) s[pos];
        std::ostringstream ss;
        ss << '%' << std::hex << std::uppercase << c;
        s.replace(pos, 1, ss.str());
        pos += 3;
    }
    return s;
}

std::string uri_decode(std::string s) {
    size_t pos = 0;
    while (std::string::npos != (pos = s.find('%', pos))) {
        std::istringstream ss(s.substr(pos+1,2));
        int c;
        ss >> std::hex >> c;
        s.replace(pos, 3, 1, (char) c);
        ++pos;
    }
    return s;
}

byte_array * uri_encrypt(std::string & userdata, byte_array * (*enc)(const byte_array *)) {
    std::string s = uri_encode(userdata);
    s.insert(0, "comment1=cooking%20MCs;userdata=");
    s += ";comment2=%20like%20a%20pound%20of%20bacon";
    byte_array * plain = cstring_to_bytes(s.c_str());
    byte_array * cipher = enc(plain);
    free_byte_array(plain);
    return cipher;
}

bool uri_decrypt(byte_array * cipher, byte_array * (*dec)(const byte_array *)) {
    byte_array * plain = dec(cipher);
    print_byte_array_ascii_blocks(plain, 16, ' ');
    std::string s = bytes_to_string(plain);
    free_byte_array(plain);
    return std::string::npos != s.find(";admin=true;");
}

byte_array * uri_encrypt_cbc(std::string & userdata) {
    return uri_encrypt(userdata, encrypt_cbc_mystery_key);
}

bool uri_decrypt_cbc(byte_array * cipher) {
    return uri_decrypt(cipher, decrypt_cbc_mystery_key);
}

byte_array * uri_encrypt_cbc_matching_iv(std::string & userdata) {
    return uri_encrypt(userdata, encrypt_cbc_mystery_key_matching_iv);
}

byte_array * uri_decrypt_cbc_matching_iv(byte_array * cipher) {
    return decrypt_cbc_mystery_key_matching_iv(cipher);
}

byte_array * uri_encrypt_ctr(std::string & userdata) {
    return uri_encrypt(userdata, encrypt_ctr_mystery_key);
}

bool uri_decrypt_ctr(byte_array * cipher) {
    return uri_decrypt(cipher, decrypt_ctr_mystery_key);
}
