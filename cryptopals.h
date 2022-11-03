#pragma once
#include "cryptopals_utils.h"

// Test cipher for single byte xor encryption, printing all high scoring candidates to stdout
void score_single_byte_xor(const byte_array cipher, bool print_plain);

// Apply XOR of repeating key to byte array ba (allocates new byte array for result)
byte_array repeating_byte_xor(const byte_array ba, const byte_array repeating_key);

// Run these before and after attempting any OpenSSL crypto operations
void init_openssl();
void cleanup_openssl();

// Create a new byte array which is ba with PKCS#7 padding.
// Rounds length of byte array up to multiple of block_size and pads with bytes
// with value equal to number of padding bytes.
byte_array pkcs7_padding(const byte_array ba, size_t block_size);

// Create a new byte array which is ba without the PKCS#7 padding.
byte_array remove_pkcs7_padding(const byte_array ba);

// Decrypt using AES-128 ECB mode. Allocates byte array for result.
byte_array decrypt_aes_128_ecb(const byte_array cipher, const byte_array key);

// Encrypt using AES-128 ECB mode. Allocates byte array for result.
byte_array encrypt_aes_128_ecb(const byte_array plaintext, const byte_array key);

// Decrypt using AES-128 CBC mode. Allocates byte array for result.
byte_array decrypt_aes_128_cbc(const byte_array cipher, const byte_array key, const byte_array iv);

// Encrypt using AES-128 CBC mode. Allocates byte array for result.
byte_array encrypt_aes_128_cbc(const byte_array plaintext, const byte_array key, const byte_array iv);

// Decrypt using AES-128 CTR mode. Allocates byte array for result.
byte_array decrypt_aes_128_ctr(const byte_array cipher, const byte_array key, uint64_t nonce);

// Encrypt using AES-128 CTR mode. Allocates byte array for result.
byte_array encrypt_aes_128_ctr(const byte_array plain, const byte_array key, uint64_t nonce);

// Starting at byte offset, replace plain by new_plain for entire length of new_plain array and reencrypt.
byte_array edit_ciphertext_aes_128_ctr(const byte_array cipher, const byte_array key, uint64_t nonce, size_t offset, byte_array new_plain);
