#pragma once
#include "cryptopals.h"

// Run these before and after using any of the other functions below. Just need to give random seed.
// Includes calls to OpenSSL setup & cleanup functions.
void init_random_encrypt(int seed);
void cleanup_random_encrypt();

// Allocate a 16 byte array filled with random bits, suitable for AES-128 key or IV
byte_array * random_128_bits();

// Allocate a random byte array of random length up to RANDOM_BYTE_ARRAY_MAX_LEN defined in cryptopals_random.c
byte_array * random_byte_array();

// Randomly encrypt with AES-128 ECB or CBC.
// Different key and IV are used every time this is called.
// Include 5-10 random bytes at beginning and end of plaintext.
byte_array * random_encrypt(const byte_array * plain);

// Mystery encryption with a random key of the plaintext appended with unknown string.
// Random key is set once when init_random_encrypt is called.
byte_array * mystery_encrypt(const byte_array * plain);

// Same as mystery encrypt but with random number of random bits prepended to plain.
byte_array * harder_mystery_encrypt(const byte_array * plain);

// These do a straightforward AES-128 encryption and decryption to unmodified plaintext using the mystery key.
// The attacker does not have access to them. They are just helper functions for the C++ code
// to use the random encryption feature in challenges 13 and 16.
byte_array * encrypt_ecb_mystery_key(const byte_array * plain);
byte_array * decrypt_ecb_mystery_key(const byte_array * cipher);
byte_array * encrypt_cbc_mystery_key(const byte_array * plain);
byte_array * decrypt_cbc_mystery_key(const byte_array * cipher);
byte_array * encrypt_ctr_mystery_key(const byte_array * plain);
byte_array * decrypt_ctr_mystery_key(const byte_array * cipher);

// Uses same key and IV
byte_array * encrypt_cbc_mystery_key_matching_iv(const byte_array * plain);
byte_array * decrypt_cbc_mystery_key_matching_iv(const byte_array * cipher);


// Same as edit_ciphertext_aes_128_ctr using the mystery key.
byte_array * edit_ciphertext_ctr_mystery_key(const byte_array * cipher, size_t offset, byte_array * new_plain);

// Allocates a byte array to hold a 128 bit IV and puts the address at the value pointed to by iv_p
// AES-128 CBC encrypts one of the hidden strings, randomly selected and returns byte array holding cipher.
// iv_p should not point to a previously allocated byte array. This call allocates two new byte arrays.
byte_array * padding_oracle_encrypt(byte_array ** iv_p);

// AES-128 CBC decrypts cipher and returns true if decryption has valid PKCS#7 padding, false otherwise
// Inputs are cipher and IV output by padding_oracle_encrypt. Uses secret AES key.
bool padding_oracle_decrypt(const byte_array * cipher, const byte_array * my_iv);

// Return true if guess is the same as the secret key
bool guess_key(const byte_array * guess);

// These encryption and decryption functions are used in Diffie-Hellman problems in set 5.
// Encrypt function generates a random IV and then prepends the IV to the message.
// Decrypt function expects encryption in this format with prepended IV.
byte_array * encrypt_aes_128_cbc_prepend_iv(const byte_array * plaintext, const byte_array * key);
byte_array * decrypt_aes_128_cbc_prepend_iv(const byte_array * cipher, const byte_array * key);
