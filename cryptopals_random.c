#include "cryptopals_random.h"
#include <stdio.h>
#include <stdlib.h>

const size_t RANDOM_BYTE_ARRAY_MAX_LEN = 100;

byte_array key;
byte_array iv;
byte_array unknown;
byte_array junk;

char * padding_oracle_base64[] = {
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
};
size_t num_plaintexts = sizeof(padding_oracle_base64)/sizeof(char *);
byte_array* padding_oracle_plaintext;

void init_random_encrypt(int seed) {
    srandom(seed);
    init_openssl();
    key = random_128_bits();
    iv = random_128_bits();
    char * b64_str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                     "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                     "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                     "YnkK";
    unknown = base64_to_bytes(b64_str);
    junk = random_byte_array();

    padding_oracle_plaintext = malloc(num_plaintexts * sizeof(byte_array));
    size_t idx;
    for (idx = 0; idx < num_plaintexts ; ++idx) {
        padding_oracle_plaintext[idx] = base64_to_bytes(padding_oracle_base64[idx]);
    }
}

void cleanup_random_encrypt() {
    size_t idx;
    for (idx = 0; idx < num_plaintexts ; ++idx) {
        free_byte_array(padding_oracle_plaintext[idx]);
    }
    free(padding_oracle_plaintext);
    free_byte_arrays(key, iv, unknown, junk, NO_BA);
    cleanup_openssl();
}

byte_array random_128_bits() {
    byte_array ba = alloc_byte_array(16);
    size_t idx;
    for (idx = 0 ; idx < 8 ; ++idx) {
        uint16_t x = random(); // random only gives 31 random bits
        (( uint16_t *) ba.bytes)[idx] = x;
    }
    return ba;
}

byte_array random_byte_array() {
    size_t len = random() % RANDOM_BYTE_ARRAY_MAX_LEN + 1;
    byte_array ba = alloc_byte_array(len);
    size_t idx;
    for (idx = 0 ; idx < len ; ++idx) {
        ba.bytes[idx] = random();
    }
    return ba;
}

// randomly encrypt with AES-128 ECB or CBC and random key and IV
// include 5-10 random bytes at beginning and end of plaintext
byte_array random_encrypt(const byte_array plain) {
    byte_array key = random_128_bits();

    size_t num_prepended_bytes = random() % 6 + 5;
    byte_array junk = random_128_bits();
    byte_array prepended_bytes = sub_byte_array(junk, 0, num_prepended_bytes);
    free_byte_array(junk);

    size_t num_appended_bytes = random() % 6 + 5;
    junk = random_128_bits();
    byte_array appended_bytes = sub_byte_array(junk, 0, num_appended_bytes);

    byte_array appended_plain = append_three_byte_arrays(prepended_bytes, plain, appended_bytes);
    free_byte_arrays(prepended_bytes, appended_bytes, NO_BA);

    byte_array cipher;
    if (junk.bytes[15]&1) {
        cipher = encrypt_aes_128_ecb(appended_plain, key);
    } else {
        byte_array iv = random_128_bits();
        cipher = encrypt_aes_128_cbc(appended_plain, key, iv);
        free_byte_array(iv);
    }
    free_byte_arrays(junk, key, appended_plain, NO_BA);
    return cipher;
}

byte_array mystery_encrypt(const byte_array plain) {
    byte_array input = append_byte_arrays(plain, unknown);
    byte_array cipher = encrypt_aes_128_ecb(input, key);
    free_byte_array(input);
    return cipher;
}

byte_array harder_mystery_encrypt(const byte_array plain) {
    byte_array prepended_plain = append_byte_arrays(junk, plain);
    byte_array cipher = mystery_encrypt(prepended_plain);
    free_byte_array(prepended_plain);
    return cipher;
}

byte_array encrypt_ecb_mystery_key(const byte_array plain) {
    return encrypt_aes_128_ecb(plain, key);
}

byte_array decrypt_ecb_mystery_key(const byte_array cipher) {
    return decrypt_aes_128_ecb(cipher, key);
}

byte_array encrypt_cbc_mystery_key(const byte_array plain) {
    return encrypt_aes_128_cbc(plain, key, iv);
}

byte_array decrypt_cbc_mystery_key(const byte_array cipher) {
    return decrypt_aes_128_cbc(cipher, key, iv);
}

byte_array encrypt_cbc_mystery_key_matching_iv(const byte_array plain) {
    return encrypt_aes_128_cbc(plain, key, key);
}

byte_array decrypt_cbc_mystery_key_matching_iv(const byte_array cipher) {
    return decrypt_aes_128_cbc(cipher, key, key);
}

byte_array encrypt_ctr_mystery_key(const byte_array plain) {
    return encrypt_aes_128_ctr(plain, key, 0ULL);
}

byte_array decrypt_ctr_mystery_key(const byte_array cipher) {
    return decrypt_aes_128_ctr(cipher, key, 0ULL);
}

byte_array edit_ciphertext_ctr_mystery_key(const byte_array cipher, size_t offset, byte_array new_plain) {
    return edit_ciphertext_aes_128_ctr(cipher, key, 0ULL, offset, new_plain);
}

byte_array padding_oracle_encrypt(byte_array* iv_p) {
    *iv_p = random_128_bits();
    size_t idx = random() % num_plaintexts;
    return encrypt_aes_128_cbc(padding_oracle_plaintext[idx], key, *iv_p);
}

bool padding_oracle_decrypt(const byte_array cipher, const byte_array my_iv) {
    byte_array plain = decrypt_aes_128_cbc(cipher, key, my_iv);
    if (plain.bytes) {
        free_byte_array(plain);
        return true;
    }
    return false;
}

bool guess_key(const byte_array guess) {
    return byte_arrays_equal(key, guess);
}

byte_array encrypt_aes_128_cbc_prepend_iv(const byte_array plaintext, const byte_array key) {
    byte_array iv = random_128_bits();
    byte_array cipher = encrypt_aes_128_cbc(plaintext, key, iv);
    byte_array encryption = append_byte_arrays(iv, cipher);
    free_byte_arrays(iv, cipher, NO_BA);
    return encryption;
}

byte_array decrypt_aes_128_cbc_prepend_iv(const byte_array cipher, const byte_array key) {
    if (cipher.len < 16) {
        fprintf(stderr, "%s: cipher too short\n", __func__);
        exit(1);
    }
    byte_array iv = {cipher.bytes, 16};
    byte_array cipher_without_iv = {cipher.bytes+16, cipher.len-16};
    return decrypt_aes_128_cbc(cipher_without_iv, key, iv);
}
