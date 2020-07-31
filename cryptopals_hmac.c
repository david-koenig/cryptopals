#include "cryptopals_hmac.h"
#include "cryptopals_sha256.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

// SHA256 has a block size of 512 bits = 64 bytes, which is the size of
// the chunks of input that it reads internally. It has an output size
// of 256 bits = 32 bytes, which is often mistakenly called the block size.
// The block size referred to in the definition of HMAC refers to the
// input block size, *not* to the output size.
#define SHA256_BLOCK_SIZE 64

// In the future can make these arrays as long as the highest
// block size of all hash functions used in this file, and
// define byte_arrays of appropriate size for each hash function.
static uint8_t opad_bytes[] =
    {0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
     0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
     0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
     0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
     0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
     0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
     0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
     0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c};

static uint8_t ipad_bytes[] =
    {0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
     0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
     0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
     0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
     0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
     0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
     0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
     0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36};

static const byte_array sha256_opad = {opad_bytes, SHA256_BLOCK_SIZE};
static const byte_array sha256_ipad = {ipad_bytes, SHA256_BLOCK_SIZE};

// HMAC(K,m) = H( (K' ^ opad) | H((K' ^ ipad) | m) )
byte_array * sha256_hmac(const byte_array * key, const byte_array * message) {
    byte_array * k_prime = NULL;
    const byte_array * my_key;
    if (key->len == SHA256_BLOCK_SIZE) {
        my_key = key;
    } else if (key->len < SHA256_BLOCK_SIZE) {
        // Here k_prime is key padded by zero bytes to SHA256 input block size
        k_prime = alloc_byte_array(SHA256_BLOCK_SIZE);
        memcpy(k_prime->bytes, key->bytes, key->len);
        my_key = k_prime;
    } else {
        k_prime = sha256_byte_array_zero_pad(key, SHA256_BLOCK_SIZE);
        my_key = k_prime;
    }

    byte_array * k_xor_ipad = xor_byte_arrays(NULL, my_key, &sha256_ipad);
    byte_array * inner_hash_out = sha256_2_byte_arrays(k_xor_ipad, message);

    byte_array * k_xor_opad = xor_byte_arrays(NULL, my_key, &sha256_opad);
    byte_array * outer_hash_out = sha256_2_byte_arrays(k_xor_opad, inner_hash_out);
    
    free_byte_array(k_prime);
    free_byte_array(k_xor_ipad);
    free_byte_array(inner_hash_out);
    free_byte_array(k_xor_opad);

    return outer_hash_out;
}

void test_sha256_hmac() {
    byte_array * key1 = cstring_to_bytes("key");
    byte_array * message1 = cstring_to_bytes("The quick brown fox jumps over the lazy dog");
    byte_array * hmac_answer1 = hex_to_bytes("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");

    byte_array * key2 = cstring_to_bytes("Jefe");
    byte_array * message2 = cstring_to_bytes("what do ya want for nothing?");
    byte_array * hmac_answer2 = hex_to_bytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    byte_array * key3 = alloc_byte_array(131);
    for (int i = 0; i < 131; ++i) {
        key3->bytes[i] = 0xaa;
    }
    byte_array * message3 = cstring_to_bytes("This is a test using a larger than block-size key and a larger t"
                                             "han block-size data. The key needs to be hashed before being use"
                                             "d by the HMAC algorithm.");
    byte_array *hmac_answer3 = hex_to_bytes("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");

    byte_array * hmac1 = sha256_hmac(key1, message1);
    byte_array * hmac2 = sha256_hmac(key2, message2);
    byte_array * hmac3 = sha256_hmac(key3, message3);

    assert(byte_arrays_equal(hmac1, hmac_answer1));
    assert(byte_arrays_equal(hmac2, hmac_answer2));
    assert(byte_arrays_equal(hmac3, hmac_answer3));
    printf("SHA256-HMAC tests pass!\n");

    free_byte_array(key1);
    free_byte_array(message1);
    free_byte_array(hmac_answer1);
    free_byte_array(hmac1);
    free_byte_array(key2);
    free_byte_array(message2);
    free_byte_array(hmac_answer2);
    free_byte_array(hmac2);
    free_byte_array(key3);
    free_byte_array(message3);
    free_byte_array(hmac_answer3);
    free_byte_array(hmac3);
}
