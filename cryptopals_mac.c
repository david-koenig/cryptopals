#include "cryptopals_mac.h"
#include "cryptopals_random.h"
#include "sha1.h"
#include <stdlib.h>
#include <stdio.h>

static void check_err(int err) {
    if (err) {
        fprintf(stderr, "SHA1 error: %d\n", err);
        exit(1);
    }
}

static byte_array * mac_key;

void init_random_mac_key(int seed) {
    init_random_encrypt(seed);
    mac_key = random_byte_array();
}

void cleanup_random_mac_key() {
    free_byte_array(mac_key);
    cleanup_random_encrypt();
}

byte_array * sha1_mac(const byte_array * message) {
    SHA1Context sha;
    check_err(SHA1Reset(&sha));
    check_err(SHA1Input(&sha, mac_key->bytes, mac_key->len));
    check_err(SHA1Input(&sha, message->bytes, message->len));
    byte_array * mac = alloc_byte_array(20);
    check_err(SHA1Result(&sha, mac->bytes));
    return mac;
}

bool check_message_sha1_mac(const byte_array * message, const byte_array * mac) {
    byte_array * correct_mac = sha1_mac(message);
    bool ret = byte_arrays_equal(mac, correct_mac);
    free_byte_array(correct_mac);
    return ret;
}

static void uint64_to_bytes_big_endian(uint8_t * out, uint64_t x) {
    size_t idx;
    for (idx = 0; idx < 8; ++idx) {
        out[idx] = (uint8_t)(x >> (56 - 8 * idx));
    }
}

byte_array * sha1_pad(uint64_t len_in_bytes) {
    size_t padding_len = 64 - (len_in_bytes % 64);
    if (padding_len <= 8) padding_len += 64;

    byte_array * padding;
    padding = alloc_byte_array(padding_len);
    padding->bytes[0] = 0x80;
    // pad with message length in BITS
    uint64_to_bytes_big_endian(padding->bytes + (padding_len - 8), len_in_bytes * 8);
    return padding;
}
