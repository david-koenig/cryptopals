#include "cryptopals_mac.h"
#include "cryptopals_random.h"
#include "sha1.h"
#include "md4.h"
#include <stdlib.h>
#include <stdio.h>

static void check_err(int err) {
    if (err) {
        fprintf(stderr, "SHA1 error: %d\n", err);
        exit(1);
    }
}

static byte_array mac_key;

void init_random_mac_key(int seed) {
    init_random_encrypt(seed);
    mac_key = random_byte_array();
}

void cleanup_random_mac_key() {
    free_byte_array(mac_key);
    cleanup_random_encrypt();
}

byte_array sha1_mac(const byte_array message) {
    SHA1Context sha;
    check_err(SHA1Reset(&sha));
    check_err(SHA1Input(&sha, mac_key.bytes, mac_key.len));
    check_err(SHA1Input(&sha, message.bytes, message.len));
    byte_array mac = alloc_byte_array(20);
    check_err(SHA1Result(&sha, mac.bytes));
    return mac;
}

byte_array md4_mac(const byte_array message) {
    MD4_CTX context;
    MD4Init(&context);
    MD4Update(&context, mac_key.bytes, mac_key.len);
    MD4Update(&context, message.bytes, message.len);
    byte_array mac = alloc_byte_array(16);
    MD4Final(mac.bytes, &context);
    return mac;
}

typedef byte_array secret_mac_fn(const byte_array message);
static bool check_message_mac(const byte_array message, const byte_array mac, secret_mac_fn * mac_fn) {
    byte_array correct_mac = mac_fn(message);
    bool ret = byte_arrays_equal(mac, correct_mac);
    free_byte_array(correct_mac);
    return ret;
}

bool check_message_sha1_mac(const byte_array message, const byte_array mac) {
    return check_message_mac(message, mac, sha1_mac);
}

bool check_message_md4_mac(const byte_array message, const byte_array mac) {
    return check_message_mac(message, mac, md4_mac);
}

static void uint64_to_bytes_big_endian(uint8_t * out, uint64_t x) {
    size_t idx;
    for (idx = 0; idx < 8; ++idx) {
        out[idx] = (uint8_t)(x >> (56 - 8 * idx));
    }
}
static void uint64_to_bytes_little_endian(uint8_t * out, uint64_t x) {
    *(uint64_t *)out = x;
}

typedef void uint64_to_bytes_fn(uint8_t * out, uint64_t len);
static byte_array sha_md_pad(uint64_t len_in_bytes, uint64_to_bytes_fn * pad_with_len) {
    size_t padding_len = 64 - (len_in_bytes % 64);
    if (padding_len <= 8) padding_len += 64;

    byte_array padding;
    padding = alloc_byte_array(padding_len);
    padding.bytes[0] = 0x80;
    // pad with message length in BITS
    pad_with_len(padding.bytes + (padding_len - 8), len_in_bytes * 8);
    return padding;
}

byte_array sha1_pad(uint64_t len_in_bytes) {
    return sha_md_pad(len_in_bytes, uint64_to_bytes_big_endian);
}

byte_array md4_pad(uint64_t len_in_bytes) {
    return sha_md_pad(len_in_bytes, uint64_to_bytes_little_endian);
}
