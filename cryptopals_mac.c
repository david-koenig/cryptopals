#include "cryptopals_mac.h"
#include "sha1.h"
#include <stdlib.h>
#include <stdio.h>

void check_err(int err) {
    if (err) {
        fprintf(stderr, "SHA1 error: %d\n", err);
        exit(1);
    }
}

byte_array * sha1_mac(const byte_array * key, const byte_array * message) {
    SHA1Context sha;
    check_err(SHA1Reset(&sha));
    check_err(SHA1Input(&sha, key->bytes, key->len));
    check_err(SHA1Input(&sha, message->bytes, message->len));
    byte_array * mac = alloc_byte_array(20);
    check_err(SHA1Result(&sha, mac->bytes));
    return mac;
}

void uint64_to_bytes_big_endian(uint8_t * out, uint64_t x) {
    size_t idx;
    for (idx = 0; idx < 8; ++idx) {
        out[idx] = (uint8_t)(x >> (56 - 8 * idx));
    }
}

byte_array * sha1_pad(const byte_array * msg) {
    uint64_t msg_len = msg->len;
    size_t padding_len = 64 - (msg_len % 64);
    if (padding_len <= 8) padding_len += 64;

    byte_array * padding;
    padding = alloc_byte_array(padding_len);
    padding->bytes[0] = 0x80;
    // pad with message length in BITS
    uint64_to_bytes_big_endian(padding->bytes + (padding_len - 8), msg_len * 8);
    byte_array * padded_msg = append_byte_arrays(msg, padding);
    free_byte_array(padding);
    return padded_msg;
}
