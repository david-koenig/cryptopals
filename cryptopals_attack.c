#include "cryptopals_attack.h"
#include <string.h>
#include <stdio.h>

const size_t MAX_PLAIN_LEN = 1024;

bool find_block_size(size_t * block_size_p, size_t * unknown_len_p, uint8_t fill_c, byte_array (*encrypt)(const byte_array)) {
    size_t plain_len = 0;
    size_t last_cipher_len = 0;
    size_t cipher_len = 0;
    while (plain_len < 2 || cipher_len == last_cipher_len) {
        last_cipher_len = cipher_len;
        byte_array plain = alloc_byte_array(plain_len);
        set_all_bytes(plain, fill_c);
        byte_array cipher = encrypt(plain);
        cipher_len = cipher.len;
        printf("%s: encryption using fill of '%c': input len = %li, output len = %li\n", __func__, fill_c, plain_len, cipher_len);
        free_byte_array(plain);
        free_byte_array(cipher);
        ++plain_len;
        if (plain_len > MAX_PLAIN_LEN) {
            printf("%s: no change in cipher length up to %li characters. test failed\n", __func__, MAX_PLAIN_LEN);
            return false;
        }
    }
    --plain_len;
    *block_size_p = cipher_len - last_cipher_len;
    printf("%s: block size = %li - %li = %li\n", __func__, cipher_len, last_cipher_len, *block_size_p);
    *unknown_len_p = last_cipher_len - plain_len;
    printf("%s: unknown len = %li - %li = %li (may include bytes before and after)\n\n", __func__, last_cipher_len, plain_len, *unknown_len_p);
    return true;
}

bool recover_bytes(size_t target_len, uint8_t fill_c, size_t unused_len, size_t block_size, size_t matching_block_idx, byte_array (*encrypt)(const byte_array)) {
    byte_array recovered_target = alloc_byte_array(target_len);
    byte_array spoof = alloc_byte_array(unused_len + block_size);
    set_all_bytes(spoof, fill_c);

    size_t target_idx;
    for (target_idx = 0 ; target_idx < recovered_target.len; ++target_idx) {
        shift_down(spoof);
        byte_array plain = alloc_byte_array(unused_len + block_size - 1 - target_idx % block_size);
        set_all_bytes(plain, fill_c); // this only matters for the first block worth of recoveries
        byte_array cipher = encrypt(plain);

        if (!recover_byte(cipher, matching_block_idx + target_idx / block_size, spoof, matching_block_idx, block_size, encrypt)) {
            printf("%s: Unable to recover byte %li!\n", __func__, target_idx);
            free_byte_array(plain);
            free_byte_array(cipher);
            free_byte_array(spoof);
            free_byte_array(recovered_target);
            return false;
        }
        recovered_target.bytes[target_idx] = spoof.bytes[spoof.len - 1];
        free_byte_array(plain);
        free_byte_array(cipher);
    }
    printf("%s: Recovered target string:\n", __func__);
    print_byte_array_ascii(recovered_target);
    free_byte_array(spoof);
    free_byte_array(recovered_target);
    return true;
}

bool recover_byte(const byte_array cipher, size_t cipher_block_num, byte_array spoof, size_t spoof_block_num, size_t block_size, byte_array (*encrypt)(const byte_array)) {
    uint8_t byte = 0;
    do {
        spoof.bytes[spoof.len - 1] = byte;
        byte_array spoof_cipher = encrypt(spoof);
        if (0 == memcmp(cipher.bytes + block_size * cipher_block_num, spoof_cipher.bytes + block_size * spoof_block_num, block_size)) {
            free_byte_array(spoof_cipher);
            return true;
        }
        free_byte_array(spoof_cipher);
    } while (++byte);
    return false;
}

void shift_down(byte_array ba) {
    memmove(ba.bytes, ba.bytes+1, ba.len-1);
}
