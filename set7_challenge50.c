#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "cryptopals_cbcmac.h"
#include "cryptopals.h"

int main(int argc, char ** argv) {
    init_openssl();
    size_t block_size = 16;
    byte_array key = cstring_to_bytes("YELLOW SUBMARINE");

    byte_array code = cstring_to_bytes("alert('MZA who was that?');\n");
    byte_array hash = cbc_mac(code, key);
    byte_array ans = hex_to_bytes("296b8d7cb78a243dda4d0a61d33bbdd1");
    assert(byte_arrays_equal(hash, ans));

    // Using 39 characters total so that PKCS7 padding bytes are 0x09 = \t.
    // "//" is how comments are indicated in Javascript.
    byte_array code1 = cstring_to_bytes("alert('Ayo, the Wu is back!');//       ");
    byte_array hash1 = cbc_mac(code1, key);
    byte_array padded_code1 = pkcs7_padding(code1, block_size);
    byte_array xor = xor_byte_arrays(NO_BA, hash1, code);

    byte_array code_minus_first_block = sub_byte_array(code, block_size, code.len);
    byte_array hack = append_three_byte_arrays(padded_code1, xor, code_minus_first_block);

    byte_array hash_hack = cbc_mac(hack, key);
    assert(byte_arrays_equal(hash, hash_hack));

    printf("Original code: ");
    print_byte_array_ascii(code);
    printf("CBC-MAC      : ");
    print_byte_array(hash);
    printf("Hacked code  : ");
    print_byte_array_ascii(hack);
    printf("CBC-MAC      : ");
    print_byte_array(hash_hack);

    free_byte_arrays(key, code, hash, ans, code1, hash1, padded_code1, xor,
                     code_minus_first_block, hack, hash_hack, NO_BA);
    cleanup_openssl();
    return 0;
}
