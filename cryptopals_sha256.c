#include "cryptopals_sha256.h"
#include "sha256.h"
#include <assert.h>
#include <stdio.h>

// Last argument allows for zero padded output larger than SHA256_OUTPUT_SIZE.
byte_array sha256_byte_array_zero_pad(const byte_array in, size_t out_size) {
    if (out_size < SHA256_OUTPUT_SIZE) {
        fprintf(stderr, "%s: out_size must be at least SHA256_OUTPUT_SIZE\n", __func__);
        return NO_BA;
    }
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, in.bytes, in.len);
    byte_array out = alloc_byte_array(out_size);
    sha256_final(&ctx, out.bytes);
    return out;
}

byte_array sha256_byte_array(const byte_array in) {
    return sha256_byte_array_zero_pad(in, SHA256_OUTPUT_SIZE);
}

byte_array sha256_2_byte_arrays(const byte_array a, const byte_array b) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, a.bytes, a.len);
    sha256_update(&ctx, b.bytes, b.len);
    byte_array sha_out = alloc_byte_array(SHA256_OUTPUT_SIZE);
    sha256_final(&ctx, sha_out.bytes);
    return sha_out;
}

void test_sha256() {
    byte_array empty = cstring_to_bytes("");
    byte_array abc = cstring_to_bytes("abc");
    byte_array long_string = cstring_to_bytes(
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");

    byte_array sha256_test1 = sha256_byte_array(empty);
    byte_array sha256_test2 = sha256_byte_array(abc);
    byte_array sha256_test3 = sha256_byte_array(long_string);

    byte_array sha256_test1_answer = hex_to_bytes(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    byte_array sha256_test2_answer = hex_to_bytes(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    byte_array sha256_test3_answer = hex_to_bytes(
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    assert(byte_arrays_equal(sha256_test1, sha256_test1_answer));
    assert(byte_arrays_equal(sha256_test2, sha256_test2_answer));
    assert(byte_arrays_equal(sha256_test3, sha256_test3_answer));
    printf("SHA256 test vectors pass!\n");

    free_byte_array(empty);
    free_byte_array(abc);
    free_byte_array(long_string);
    free_byte_array(sha256_test1);
    free_byte_array(sha256_test2);
    free_byte_array(sha256_test3);
    free_byte_array(sha256_test1_answer);
    free_byte_array(sha256_test2_answer);
    free_byte_array(sha256_test3_answer);
}
