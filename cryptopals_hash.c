#include "cryptopals_hash.h"
#include "md4.h"
#include "sha1.h"
#include "sha256.h"
#include <assert.h>
#include <stdio.h>

byte_array md4(const byte_array in) {
    MD4_CTX ctx;
    byte_array digest = alloc_byte_array(16);
    MD4Init(&ctx);
    MD4Update(&ctx, in.bytes, in.len);
    MD4Final(digest.bytes, &ctx);
    return digest;
}

byte_array sha1(const byte_array in) {
    SHA1Context ctx;
    byte_array digest = alloc_byte_array(SHA1HashSize);
    SHA1Reset(&ctx);
    SHA1Input(&ctx, in.bytes, in.len);
    SHA1Result(&ctx, digest.bytes);
    return digest;
}

byte_array sha256(const byte_array in) {
    SHA256_CTX ctx;
    byte_array digest = alloc_byte_array(SHA256_OUTPUT_SIZE);
    sha256_init(&ctx);
    sha256_update(&ctx, in.bytes, in.len);
    sha256_final(&ctx, digest.bytes);
    return digest;
}

byte_array sha256_cat(const byte_array a, const byte_array b) {
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

    byte_array sha256_test1 = sha256(empty);
    byte_array sha256_test2 = sha256(abc);
    byte_array sha256_test3 = sha256(long_string);

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
