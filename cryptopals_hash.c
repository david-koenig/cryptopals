#include "cryptopals_hash.h"
#include "md4.h"
#include "sha256.h"
#include "sha1.h"

byte_array md4(const byte_array in) {
    MD4_CTX ctx;
    byte_array digest = alloc_byte_array(16);
    MD4Init(&ctx);
    MD4Update(&ctx, in.bytes, in.len);
    MD4Final(digest.bytes, &ctx);
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

byte_array sha1(const byte_array in) {
    SHA1Context ctx;
    byte_array digest = alloc_byte_array(SHA1HashSize);
    SHA1Reset(&ctx);
    SHA1Input(&ctx, in.bytes, in.len);
    SHA1Result(&ctx, digest.bytes);
    return digest;
}
