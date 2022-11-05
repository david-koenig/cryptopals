#include "cryptopals_md4.h"
#include "md4.h"

byte_array md4(byte_array msg) {
    MD4_CTX ctx;
    byte_array digest = alloc_byte_array(16);
    MD4Init(&ctx);
    MD4Update(&ctx, msg.bytes, msg.len);
    MD4Final(digest.bytes, &ctx);
    return digest;
}
