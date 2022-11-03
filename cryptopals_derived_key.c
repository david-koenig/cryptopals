#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "cryptopals_derived_key.h"
#include "sha1.h"

static void check_err(int err) {
    if (err) {
        fprintf(stderr, "SHA1 error: %d\n", err);
        exit(1);
    }
}

byte_array derive_key(const char * secret) {
    SHA1Context sha;
    check_err(SHA1Reset(&sha));
    check_err(SHA1Input(&sha, (const uint8_t *) secret, strlen(secret)));
    byte_array digest = alloc_byte_array(20);
    check_err(SHA1Result(&sha, digest.bytes));
    digest.len = 16;

    return digest;
}
