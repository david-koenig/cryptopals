#pragma once
#include "cryptopals_utils.h"

// derives an AES-128 key that is the first 16 bytes of the SHA1 digest of the secret printed as hex
byte_array * derive_key(const char * secret);
