#pragma once
#include "cryptopals_utils.h"

// Hash-based message-authentication code. See RFC 2104 for definition.
byte_array * sha256_hmac(const byte_array * key, const byte_array * message);

void test_sha256_hmac();
