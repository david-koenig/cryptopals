#pragma once
#include "cryptopals_utils.h"

// Hash-based message-authentication code. See RFC 2104 for definition.
byte_array * hmac_sha256(const byte_array * key, const byte_array * message);
