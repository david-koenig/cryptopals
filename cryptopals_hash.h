#pragma once
#include "cryptopals_utils.h"

byte_array md4(const byte_array in);
byte_array sha1(const byte_array in);
byte_array sha256(const byte_array in);

// SHA256(a|b) where | is the concatenation operator.
byte_array sha256_cat(const byte_array a, const byte_array b);
