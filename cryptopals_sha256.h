#pragma once
#include "cryptopals_utils.h"

// Produces a new byte array which is the SHA256 hash of original byte array.
byte_array * sha256_byte_array(const byte_array * in);

// Same as previous but zero pads result to total length out_size.
byte_array * sha256_byte_array_zero_pad(const byte_array * in, size_t out_size);

// SHA256(a|b) where | is the concatenation operator.
byte_array * sha256_2_byte_arrays(const byte_array * a, const byte_array * b);
