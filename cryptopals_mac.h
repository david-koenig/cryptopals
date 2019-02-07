#pragma once
#include "cryptopals_utils.h"

// Calculates a secret-prefix MAC: SHA1(key || message). Allocates byte array for result.
byte_array * sha1_mac(const byte_array * key, const byte_array * message);

// Adds SHA1 padding to message, allocating a new byte array for result.
// Padding consists of a 1 bit, followed by zeroes, followed by a 64 bit
// integer which is the length of the unpadded message in BITS, such
// that the end result is a multiple of 512 bits, the SHA1 block size.
// Tthis implementation only works for multiples of 8 bits, as it assumes
// that the input byte array is exactly the length of the message.
byte_array * sha1_pad(const byte_array * message);
