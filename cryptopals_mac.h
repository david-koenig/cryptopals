#pragma once
#include "cryptopals_utils.h"

// sets up random mac key of random length
void init_random_mac_key(int seed);

// deallocates random mac key
void cleanup_random_mac_key();

// Calculates a secret-prefix MAC: SHA1(key || message). Allocates byte array for result.
// Attacker does not have access to this function.
byte_array * sha1_mac(const byte_array * message);

// Same thing but MD4(key || message)
byte_array * md4_mac(const byte_array * message);

// Returns true if sha1_mac(message) == mac
// Attacker does have access to this function.
bool check_message_sha1_mac(const byte_array * message, const byte_array * mac);

// Returns true if md4_mac(message) == mac
// Attacker does have access to this function.
bool check_message_md4_mac(const byte_array * message, const byte_array * mac);

/* Produces a byte array of just the SHA1 padding bytes for a message
 * of the specified length in bytes. This implementation assumes the
 * message length is always a whole number of bytes.
 *
 * Padding consists of a 1 bit, followed by zeroes, followed by a 64 bit
 * integer which is the length of the unpadded message in BITS, such
 * that the end result is a multiple of 512 bits, the SHA1 block size.
 * This implementation only works for multiples of 8 bits, as it assumes
 * that the input byte array is exactly the length of the message.
 */
byte_array * sha1_pad(uint64_t len_in_bytes);

// MD4 uses same padding as SHA1, except padding stores length in little endian.
byte_array * md4_pad(uint64_t len_in_bytes);
