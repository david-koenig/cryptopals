#pragma once
#include "cryptopals_utils.h"

/* Example: let's say black box encryption has 16 byte block size, prepends 22 bytes and appends 240 bytes.
 * unknown length = 262 bytes (22+240). We will discover this before we know how many are prepended and appended.
 * junk bytes = the first 22 bytes that are prepended. We don't care about these.
 * target bytes = the last 240 bytes that are appended, which are what we want to recover.
 * unused bytes = the first 10 bytes of plaintext we provide to encrypt function. Need these to round out 32 bytes of encryption.
 * matching block index = 2. (first 32 bytes, which includes junk, have indices 0 and 1, so block 2 is where we start the attack)
 */


/* Does repeated encryptions using increasing plaintext size of the fill character until the length of the produced cipher
 * changes. This is assuming that the encryption function is a block cipher which encrypts the entire input text possibly
 * prepended and appended with unknown strings of fixed length. It determines both the block size of the encryption function
 * and the total number of unknown bytes (prepended and appended together) and copies those values to the addresses pointed
 * to by the first two arguments. Returns true on success, false on failure.
 */
bool find_block_size(size_t * block_size_p, size_t * unknown_len_p, uint8_t fill_c, byte_array (*encrypt)(const byte_array));


/* Does byte at a time recovery of target appended text attack for challenges 12 and 14. Inputs are:
 * target_len = length of target text to be recovered
 * fill_c = fill character to use in the attack, generally doesn't matter as long as black box accepts that character
 * unused_len = extra length of input to encryption function that is needed at the beginning to round out a whole block
 * block_size = block size of encryption function
 * matching_block_idx = index of the first block that attacker is able to completely fill with fill_c
 * encrypt = black box ECB encryption function which appends target text and possibly prepends junk text
 */
bool recover_bytes(size_t target_len, uint8_t fill_c, size_t unused_len, size_t block_size, size_t matching_block_idx, byte_array (*encrypt)(const byte_array));

/* Subfunction of recover_bytes attack above. Spoof is known to match block of plaintext in all except last byte.
 * Keep changing last byte of spoof until specified block of its encryption matches specified block of target cipher.
 * Return true on success, false on failure. Recovered byte will be at spoof.bytes[spoof.len - 1]
 */
bool recover_byte(const byte_array cipher, size_t cipher_block_num, byte_array spoof, size_t spoof_block_num, size_t block_size, byte_array (*encrypt)(const byte_array));

/* Shift all bytes of an array down one */
void shift_down(byte_array ba);
