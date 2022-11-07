#pragma once
#include <gmp.h>
#include "cryptopals_utils.h"

extern gmp_randstate_t cryptopals_gmp_randstate;

// Interprets hex printout of byte array as a single integer
// (lowest address byte being most significant, i.e., big endian)
// and converts array to mpz_t. First argument must be
// uninitialized mpz_t and will be initialized.
void byte_array_to_mpz_init(mpz_t out, const byte_array in);

// Same as previous function, but assumes first argument
// has already been initialized.
void byte_array_to_mpz(mpz_t out, const byte_array in);

// Converts mpz_t to byte array in which first byte of array
// is most significant byte of integer represented by mpz.
byte_array mpz_to_byte_array(const mpz_t in);

// Hex string is null terminated, but length of byte array
// does not include null bytes at end
byte_array mpz_to_hex(const mpz_t in);
