#pragma once

// This header does not need to be included directly. It will be used by other
// headers that access code using GMP, for example cryptopals_dh.h and cryptopals_srp.h.
// The header files that include this will indicate when these functions are needed.

// Run this before running other functions here to set up GMP's RNG state.
void init_gmp(unsigned long int seed);

// Run this when done using functions here to deallocate RNG state.
void cleanup_gmp();

