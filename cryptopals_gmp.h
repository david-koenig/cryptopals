#pragma once

// Do include this header in user files directly. It will be used by other headers that
// access code using GMP, for example cryptopals_dh.h and cryptopals_srp.h. Header files
// that include this will document when these functions are needed.

// Best practice for using this is for the other cryptopals source file using GMP to
// include cryptopals_gmp_private.h and for its header file to include cryptopals_gmp.h
// This allows the library code to access the RNG state and few other useful utility
// functions for interacting with GMP but does not give user code consuming the library
// access to the GMP internals at all.

// Set up GMP's RNG state.
void init_gmp(unsigned long int seed);

// Deallocate GMP's RNG state.
void cleanup_gmp();

