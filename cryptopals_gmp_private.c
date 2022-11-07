#include "cryptopals_gmp_private.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

void byte_array_to_mpz_init(mpz_t out, const byte_array in) {
    byte_array hex = byte_array_to_hex_byte_array(in);
    mpz_init_set_str(out, (const char *)hex.bytes, 16);
    free_byte_array(hex);
}

void byte_array_to_mpz(mpz_t out, const byte_array in) {
    byte_array hex = byte_array_to_hex_byte_array(in);
    mpz_set_str(out, (const char *)hex.bytes, 16);
    free_byte_array(hex);
}

byte_array mpz_to_byte_array(const mpz_t in) {
    // Normally need 2 more than mpz_sizeinbase, for possible negative sign
    // and null byte. We're only dealing with positive integers, so probably
    // could just use 1 more, but just playing it safe.
    size_t size_needed = 2 + mpz_sizeinbase(in, 16);
    byte_array hex = alloc_byte_array(size_needed);
    size_t len = gmp_snprintf((char *)hex.bytes, size_needed, "%Zx", in);
    if (len >= size_needed) {
        fprintf(stderr, "%s: mpz_sizeinbase incorrectly determined size of mpz\n", __func__);
	free_byte_array(hex);
	return NO_BA;
    }
    byte_array out = hex_to_bytes((const char *)hex.bytes);
    free_byte_array(hex);
    return out;
}

byte_array mpz_to_hex(const mpz_t in) {
    size_t size_needed = 2 + mpz_sizeinbase(in, 16);
    byte_array hex = alloc_byte_array(size_needed);
    size_t len = gmp_snprintf((char *)hex.bytes, size_needed, "%Zx", in);
    if (len >= size_needed) {
        fprintf(stderr, "%s: mpz_sizeinbase incorrectly determined size of mpz\n", __func__);
	free_byte_array(hex);
	return NO_BA;
    }
    hex.len = strlen(hex.bytes);
    return hex;
}

void test_conversion_functions(const char * hex) {
    printf("%-11s = %s\n", "input", hex);
    mpz_t in;
    mpz_init_set_str(in, hex, 16);
    gmp_printf("%-11s = %Zx\n", "as mpz", in);
    byte_array bytes = mpz_to_byte_array(in);
    printf("%-11s = ", "as bytes");
    print_byte_array(bytes);
    mpz_t copy;
    byte_array_to_mpz_init(copy, bytes);
    gmp_printf("%-11s = %Zx\n", "back to mpz", copy);
    assert(!mpz_cmp(in, copy));
    printf("tests passed!\n");
    mpz_clear(in);
    mpz_clear(copy);
    free_byte_array(bytes);
}

void test_zero_conversion() {
    mpz_t zero;
    mpz_init(zero);
    byte_array zero_mpz_as_ba = mpz_to_byte_array(zero);

    assert(zero_mpz_as_ba.len == 1);
    assert(zero_mpz_as_ba.bytes[0] == 0);

    free_byte_array(zero_mpz_as_ba);
    mpz_clear(zero);
}
