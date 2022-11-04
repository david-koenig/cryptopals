#include "cryptopals_rsa.h"
#include "cryptopals_gmp_private.h"
#include <stdlib.h>
#include <stdio.h>

typedef struct rsa_private_key {
    mpz_t n; // modulus
    mpz_t d; // private key, for decryption and signing
} rsa_private_key;

typedef struct rsa_public_key {
    mpz_t n; // modulus
    mpz_t e; // public key, for encryption and verification
} rsa_public_key;

void free_rsa_private_key(const rsa_private_key * private) {
    rsa_private_key * myprivate = (rsa_private_key *) private;
    mpz_clears(myprivate->n, myprivate->d, (mpz_ptr)NULL);
    free(myprivate);
}

void free_rsa_public_key(const rsa_public_key * public) {
    rsa_public_key * mypublic = (rsa_public_key *) public;
    mpz_clears(mypublic->n, mypublic->e, (mpz_ptr)NULL);
    free(mypublic);
}

static size_t mpz_sizeinbytes(const mpz_t op) {
    size_t x = mpz_sizeinbase(op, 16);
    return (x+1)>>1;
}

rsa_params rsa_keygen(unsigned long mod_bits) {
    rsa_params params;
    rsa_private_key ** private = (rsa_private_key **) &params.private;
    rsa_public_key ** public = (rsa_public_key **) &params.public;
    mpz_t p, q, et;

    *private = malloc(sizeof(rsa_private_key));
    *public = malloc(sizeof(rsa_public_key));
    mpz_init_set_ui((*public)->e, 3);
    mpz_inits((*public)->n, (*private)->d, (*private)->n, p, q, et, (mpz_ptr)NULL);
    
    do {
        mpz_urandomb(p, cryptopals_gmp_randstate, mod_bits);
        mpz_nextprime(p, p);
        mpz_urandomb(q, cryptopals_gmp_randstate, mod_bits);
        mpz_nextprime(q, q);
        mpz_mul((*public)->n, p, q);
    
        mpz_sub_ui(p, p, 1);
        mpz_sub_ui(q, q, 1);
        mpz_mul(et, p, q);
        // e must be invertible mod (p-1)(q-1) for encryption/decryption to work and
        // n must be at least 12 octets for PKCS 1.5 standard (RFC 2313)
    } while (!mpz_invert((*private)->d, (*public)->e, et) || mpz_sizeinbytes((*public)->n) < 12);
    mpz_set((*private)->n, (*public)->n);

    mpz_clears(p, q, et, (mpz_ptr)NULL);
    return params;
}

byte_array rsa_encrypt(const rsa_public_key * public, const byte_array plain) {
    mpz_t myplain, mycipher;
    mpz_init(mycipher);
    byte_array_to_mpz_init(myplain, plain);
    mpz_powm(mycipher, myplain, public->e, public->n);

    byte_array cipher = mpz_to_byte_array(mycipher);
    mpz_clears(myplain, mycipher, (mpz_ptr)NULL);
    return cipher;
}

byte_array rsa_decrypt(const rsa_private_key * private, const byte_array cipher) {
    mpz_t mycipher, myplain;
    mpz_init(myplain);
    byte_array_to_mpz_init(mycipher, cipher);
    mpz_powm(myplain, mycipher, private->d, private->n);

    byte_array plain = mpz_to_byte_array(myplain);
    mpz_clears(mycipher, myplain, (mpz_ptr)NULL);
    return plain;
}

byte_array rsa_broadcast_attack(const rsa_public_key * public[3], const byte_array cipher[3]) {
    mpz_t ans, N;
    mpz_t mycipher[3], m[3], inv[3];
    mpz_inits(ans, N, (mpz_ptr)NULL);

    for (int idx = 0 ; idx < 3 ; idx++) {
        byte_array_to_mpz_init(mycipher[idx], cipher[idx]);
        mpz_inits(m[idx], inv[idx], (mpz_ptr)NULL);

        mpz_mul(m[idx], public[(idx+1)%3]->n, public[(idx+2)%3]->n);
        mpz_mul(mycipher[idx], mycipher[idx], m[idx]);
        if (!mpz_invert(inv[idx], m[idx], public[idx]->n)) {
            fprintf(stderr, "%s: Chinese Remainder Theorem fail: moduli not coprime\n", __func__);
            exit(-1);
        }
        mpz_addmul(ans, mycipher[idx], inv[idx]);
    }

    mpz_mul(N, m[0], public[0]->n);
    mpz_mod(ans, ans, N);
    if (!mpz_root(ans, ans, 3)) {
        fprintf(stderr, "%s: Chinese Remainder Theorem fail: not an exact cube root\n", __func__);
        exit(-2);
    }

    byte_array plain = mpz_to_byte_array(ans);
    mpz_clears(ans, N, (mpz_ptr)NULL);
    for (int idx = 0 ; idx < 3 ; idx++) {
        mpz_clears(m[idx], inv[idx], mycipher[idx], (mpz_ptr)NULL);
    }

    return plain;
}

byte_array rsa_unpadded_message_recovery_oracle(rsa_params params, const byte_array cipher) {
    mpz_t s, s_inv, c, p, c_prime, p_prime;
    mpz_inits(s, s_inv, c, p, c_prime, p_prime, (mpz_ptr)NULL);
    byte_array_to_mpz(c, cipher);

    do {
        mpz_urandomm(s, cryptopals_gmp_randstate, params.public->n);
        mpz_invert(s_inv, s, params.public->n);
    } while (mpz_cmp_ui(s, 1) <= 0 || mpz_cmp_ui(s_inv, 1) <= 0);

    mpz_powm(c_prime, s, params.public->e, params.public->n);
    mpz_mul(c_prime, c_prime, c);
    mpz_mod(c_prime, c_prime, params.public->n);

    byte_array c_prime_ba = mpz_to_byte_array(c_prime);
    byte_array p_prime_ba = rsa_decrypt(params.private, c_prime_ba);

    byte_array_to_mpz(p_prime, p_prime_ba);
    mpz_mul(p, p_prime, s_inv);
    mpz_mod(p, p, params.public->n);

    byte_array p_ba = mpz_to_byte_array(p);

    mpz_clears(s, s_inv, c, p, c_prime, p_prime, (mpz_ptr)NULL);
    free_byte_array(c_prime_ba);
    free_byte_array(p_prime_ba);
    return p_ba;
}
