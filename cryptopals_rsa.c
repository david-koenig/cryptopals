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
    mpz_clear(myprivate->n);
    mpz_clear(myprivate->d);
    free(myprivate);
}

void free_rsa_public_key(const rsa_public_key * public) {
    rsa_public_key * mypublic = (rsa_public_key *) public;
    mpz_clear(mypublic->n);
    mpz_clear(mypublic->e);
    free(mypublic);
}

rsa_params rsa_keygen(unsigned long mod_bits) {
    rsa_params params;
    rsa_private_key ** private = (rsa_private_key **) &params.private;
    rsa_public_key ** public = (rsa_public_key **) &params.public;

    *private = malloc(sizeof(rsa_private_key));
    *public = malloc(sizeof(rsa_public_key));
    mpz_init_set_ui((*public)->e, 3);
    mpz_init((*public)->n);
    mpz_init((*private)->d);
    mpz_init((*private)->n);

    mpz_t p, q, et;
    mpz_init(p);
    mpz_init(q);
    mpz_init(et);
    
    do {
        mpz_urandomb(p, cryptopals_gmp_randstate, mod_bits);
        mpz_nextprime(p, p);
        mpz_urandomb(q, cryptopals_gmp_randstate, mod_bits);
        mpz_nextprime(q, q);
        mpz_mul((*public)->n, p, q);
    
        mpz_sub_ui(p, p, 1);
        mpz_sub_ui(q, q, 1);
        mpz_mul(et, p, q);
    } while (!mpz_invert((*private)->d, (*public)->e, et));
    mpz_set((*private)->n, (*public)->n);

    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(et);
    return params;
}

byte_array * rsa_encrypt(const rsa_public_key * public, const byte_array * plain) {
    mpz_t myplain, mycipher;
    mpz_init(mycipher);
    byte_array_to_mpz_init(myplain, plain);
    mpz_powm(mycipher, myplain, public->e, public->n);

    byte_array * cipher = mpz_to_byte_array(mycipher);
    mpz_clear(myplain);
    mpz_clear(mycipher);
    return cipher;
}

byte_array * rsa_decrypt(const rsa_private_key * private, const byte_array * cipher) {
    mpz_t mycipher, myplain;
    mpz_init(myplain);
    byte_array_to_mpz_init(mycipher, cipher);
    mpz_powm(myplain, mycipher, private->d, private->n);

    byte_array * plain = mpz_to_byte_array(myplain);
    mpz_clear(mycipher);
    mpz_clear(myplain);
    return plain;
}

byte_array * rsa_broadcast_attack(const rsa_public_key * public[3], const byte_array * cipher[3]) {
    mpz_t ans, N;
    mpz_t mycipher[3], m[3], inv[3];
    mpz_init(ans);
    mpz_init(N);

    for (int idx = 0 ; idx < 3 ; idx++) {
        byte_array_to_mpz_init(mycipher[idx], cipher[idx]);
        mpz_init(m[idx]);
        mpz_init(inv[idx]);

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

    byte_array * plain = mpz_to_byte_array(ans);
    mpz_clear(ans);
    mpz_clear(N);
    for (int idx = 0 ; idx < 3 ; idx++) {
        mpz_clear(m[idx]);
        mpz_clear(inv[idx]);
        mpz_clear(mycipher[idx]);
    }

    return plain;
}
