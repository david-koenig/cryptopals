#include "cryptopals_rsa.h"
#include "cryptopals_gmp_private.h"
#include <stdlib.h>

typedef struct rsa_params {
    mpz_t n; // modulus
    mpz_t d; // private key, for decryption
    mpz_t e; // public key, for encryption
} rsa_params;

void free_rsa_params(rsa_params * params) {
    mpz_clear(params->n);
    mpz_clear(params->d);
    mpz_clear(params->e);
    free(params);
}

rsa_params * rsa_keygen() {
    const mp_bitcnt_t bits = 256; // number of bits in random primes
    
    rsa_params * params = malloc(sizeof(rsa_params));
    mpz_init_set_ui(params->e, 3);
    mpz_init(params->d);
    mpz_init(params->n);

    mpz_t p, q, et;
    mpz_init(p);
    mpz_init(q);
    mpz_init(et);
    
    do {
        mpz_urandomb(p, cryptopals_gmp_randstate, bits);
        mpz_nextprime(p, p);
        mpz_urandomb(q, cryptopals_gmp_randstate, bits);
        mpz_nextprime(q, q);
        mpz_mul(params->n, p, q);
    
        mpz_sub_ui(p, p, 1);
        mpz_sub_ui(q, q, 1);
        mpz_mul(et, p, q);
    
        mpz_invert(params->d, params->e, et);  
    } while (!mpz_cmp_ui(params->d, 0));

    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(et);
    return params;
}

byte_array * rsa_encrypt(const rsa_params * params, const byte_array * plain) {
    mpz_t myplain, mycipher;
    mpz_init(mycipher);
    byte_array_to_mpz_init(myplain, plain);
    mpz_powm(mycipher, myplain, params->e, params->n);

    byte_array * cipher = mpz_to_byte_array(mycipher);
    mpz_clear(myplain);
    mpz_clear(mycipher);
    return cipher;
}

byte_array * rsa_decrypt(const rsa_params * params, const byte_array * cipher){
    mpz_t mycipher, myplain;
    mpz_init(myplain);
    byte_array_to_mpz_init(mycipher, cipher);
    mpz_powm(myplain, mycipher, params->d, params->n);

    byte_array * plain = mpz_to_byte_array(myplain);
    mpz_clear(mycipher);
    mpz_clear(myplain);
    return plain;
}
