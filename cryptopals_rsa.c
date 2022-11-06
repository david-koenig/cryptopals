#include "cryptopals_rsa.h"
#include "cryptopals_gmp_private.h"
#include "cryptopals_md4.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

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

rsa_key_pair rsa_keygen(unsigned long mod_bits) {
    rsa_key_pair kp;
    rsa_private_key ** private = (rsa_private_key **) &kp.private;
    rsa_public_key ** public = (rsa_public_key **) &kp.public;
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
    return kp;
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

static inline byte_array decrypt_sig(const rsa_public_key * public, const byte_array sig) {
    return rsa_encrypt(public, sig);
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

static inline byte_array encrypt_sig(const rsa_private_key * private, const byte_array plain) {
    return rsa_decrypt(private, plain);
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

byte_array rsa_unpadded_message_recovery_oracle(rsa_key_pair kp, const byte_array cipher) {
    mpz_t s, s_inv, c, p, c_prime, p_prime;
    mpz_inits(s, s_inv, c, p, c_prime, p_prime, (mpz_ptr)NULL);
    byte_array_to_mpz(c, cipher);

    do {
        mpz_urandomm(s, cryptopals_gmp_randstate, kp.public->n);
        mpz_invert(s_inv, s, kp.public->n);
    } while (mpz_cmp_ui(s, 1) <= 0 || mpz_cmp_ui(s_inv, 1) <= 0);

    mpz_powm(c_prime, s, kp.public->e, kp.public->n);
    mpz_mul(c_prime, c_prime, c);
    mpz_mod(c_prime, c_prime, kp.public->n);

    byte_array c_prime_ba = mpz_to_byte_array(c_prime);
    byte_array p_prime_ba = rsa_decrypt(kp.private, c_prime_ba);

    byte_array_to_mpz(p_prime, p_prime_ba);
    mpz_mul(p, p_prime, s_inv);
    mpz_mod(p, p, kp.public->n);

    byte_array p_ba = mpz_to_byte_array(p);

    mpz_clears(s, s_inv, c, p, c_prime, p_prime, (mpz_ptr)NULL);
    free_byte_array(c_prime_ba);
    free_byte_array(p_prime_ba);
    return p_ba;
}

// According to PKCS1.5 padding rules, a digitally signature
// using MD4 as the digest algorithm will always have the
// following form before it is encrypted with private key:
// 0001ff..ff003020300c06082a864886f70d020405000410
// followed by the 16 byte MD4 hash of the signed file.
// Here "ff..ff" represents a long sequence of ff bytes to
// extend the sequence to the number of bytes of the modulus.

// The part beginning "3020300c..." is the ASN.1 format
// identifying that this is digested with MD4. In particular,
// the byte sequence "2a864886f70d0204" is the OID encoding
// of 1.2.840.113549.2.4, and the final "10" indicates the
// digest value is 16 bytes long.

static uint8_t asn1_bytes[] =
{0x00, 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48,
 0x86, 0xf7, 0x0d, 0x02, 0x04, 0x05, 0x00, 0x04, 0x10};
static const byte_array rsa_md4_asn1 = {asn1_bytes, sizeof(asn1_bytes)};

byte_array rsa_md4_sign_msg(const rsa_private_key * private, const byte_array msg) {
    byte_array digest = md4(msg);

    size_t mod_size = mpz_sizeinbytes(private->n);
    byte_array padding = alloc_byte_array(mod_size - rsa_md4_asn1.len - digest.len);
    padding.bytes[0] = 0x00;
    padding.bytes[1] = 0x01;
    for (int idx = 2 ; idx < padding.len ; ++idx) {
        padding.bytes[idx] = 0xff;
    }
    byte_array padded_digest = append_three_byte_arrays(padding, rsa_md4_asn1, digest);
    byte_array sig = encrypt_sig(private, padded_digest);

    free_byte_array(digest);
    free_byte_array(padding);
    free_byte_array(padded_digest);
    return sig;
}

// A faulty implementation of signature verification that
// does not check that the sequence of "ff..ff" is long
// enough to right-justify the hash value.
bool rsa_md4_verify_sig(const rsa_public_key * public, const byte_array msg, const byte_array sig) {
    bool ret = false;

    byte_array digest = md4(msg);
    byte_array decrypted_sig = decrypt_sig(public, sig);
    size_t mod_size = mpz_sizeinbytes(public->n);
    // because of how decrypted sig is printed, leading zero byte is truncated from array
    if (decrypted_sig.len + 1 != mod_size ||
        decrypted_sig.bytes[0] != 0x01 ||
        decrypted_sig.bytes[1] != 0xff) {
        goto OUT;
    }
    int idx = 1;
    while (decrypted_sig.bytes[++idx] == 0xff);
    const byte_array window = {&decrypted_sig.bytes[idx], rsa_md4_asn1.len};
    if (!byte_arrays_equal(window, rsa_md4_asn1)) {
        goto OUT;
    }
    idx += rsa_md4_asn1.len;
    const byte_array decrypted_dgst = {&decrypted_sig.bytes[idx], digest.len};

    ret = byte_arrays_equal(decrypted_dgst, digest);
OUT:
    free_byte_array(digest);
    free_byte_array(decrypted_sig);
    return ret;
}

byte_array hack_sig(const rsa_public_key * public, const byte_array msg) {
    size_t mod_size = mpz_sizeinbytes(public->n);
    byte_array fake_sig = alloc_byte_array(mod_size);
    fake_sig.bytes[1] = 0x01;
    int idx;
    for (idx = 2 ; idx < 6; ++idx) {
        fake_sig.bytes[idx] = 0xff;
    }
    memcpy(fake_sig.bytes+idx, rsa_md4_asn1.bytes, rsa_md4_asn1.len);
    idx += rsa_md4_asn1.len;
    byte_array digest = md4(msg);
    memcpy(fake_sig.bytes+idx, digest.bytes, digest.len);

    mpz_t fake, signed_fake;
    byte_array_to_mpz_init(fake, fake_sig);
    mpz_init(signed_fake);
    mpz_root(signed_fake, fake, 3);
    mpz_add_ui(signed_fake, signed_fake, 1);

    byte_array signed_fake_sig = mpz_to_byte_array(signed_fake);
    mpz_clears(fake, signed_fake, (mpz_ptr)NULL);
    free_byte_array(fake_sig);
    free_byte_array(digest);
    return signed_fake_sig;
}
