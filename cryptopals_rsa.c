#include "cryptopals_rsa.h"
#include "cryptopals_gmp_private.h"
#include "cryptopals_hash.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

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

static inline size_t mpz_sizeinbytes(const mpz_t op) {
    size_t x = mpz_sizeinbase(op, 16);
    return (x+1)>>1;
}

rsa_key_pair rsa_keygen(unsigned long bits) {
    rsa_key_pair kp;
    rsa_private_key ** private = (rsa_private_key **) &kp.private;
    rsa_public_key ** public = (rsa_public_key **) &kp.public;
    mpz_t p, q, et;

    *private = malloc(sizeof(rsa_private_key));
    *public = malloc(sizeof(rsa_public_key));
    mpz_init_set_ui((*public)->e, 3);
    mpz_inits((*public)->n, (*private)->d, (*private)->n, p, q, et, (mpz_ptr)NULL);
    do {
        mpz_urandomb(p, cryptopals_gmp_randstate, bits>>1);
        mpz_nextprime(p, p);
        mpz_urandomb(q, cryptopals_gmp_randstate, bits>>1);
        mpz_nextprime(q, q);
        mpz_mul((*public)->n, p, q);
        mpz_sub_ui(p, p, 1);
        mpz_sub_ui(q, q, 1);
        mpz_mul(et, p, q);
        // e must be invertible mod (p-1)(q-1) for encryption/decryption to work
    } while (!mpz_invert((*private)->d, (*public)->e, et) || mpz_sizeinbytes((*public)->n) != bits>>3);
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

static inline void encrypt(mpz_t cipher, const rsa_public_key * public, const mpz_t plain) {
    mpz_powm(cipher, plain, public->e, public->n);
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

// returns true if first two bytes of plaintext are 00 02
static bool rsa_padding_oracle(const rsa_private_key * private, const mpz_t cipher) {
    size_t mod_size = mpz_sizeinbytes(private->n);
    mpz_t plain;
    mpz_init(plain);
    mpz_powm(plain, cipher, private->d, private->n);
    mpz_fdiv_q_2exp(plain, plain, 8*(mod_size-2));
    bool ret = !mpz_cmp_ui(plain, 2);
    mpz_clear(plain);
    return ret;
}

bool rsa_padding_oracle_test() {
    int key_sizes[] = {256, 512, 1024, 2048};
    for (int idx = 0 ; idx < sizeof(key_sizes)/sizeof(int) ; idx++) {
        int bits = key_sizes[idx];
        rsa_key_pair kp = rsa_keygen(bits);
        size_t mod_sz = mpz_sizeinbytes(kp.public->n);
        byte_array plain = alloc_byte_array(mod_sz);
        plain.bytes[1] = 2;
        mpz_t myplain, mycipher;
        byte_array_to_mpz_init(myplain, plain);
        mpz_init(mycipher);
        encrypt(mycipher, kp.public, myplain);
        assert(rsa_padding_oracle(kp.private, mycipher));

        plain.bytes[0] = 1;
        byte_array_to_mpz(myplain, plain);
        encrypt(mycipher, kp.public, myplain);
        assert(!rsa_padding_oracle(kp.private, mycipher));

        mpz_clears(myplain, mycipher, (mpz_ptr)NULL);
        free_byte_array(plain);
        free_rsa_public_key(kp.public);
        free_rsa_private_key(kp.private);
    }
    printf("tests pass!\n");
    return true;
}

// From RFC2313, PKCS#1 version 1.5, section 8.1:
// The padding string PS shall consist of k-3-||D|| octets. For block
// type 00, the octets shall have value 00; for block type 01, they
// shall have value FF; and for block type 02, they shall be
// pseudorandomly generated and nonzero.
static byte_array pkcs1_padding(const byte_array data, size_t len) {
    if (data.len > len - 11) {
        fprintf(stderr, "%s: data block too long (%lu bytes) for PKCS 1.5 padding to %lu bytes\n", __func__, data.len, len);
        return NO_BA;
    }
    byte_array out = alloc_byte_array(len);
    size_t pad_len = len - data.len - 3;
    out.bytes[1] = 2;
    for (size_t idx = 2 ; idx < 2 + pad_len ; ++idx) {
        while(!(out.bytes[idx] = random()));
    }
    memcpy(out.bytes + pad_len + 3, data.bytes, data.len);
    return out;
}

// Because we're processing data that might not include the leading 00
// byte, I'm skipping over the first two bytes.
static byte_array remove_pkcs1_padding(const byte_array data) {
    size_t idx = 2;

    if (!data.bytes[++idx]) {
        fprintf(stderr, "%s: Not PKCS 1 padded\n", __func__);
        return NO_BA;
    }
    while (idx < data.len - 2 && data.bytes[++idx]);
    if (data.bytes[idx++] != 0) {
        fprintf(stderr, "%s: Not PKCS 1 padded\n", __func__);
        return NO_BA;
    }
    return sub_byte_array(data, idx, data.len);
}

#define MAX_INTERVALS 64

typedef struct interval {
    mpz_t min;
    mpz_t max;
} interval;

static void print_intervals(interval M[], size_t M_sz) {
    for (size_t idx = 0 ; idx < M_sz ; idx++) {
        gmp_printf("%lu of %lu: [%Zx, %Zx]\n", idx+1, M_sz, M[idx].min, M[idx].max);
    }
}

// If there is an interval overlapping with [min, max], merge this interval with it
// Otherwise, add this as a new interval to the list
size_t merge_append_intervals(interval M[], size_t M_sz, mpz_t min, mpz_t max) {
    for (size_t idx = 0 ; idx < M_sz ; idx++) {
        if (!(mpz_cmp(M[idx].max, min) < 0 || mpz_cmp(M[idx].min, max) > 0)) {
            if (mpz_cmp(min, M[idx].min) < 0) {
                mpz_set(M[idx].min, min);
            }
            if (mpz_cmp(max, M[idx].max) > 0) {
                mpz_set(M[idx].max, max);
            }
            return M_sz;
        }
    }
    if (M_sz == MAX_INTERVALS) {
        fprintf(stderr, "%s: interval size increased beyond maximum of %u\n", __func__, MAX_INTERVALS);
        exit(1);
    }
    mpz_set(M[M_sz].min, min);
    mpz_set(M[M_sz].max, max);
    return M_sz + 1;
}

// global constants allocated and set in padding oracle attack so they can be used in sub functions
mpz_t n, twoB, threeB;
// local scratch variables defined globally so they don't have to be reallocated
mpz_t min, max, min_r, max_r, r;

// Writes a new array of intervals and returns size of the new array
static size_t calculate_intervals(interval * current, const interval * prev, const size_t prev_sz, const mpz_t s) {
    size_t current_sz = 0; // considering current[] to be empty to start
    for (int idx = 0; idx < prev_sz; idx++) {
        // min_r = (a*s-3B+1)/n
        mpz_mul(min_r, prev[idx].min, s);
        mpz_sub(min_r, min_r, threeB);
        mpz_add_ui(min_r, min_r, 1);
        mpz_cdiv_q(min_r, min_r, n);

        // max_r = (b*s_i-2B)/n
        mpz_mul(max_r, prev[idx].max, s);
        mpz_sub(max_r, max_r, twoB);
        mpz_fdiv_q(max_r, max_r, n);

        for (mpz_set(r, min_r) ; mpz_cmp(r, max_r) <= 0 ; mpz_add_ui(r, r, 1)) {
            // set both min and max to r*n
            mpz_mul(min, r, n);
            mpz_set(max, min);

            // min = (2B + r*n)/s or prev min if it was higher
            mpz_add(min, min, twoB);
            mpz_cdiv_q(min, min, s);
            if (mpz_cmp(prev[idx].min, min) > 0) {
                mpz_set(min, prev[idx].min);
            }

            // max = (3B - 1 + r*n)/s or prev max if it was lower
            mpz_add(max, max, threeB);
            mpz_sub_ui(max, max, 1);
            mpz_fdiv_q(max, max, s);
            if (mpz_cmp(prev[idx].max, max) < 0) {
                mpz_set(max, prev[idx].max);
            }
            current_sz = merge_append_intervals(current, current_sz, min, max);
        }
    }
    return current_sz;
}

bool rsa_padding_oracle_attack(unsigned long bits, const char * msg) {
    rsa_key_pair kp = rsa_keygen(bits);
    const size_t mod_sz = mpz_sizeinbytes(kp.public->n);
    byte_array data = cstring_to_bytes(msg);

    if (strlen(msg) > mod_sz - 11) {
        fprintf(stderr, "Data is too long. Max length = key size - 11 bytes\n");
        free_byte_array(data);
        free_rsa_public_key(kp.public);
        free_rsa_private_key(kp.private);
        return false;
    }
    byte_array plain = pkcs1_padding(data, mod_sz);

    // we alternate between reading and writing these two arrays of intervals
    interval M0[MAX_INTERVALS], M1[MAX_INTERVALS];
    interval * M[2] = {M0, M1};
    size_t M_sz[2] = {1, 0};
    for (size_t idx = 0 ; idx < MAX_INTERVALS ; ++idx) {
        mpz_inits(M0[idx].min, M0[idx].max, M1[idx].min, M1[idx].max, (mpz_ptr)NULL);
    }

    // allocating globals to be used as locals in other functions
    mpz_inits(min, max, min_r, max_r, r, (mpz_ptr)NULL);

    // setting global constants
    mpz_init_set(n, kp.public->n);

    mpz_init_set_ui(twoB, 2);
    mpz_mul_2exp(twoB, twoB, 8*(mod_sz - 2));
    mpz_init_set_ui(threeB, 3);
    mpz_mul_2exp(threeB, threeB, 8*(mod_sz - 2));

    mpz_t myplain, mycipher, s, enc_s, trick_cipher, ri, min_s, max_s;
    mpz_inits(mycipher, s, enc_s, trick_cipher, ri, min_s, max_s, (mpz_ptr)NULL);
    byte_array_to_mpz_init(myplain, plain);
    encrypt(mycipher, kp.public, myplain);

    // s[0] = 1
    assert(rsa_padding_oracle(kp.private, mycipher));

    // M[0] is just one interval: [2B, 3B-1]
    mpz_set(M0[0].min, twoB);
    mpz_sub_ui(M0[0].max, threeB, 1);

    // start looking for s[1] at n/3B
    mpz_cdiv_q(s, n, threeB);

    int prev;
    for (size_t i = 1 ; ; i++) {
        int current = i&1; // M[current] = M[i] = intervals calculated in this iteration
        prev = current^1; // M[prev] = M[i-1] = intervals calculated in previous iteration

        if (i == 1 || M_sz[prev] > 1) {
            do {
                mpz_add_ui(s, s, 1);
                encrypt(enc_s, kp.public, s);
                mpz_mul(trick_cipher, mycipher, enc_s);
            } while(!rsa_padding_oracle(kp.private, trick_cipher));
        } else {
            assert(M_sz[prev] == 1);
            if (!mpz_cmp(M[prev][0].min, M[prev][0].max)) {
                goto SUCCESS;
            }
            mpz_mul(ri, M[prev][0].max, s);
            mpz_sub(ri, ri, twoB);
            mpz_mul_2exp(ri, ri, 1);
            mpz_cdiv_q(ri, ri, n);

            while(true) {
                mpz_mul(min_s, ri, n);
                mpz_set(max_s, min_s);

                mpz_add(min_s, min_s, twoB);
                mpz_cdiv_q(min_s, min_s, M[prev][0].max);

                mpz_add(max_s, max_s, threeB);
                mpz_fdiv_q(max_s, max_s, M[prev][0].min);

                for (mpz_set(s, min_s) ; mpz_cmp(s, max_s) <= 0 ; mpz_add_ui(s, s, 1)) {
                    encrypt(enc_s, kp.public, s);
                    mpz_mul(trick_cipher, mycipher, enc_s);
                    if (rsa_padding_oracle(kp.private, trick_cipher)) {
                        goto NEXT;
                    }
                }
                mpz_add_ui(ri, ri, 1);
                // If we had a single interval that was incorrect, we could get into an
                // infinite loop here. Shouldn't happen if I programmed algorithm right.
            }
        }
    NEXT:
        M_sz[current] = calculate_intervals(M[current], M[prev], M_sz[prev], s);
    }
SUCCESS:
    assert(!mpz_cmp(M[prev][0].max, myplain));
    byte_array cracked = mpz_to_byte_array(M[prev][0].max);
    printf("Cracked plaintext!\n");
    printf("00"); // the way we convert mpz to byte array the leading zeros get truncated
    print_byte_array(cracked);
    byte_array cracked_plain = remove_pkcs1_padding(cracked);
    printf("With PKCS 1.5 padding removed and printed in ASCII: ");
    print_byte_array_ascii(cracked_plain);

    free_byte_arrays(cracked, cracked_plain, NO_BA);
    for (size_t idx = 0 ; idx < MAX_INTERVALS ; ++idx) {
        mpz_clears(M[0][idx].min, M[0][idx].max, M[1][idx].min, M[1][idx].max, (mpz_ptr)NULL);
    }
    mpz_clears(n, twoB, threeB, min, max, min_r, max_r, r, myplain, mycipher, ri, s, enc_s, min_s, max_s, trick_cipher, (mpz_ptr)NULL);
    free_byte_arrays(data, plain, NO_BA);
    free_rsa_private_key(kp.private);
    free_rsa_public_key(kp.public);
    return true;
}

static bool rsa_parity_oracle(const rsa_private_key * private, const mpz_t cipher) {
    mpz_t plain;
    mpz_init(plain);
    mpz_powm(plain, cipher, private->d, private->n);
    bool ret = mpz_odd_p(plain);
    mpz_clear(plain);
    return ret;
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
    free_byte_arrays(c_prime_ba, p_prime_ba, NO_BA);
    return p_ba;
}

// According to PKCS1.5 padding rules, a digital signature
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

    free_byte_arrays(digest, padding, padded_digest, NO_BA);
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
    free_byte_arrays(digest, decrypted_sig, NO_BA);
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
    free_byte_arrays(fake_sig, digest, NO_BA);
    return signed_fake_sig;
}

bool rsa_parity_oracle_attack(bool hollywood) {
    if (!hollywood) {
        printf("To see a big splash on the screen, add \"hollywood\" to the command line.\n");
    }
    rsa_key_pair kp = rsa_keygen(1024);
    mpf_set_default_prec(1024);

    byte_array plain_txt = base64_to_bytes("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5I"
                                           "GFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="); 
    mpz_t plain, cipher;
    byte_array_to_mpz_init(plain, plain_txt);
    mpz_init(cipher);
    encrypt(cipher, kp.public, plain);

    mpf_t max, min, diff;
    mpf_inits(max, min, diff, (mpf_ptr)NULL);
    mpf_set_z(max, kp.public->n);

    mpz_t enc_two, two, trick_cipher, max_int;
    mpz_inits(enc_two, two, trick_cipher, max_int, (mpz_ptr)NULL);

    mpz_set_ui(two, 2);
    encrypt(enc_two, kp.public, two); // encryption of 2, i.e., 2**e mod n

    mpz_set(trick_cipher, cipher); 
    while (true) {
        mpf_sub(diff, max, min);
        if (mpf_cmp_ui(diff, 1) < 0) break;

        mpf_div_ui(diff, diff, 2);

        mpz_mul(trick_cipher, enc_two, trick_cipher); // doubles plaintext
        if (rsa_parity_oracle(kp.private, trick_cipher)) {
            mpf_add(min, min, diff);
        } else {
            mpf_add(max, min, diff);
        }
        if (hollywood) {
            mpz_set_f(max_int, max);
            byte_array max_txt = mpz_to_byte_array(max_int);
            print_byte_array_ascii(max_txt);
            free_byte_array(max_txt);
        }
    }

    mpz_set_f(max_int, max);
    assert(!mpz_cmp(max_int, plain));
    printf("Plaintext cracked!\n");
    if (!hollywood) {
        byte_array decrypt = mpz_to_byte_array(max_int);
        print_byte_array_ascii(decrypt);
        free_byte_array(decrypt);
    }

    free_rsa_public_key(kp.public);
    free_rsa_private_key(kp.private);
    free_byte_array(plain_txt);
    mpz_clears(plain, cipher, enc_two, two, trick_cipher, max_int, (mpz_ptr)NULL);
    mpf_clears(max, min, diff, (mpf_ptr)NULL);

    return true;
}
