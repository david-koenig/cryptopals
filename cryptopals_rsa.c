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
        mpz_urandomb(p, cryptopals_gmp_randstate, mod_bits>>1);
        mpz_nextprime(p, p);
        mpz_urandomb(q, cryptopals_gmp_randstate, mod_bits>>1);
        mpz_nextprime(q, q);
        mpz_mul((*public)->n, p, q);
        mpz_sub_ui(p, p, 1);
        mpz_sub_ui(q, q, 1);
        mpz_mul(et, p, q);
        // e must be invertible mod (p-1)(q-1) for encryption/decryption to work
    } while (!mpz_invert((*private)->d, (*public)->e, et));
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

static byte_array pkcs_1_padding(const byte_array data, size_t len) {
    if (data.len > len - 4) {
        fprintf(stderr, "%s: data block too long (%lu bytes) for PKCS 1.5 padding to %lu bits\n", __func__, data.len, len);
        return NO_BA;
    }
    byte_array out = alloc_byte_array(len);
    size_t pad_len = len - data.len - 3;
    out.bytes[1] = 2;
    memset(out.bytes + 2, 0xff, pad_len);
    memcpy(out.bytes + pad_len + 3, data.bytes, data.len);
    return out;
}

static byte_array remove_pkcs_1_padding(const byte_array data) {
    size_t idx = 3;

    if (data.bytes[++idx] != 0xff) {
        fprintf(stderr, "%s: Not PKCS 1 padded\n", __func__);
        return NO_BA;
    }
    while (idx < data.len - 2 && data.bytes[++idx] == 0xff);
    if (data.bytes[idx++] != 0) {
        fprintf(stderr, "%s: Not PKCS 1 padded\n", __func__);
        return NO_BA;
    }
    return sub_byte_array(data, idx, data.len);
}

static void calculate_highest_interval(mpz_t min, mpz_t max, mpz_t last_min, mpz_t last_max, mpz_t r, const mpz_t s, const mpz_t twoB, const mpz_t threeB, const mpz_t n) {
    mpz_mul(r, max, s);
    mpz_sub(r, r, twoB);
    mpz_fdiv_q(r, r, n);

    mpz_set(last_max, max);
    mpz_set(last_min, min);

    // set both min and max to r*n
    mpz_mul(min, r, n);
    mpz_set(max, min);

    // min = (2B + r*n)/s or last_min if it was higher
    mpz_add(min, min, twoB);
    mpz_cdiv_q(min, min, s);
    if (mpz_cmp(last_min, min) > 0) {
        mpz_set(min, last_min);
    }

    // max = (3B - 1 + r*n)/s or last_max if it was lower
    mpz_add(max, max, threeB);
    mpz_sub_ui(max, max, 1);
    mpz_fdiv_q(max, max, s);
    if (mpz_cmp(last_max, max) < 0) {
        mpz_set(max, last_max);
    }
    //gmp_printf("M[%lu] = [%Zx, %Zx]\n", i, min, max);
}

bool rsa_padding_oracle_attack() {
    rsa_key_pair kp = rsa_keygen(256);
    const size_t mod_sz = mpz_sizeinbytes(kp.public->n);
    byte_array data = cstring_to_bytes("kick it, CC");
    byte_array plain = pkcs_1_padding(data, mod_sz);
    mpz_t twoB, threeB, myplain, mycipher, s, enc_s, min, max, trick_cipher;
    mpz_t ri, last_min, last_max, r, min_s, max_s;
    mpz_inits(ri, r, min_s, max_s, last_min, last_max, (mpz_ptr)NULL);

    byte_array_to_mpz_init(myplain, plain);
    mpz_init(mycipher);
    encrypt(mycipher, kp.public, myplain);
    assert(rsa_padding_oracle(kp.private, mycipher));

    mpz_init_set_ui(twoB, 2);
    mpz_mul_2exp(twoB, twoB, 8*(mod_sz - 2));
    mpz_init_set_ui(threeB, 3);
    mpz_mul_2exp(threeB, threeB, 8*(mod_sz - 2));

    // min = 2B, max = 3B-1, s = ceil(n/3B)
    mpz_init_set(min, twoB);
    mpz_init(max);
    mpz_sub_ui(max, threeB, 1);
    mpz_init(s);
    mpz_cdiv_q(s, kp.public->n, threeB);

    size_t i = 0;
    //gmp_printf("s[%lu] = %d\nM[%lu] = [%Zx, %Zx]\n", i, 1, i, min, max);
    mpz_init(enc_s);
    mpz_init(trick_cipher);
    do {
        mpz_add_ui(s, s, 1);
        encrypt(enc_s, kp.public, s);
        mpz_mul(trick_cipher, mycipher, enc_s);
    } while(!rsa_padding_oracle(kp.private, trick_cipher));
    i++;
    //gmp_printf("s[%lu] = %Zx\n", i, s);

    calculate_highest_interval(min, max, last_min, last_max, r, s, twoB, threeB, kp.public->n);

    for (i++ ; mpz_cmp(min, max) < 0 ; i++) {
        mpz_mul(ri, max, s);
        mpz_sub(ri, ri, twoB);
        mpz_mul_2exp(ri, ri, 1);
        mpz_cdiv_q(ri, ri, kp.public->n);
        bool success = false;
        while(true) {
            mpz_mul(min_s, ri, kp.public->n);
            mpz_set(max_s, min_s);

            mpz_add(min_s, min_s, twoB);
            mpz_cdiv_q(min_s, min_s, max);

            mpz_add(max_s, max_s, threeB);
            mpz_fdiv_q(max_s, max_s, min);

            //gmp_printf("ri = %Zd\tSearch interval for s[%lu] : [%Zx, %Zx]\n", ri, i, min_s, max_s);

            for (mpz_set(s, min_s) ; mpz_cmp(s, max_s) <= 0 ; mpz_add_ui(s, s, 1)) {
                encrypt(enc_s, kp.public, s);
                mpz_mul(trick_cipher, mycipher, enc_s);
                if (rsa_padding_oracle(kp.private, trick_cipher)) {
                    success = true;
                    goto BREAK;
                }
            }
            mpz_add_ui(ri, ri, 1);
        }
    BREAK:
        if (!success) {
            printf("Couldn't find s[%lu]\n", i);
            exit(1);
        }
        //gmp_printf("s[%lu] = %Zx\n", i, s);

        calculate_highest_interval(min, max, last_min, last_max, r, s, twoB, threeB, kp.public->n);
    }
    assert(!mpz_cmp(max, myplain));
    byte_array cracked = mpz_to_byte_array(max);
    printf("Cracked plaintext!\n");
    printf("00"); // the way we convert mpz to byte array the leading zeros get truncated
    print_byte_array(cracked);
    byte_array cracked_plain = remove_pkcs_1_padding(cracked);
    printf("With PKCS 1.5 padding removed and printed in ASCII: ");
    print_byte_array_ascii(cracked_plain);

    free_byte_array(cracked);
    free_byte_array(cracked_plain);
    mpz_clears(twoB, threeB, myplain, mycipher, ri, r, s, enc_s, min_s, max_s, min, max, last_min, last_max, trick_cipher, (mpz_ptr)NULL);
    free_byte_array(data);
    free_byte_array(plain);
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
    free_byte_array(c_prime_ba);
    free_byte_array(p_prime_ba);
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
