#include "cryptopals_dsa.h"
#include "cryptopals_gmp_private.h"
#include "cryptopals_hash.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

typedef struct dsa_params {
    mpz_t p;
    mpz_t q;
    mpz_t g;
    byte_array (*hash)(const byte_array);
} dsa_params;

typedef struct dsa_private_key {
    mpz_t x;
} dsa_private_key;

typedef struct dsa_public_key {
    mpz_t y;
} dsa_public_key;

typedef struct dsa_sig {
    mpz_t r;
    mpz_t s;
} dsa_sig;

void free_dsa_params(const dsa_params * params) {
    dsa_params * p = (dsa_params *)params;
    mpz_clears(p->p, p->q, p->g, (mpz_ptr)NULL);
    free(p);
}

void free_dsa_private_key(const dsa_private_key * key) {
    dsa_private_key * k = (dsa_private_key *)key;
    mpz_clear(k->x);
    free(k);
}

void free_dsa_public_key(const dsa_public_key * key) {
    dsa_public_key * k = (dsa_public_key *)key;
    mpz_clear(k->y);
    free(k);
}

void free_dsa_sig(const dsa_sig * sig) {
    dsa_sig * s = (dsa_sig *)sig;
    mpz_clear(s->r);
    mpz_clear(s->s);
    free(s);
}

const dsa_params * dsa_paramgen() {
    dsa_params * params = malloc(sizeof(dsa_params));
    mpz_init_set_str(params->p,
                     "800000000000000089e1855218a0e7dac38136ffafa72eda7"
                     "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"
                     "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"
                     "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"
                     "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"
                     "1a584471bb1", 16);
    mpz_init_set_str(params->q,
                     "f4f47f05794b256174bba6e9b396a7707e563c5b", 16);
    mpz_init_set_str(params->g,
                     "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"
                     "458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"
                     "322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047"
                     "0f5b64c36b625a097f1651fe775323556fe00b3608c887892"
                     "878480e99041be601a62166ca6894bdd41a7054ec89f756ba"
                     "9fc95302291", 16);
    params->hash = sha1;
    return params;
}

const dsa_params * dsa_param_g0() {
    dsa_params * params = (dsa_params *)dsa_paramgen();
    mpz_set_ui(params->g, 0);
    return params;
}

const dsa_params * dsa_param_g1() {
    dsa_params * params = (dsa_params *)dsa_paramgen();
    mpz_add_ui(params->g, params->p, 1);
    return params;
}

dsa_key_pair dsa_keygen(const dsa_params * params) {
    dsa_key_pair kp;
    dsa_private_key ** private = (dsa_private_key **) &kp.private;
    dsa_public_key ** public = (dsa_public_key **) &kp.public;
    *private = malloc(sizeof(dsa_private_key));
    *public = malloc(sizeof(dsa_public_key));
    mpz_inits((*private)->x, (*public)->y, (mpz_ptr)NULL);
    do {
        mpz_urandomm((*private)->x, cryptopals_gmp_randstate, params->q);
    } while (!mpz_cmp_ui((*private)->x, 0));
    mpz_powm((*public)->y, params->g, (*private)->x, params->p);
    return kp;
}

dsa_key_pair random_key_pair(const dsa_params * params) {
    dsa_key_pair kp;
    dsa_private_key ** private = (dsa_private_key **) &kp.private;
    dsa_public_key ** public = (dsa_public_key **) &kp.public;
    *private = malloc(sizeof(dsa_private_key));
    *public = malloc(sizeof(dsa_public_key));
    mpz_inits((*private)->x, (*public)->y, (mpz_ptr)NULL);
    mpz_urandomm((*private)->x, cryptopals_gmp_randstate, params->q);
    mpz_urandomm((*public)->y, cryptopals_gmp_randstate, params->p);
    return kp;
}

// inverse of k is calculated outside of this just to avoid doing any allocations here
static void calculate_sig(dsa_sig * sig, const dsa_params * params, const mpz_t priv, const mpz_t dgst, const mpz_t k, const mpz_t k_inv) {
    mpz_powm(sig->r, params->g, k, params->p);
    mpz_mod(sig->r, sig->r, params->q);

    mpz_mul(sig->s, priv, sig->r);
    mpz_mod(sig->s, sig->s, params->q);
    mpz_add(sig->s, sig->s, dgst);
    mpz_mod(sig->s, sig->s, params->q);
    mpz_mul(sig->s, sig->s, k_inv);
    mpz_mod(sig->s, sig->s, params->q);
}

const dsa_sig * dsa_sign(const dsa_params * params, const dsa_private_key * priv, const byte_array msg) {
    dsa_sig * sig;
    sig = malloc(sizeof(dsa_sig));
    mpz_t k, k_inv, dgst;
    mpz_inits(sig->r, sig->s, k, k_inv, dgst, (mpz_ptr)NULL);
    byte_array digest = params->hash(msg);
    byte_array_to_mpz(dgst, digest);
    
    mpz_urandomm(k, cryptopals_gmp_randstate, params->q);
    mpz_invert(k_inv, k, params->q);

    calculate_sig(sig, params, priv->x, dgst, k, k_inv);

    mpz_clears(k, k_inv, dgst, (mpz_ptr)NULL);
    free_byte_array(digest);
    return sig;
}

bool dsa_verify(const dsa_params * params, const dsa_public_key * pub, const byte_array msg, const dsa_sig * sig) {
    mpz_t w, u1, u2, v1, v2, v, dgst;
    mpz_inits(w, u1, u2, v1, v2, v, dgst, (mpz_ptr)NULL);
    mpz_invert(w, sig->s, params->q);
    
    byte_array digest = params->hash(msg);
    byte_array_to_mpz(dgst, digest);
    mpz_mul(u1, dgst, w);
    mpz_mod(u1, u1, params->q);

    mpz_mul(u2, sig->r, w);
    mpz_mod(u2, u2, params->q);

    mpz_powm(v1, params->g, u1, params->p);
    mpz_powm(v2, pub->y, u2, params->p);
    mpz_mul(v, v1, v2);
    mpz_mod(v, v, params->p);
    mpz_mod(v, v, params->q);

    bool ret = !mpz_cmp(sig->r, v);
    free_byte_array(digest);
    mpz_clears(w, u1, u2, v1, v2, v, dgst, (mpz_ptr)NULL);
    return ret;
}

//          (s * k) - H(msg)
//      x = ----------------  mod q
//                  r
static void priv_from_k(mpz_t priv, const mpz_t k, const mpz_t r_inv, const mpz_t s, const mpz_t dgst, const mpz_t q) {
    mpz_mul(priv, s, k);
    mpz_sub(priv, priv, dgst);
    mpz_mod(priv, priv, q);
    mpz_mul(priv, priv, r_inv);
    mpz_mod(priv, priv, q);
}

static bool sig_eq(const dsa_sig * sig1, const dsa_sig * sig2) {
    return !(mpz_cmp(sig1->r, sig2->r) || mpz_cmp(sig1->s, sig2->s));
}

static const char * pubkeys[] =
{
    // challenge 43
    "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4"
    "abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004"
    "e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed"
    "1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b"
    "bb283e6633451e535c45513b2d33c99ea17",
    // challenge 44
    "2d026f4bf30195ede3a088da85e398ef869611d0f68f07"
    "13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8"
    "5519b1c23cc3ecdc6062650462e3063bd179c2a6581519"
    "f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430"
    "f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3"
    "2971c3de5084cce04a2e147821"
};

static const dsa_public_key * fixed_pubkey(const char * keystr) {
    dsa_public_key * k;
    k = malloc(sizeof(dsa_public_key));
    mpz_init_set_str(k->y, keystr, 16);
    return k;
}

static const dsa_sig * challenge_43_sig() {
    dsa_sig * sig;
    sig = malloc(sizeof(dsa_sig));
    mpz_init_set_str(sig->r, "548099063082341131477253921760299949438196259240", 10);
    mpz_init_set_str(sig->s, "857042759984254168557880549501802188789837994940", 10);
    return sig;
}

bool challenge_43() {
    const dsa_public_key * pub = fixed_pubkey(pubkeys[0]);
    const dsa_sig * sig = challenge_43_sig();
    const dsa_params * params = dsa_paramgen();
    byte_array msg = cstring_to_bytes(
        "For those that envy a MC it can be hazardous to your health\n"
        "So be friendly, a matter of life and death, just like a etch-a-sketch\n"
        );

    assert(dsa_verify(params, pub, msg, sig));
    printf("Material provided in problem 43 passes signature verification.\n");

    mpz_t dgst;
    byte_array digest = params->hash(msg);
    byte_array_to_mpz_init(dgst, digest);

    mpz_t k, k_inv, r_inv, priv;
    mpz_inits(k_inv, r_inv, priv, (mpz_ptr)NULL);
    mpz_invert(r_inv, sig->r, params->q);

    dsa_sig * sig_guess = malloc(sizeof(dsa_sig));
    mpz_init(sig_guess->r);
    mpz_init(sig_guess->s);

    bool success = false;
    for (mpz_init_set_ui(k, 1) ; mpz_cmp_ui(k, 1UL<<16) < 0 ; mpz_add_ui(k, k, 1)) {
        if(!mpz_invert(k_inv, k, params->q)) {
            continue;
        }

        priv_from_k(priv, k, r_inv, sig->s, dgst, params->q);
        calculate_sig(sig_guess, params, priv, dgst, k, k_inv);

        if (sig_eq(sig_guess, sig)) {
            gmp_printf("Cracked key: %Zx\nSHA1(key): ", priv);
            byte_array priv_hex = mpz_to_hex(priv);
            byte_array priv_sha1 = sha1(priv_hex);
            print_byte_array(priv_sha1);
            free_byte_array(priv_hex);
            free_byte_array(priv_sha1);
            success = true;
        }
    }
    if (!success) {
        printf("Couldn't crack key!\n");
    }
    mpz_clears(dgst, k, k_inv, r_inv, priv, (mpz_ptr)NULL);
    free_dsa_params(params);
    free_dsa_public_key(pub);
    free_dsa_sig(sig_guess);
    free_dsa_sig(sig);
    free_byte_array(msg);
    free_byte_array(digest);
    return success;
}

bool challenge_44() {
    struct {
        char * msg; // ASCII bytes
        char * s; // DSA sig in decimal
        char * r; // DSA sig in decimal
        char * sha1; // SHA1(msg) in hex
    } data[] = {
        {
            "When me rockin' the microphone me rock on steady, ",
            "277954141006005142760672187124679727147013405915",
            "228998983350752111397582948403934722619745721541",
            "21194f72fe39a80c9c20689b8cf6ce9b0e7e52d4"
        },{
            "Where me a born in are de one Toronto, so ",
            "458429062067186207052865988429747640462282138703",
            "228998983350752111397582948403934722619745721541",
            "d6340bfcda59b6b75b59ca634813d572de800e8f"
        }
    };
    const dsa_params * params = dsa_paramgen();
    mpz_t dgst_diff, s_diff, k;
    mpz_t dgst[2];
    dsa_sig sig[2];
    mpz_init(dgst_diff);
    mpz_init(s_diff);
    mpz_init(k);

    for (int idx = 0; idx < 2; idx++) {
        mpz_init_set_str(dgst[idx], data[idx].sha1, 16);
        mpz_init_set_str(sig[idx].s, data[idx].s, 10);
        mpz_init_set_str(sig[idx].r, data[idx].r, 10);
    }

    // Any two signatures that reuse the same nonce have matching r values.
    // We just need to take any pair with the same r, and then calculate k.

    // H(m1) = k*s1 - xr (mod q)
    // H(m2) = k*s2 - xr (mod q)

    // Subtracting one equation from the other:
    // H(m1) - H(m2) = k*(s1 - s2)
    // k = (H(m1) - H(m2))*inv(s1 - s2)
    mpz_sub(dgst_diff, dgst[0], dgst[1]);
    mpz_sub(s_diff, sig[0].s, sig[1].s);
    mpz_invert(s_diff, s_diff, params->q);
    mpz_mul(k, dgst_diff, s_diff);
    mpz_mod(k, k, params->q);

    mpz_t r_inv, priv;
    mpz_init(priv);
    mpz_init(r_inv);
    mpz_invert(r_inv, sig[0].r, params->q);
    priv_from_k(priv, k, r_inv, sig[0].s, dgst[0], params->q);
    gmp_printf("Cracked key: %Zx\nSHA1(key): ", priv);
    byte_array priv_hex = mpz_to_hex(priv);
    byte_array priv_sha1 = sha1(priv_hex);
    print_byte_array(priv_sha1);

    free_byte_array(priv_hex);
    free_byte_array(priv_sha1);

    // We've already cracked the private key without ever calculating or
    // verifying a signature. We didn't even need the public key. But as a
    // common-sense check, let's verify that both signatures validate with
    // the public key, and that we can recalculate the same signatures.

    const dsa_public_key * pub = fixed_pubkey(pubkeys[1]);
    byte_array msg[2] = {{data[0].msg, strlen(data[0].msg)}, {data[1].msg, strlen(data[1].msg)}};
    dsa_sig same_sig[2];
    mpz_t k_inv;
    mpz_inits(same_sig[0].r, same_sig[0].s, same_sig[1].r, same_sig[1].s, k_inv, (mpz_ptr)NULL);
    mpz_invert(k_inv, k, params->q);
    for (int idx = 0 ; idx < 2 ; idx++) {
        assert(dsa_verify(params, pub, msg[idx], &sig[idx]));
        calculate_sig(&same_sig[idx], params, priv, dgst[idx], k, k_inv);
        assert(sig_eq(&sig[idx], &same_sig[idx]));
    }

    mpz_clears(dgst_diff, s_diff, k, dgst[0], dgst[1], sig[0].r, sig[0].s, sig[1].r, sig[1].s,
               r_inv, priv, same_sig[0].r, same_sig[0].s, same_sig[1].r, same_sig[1].s, k_inv,
               (mpz_ptr)NULL);
    free_dsa_params(params);
    free_dsa_public_key(pub);
    return true;
}

const dsa_sig * random_s_set_r(const dsa_params * params, unsigned long int r) {
    dsa_sig * sig;
    sig = malloc(sizeof(dsa_sig));
    mpz_inits(sig->r, sig->s, (mpz_ptr)NULL);
    mpz_set_ui(sig->r, r);
    mpz_urandomm(sig->s, cryptopals_gmp_randstate, params->q);
    return sig;
}

void print_sig(const dsa_sig * sig) {
    gmp_printf("r = %Zx\ns = %Zx\n", sig->r, sig->s);
}

const dsa_sig * magic_sig(const dsa_params * params, const dsa_public_key * key) {
    dsa_sig * sig;
    mpz_t z;
    sig = malloc(sizeof(dsa_sig));
    mpz_inits(z, sig->r, sig->s, (mpz_ptr)NULL);
    mpz_urandomm(z, cryptopals_gmp_randstate, params->q);
    mpz_powm(sig->r, key->y, z, params->p);
    mpz_mod(sig->r, sig->r, params->q);

    mpz_invert(z, z, params->q);
    mpz_mul(sig->s, sig->r, z);
    mpz_mod(sig->s, sig->s, params->q);
    mpz_clear(z);
    return sig;
}
