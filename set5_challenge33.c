#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <assert.h>

int main(int argc, char ** argv) {
    gmp_randstate_t state;
    gmp_randinit_default(state);

    mpz_t p, g, a, A, b, B, s1, s2;

    mpz_init_set_str(p,
                     "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
                     "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
                     "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
                     "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
                     "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
                     "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
                     "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
                     "fffffffffffff", 16);
    mpz_init_set_ui(g, 2);
    mpz_inits(a, A, b, B, s1, s2, (mpz_ptr)NULL);

    // a is a private key and A the public key generated from it.
    mpz_urandomm(a, state, p);
    // A = (g ** a) mod p
    mpz_powm(A, g, a, p);
    
    // b is a private key and B the public key generated from it.
    mpz_urandomm(b, state, p);
    // B = (g ** b) mod p
    mpz_powm(B, g, b, p);

    // Each side generates the same session key with their private
    // key and the other side's public key.

    // s = (B ** a) = (A ** b) mod p
    mpz_powm(s1, B, a, p);
    mpz_powm(s2, A, b, p);

    assert(!mpz_cmp(s1, s2));
    printf("Shared secret established!\n");

    mpz_clears(p, g, a, A, b, B, s1, s2, (mpz_ptr)NULL);
    gmp_randclear(state);

    return 0;
}
