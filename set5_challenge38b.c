#include <stdio.h>
#include <stdlib.h>

#include "cryptopals_random.h"
#include "cryptopals_srp.h"

int main(int argc, char ** argv) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s seed email password dictionary\n"
                "Offline dictionary attack on simplified SRP\n", argv[0]);
        return 1;
    }
    unsigned int seed = atoi(argv[1]);
    const char * email = argv[2];
    const char * password = argv[3];
    const char * dictionary = argv[4];
    init_random_encrypt(seed);
    init_gmp(seed);

    // A NIST prime to be used as modulus of operations similar to Diffie-Helman key exchange.
    const char * modulus =
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
        "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
        "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
        "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
        "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
        "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
        "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
        "fffffffffffff";

    // SETUP
    
    // Simplified SRP is same as regular SRP with k=0. This still works in normal usage
    // if both sides behave well, but it creates a security weakness that a hacker can
    // take advantage of by posing as the server in a MITM attack. Attack illustrated below.
    const unsigned int g = 2;
    const unsigned int k = 0;
    srp_params * params = init_srp(modulus, g, k);

    byte_array salt = random_128_bits();
    register_user_server(params, email, password, salt);


    // LOGIN ATTEMPT

    // Client sends handshake to server, not knowing it will be intercepted by hacker.
    srp_client_session * client;
    srp_client_handshake * client_handshake =
        construct_client_handshake(&client, params, email);

    // Hacker constructs server handshake, using salt = "" and B=g (implying b=1)
    const byte_array empty = {"", 0};
    srp_server_handshake * forged_server_handshake =
        forge_server_handshake(g, empty);
    
    // Client receives handshake from hacker and passes back HMAC =
    // HMAC_SHA256(SHA256(A * (g ** SHA256(password))**SHA256(A|g) mod N))
    byte_array hmac =
        calculate_client_hmac(client, params, forged_server_handshake, password);

    // Hacker has an HMAC which contains unsalted SHA256(password). In practice,
    // hacker would precompute SHA256 of all words in his password guess dictionary,
    // which can be reused for all users. Then once he receives a particular user's
    // (A, HMAC) pair from this MITM attack, he can cycle through all of them to
    // see which one produces a matching HMAC. This attack is done offline after
    // hacker has captured the HMAC. On success, hacker knows user's password.

    // If hacker prefers, instead of an empty salt, he can use a fixed salt for all
    // users and make his precomputation table based on the fixed salt. This has
    // the additional advantage of obscuring what he is doing from users who
    // receive his forged handshakes without providing any additional work for him
    // beyond the precomputation step. It also provides a workaround for clients
    // with built-in safeguards that refuse to use an empty salt.
    
    // To simplify the code and keep this program using low memory, there is no
    // precomputation in this implementation. Program simply cycles through
    // dictionary file until it finds a password that works.

    FILE * dictionary_fp = fopen(dictionary, "r");
    if (dictionary_fp == NULL) {
	fprintf(stderr, "%s: error reading file %s\n", __func__, dictionary);
        exit(1);
    }
    ssize_t line_len;
    size_t line_cap;
    char * line = NULL;
    bool password_cracked = false;

    printf("Peforming dictionary attack. This can take some time, depending on\n"
           "size of dictionary file and how far into it the correct password is.\n");
    while ((line_len = getline(&line, &line_cap, dictionary_fp)) > 0) {
        line[line_len-1] = '\0'; // replace newline by NUL
        if (hack_client_hmac(params, client_handshake, hmac, line)) {
            password_cracked = true;
            break;
        }
    }

    if (password_cracked) {
        printf("Password cracked: %s\n", line);
    } else {
        printf("Password not found in dictionary.\n");
    }
    
    fclose(dictionary_fp);
    free(line);
    
    free_srp_params(params);
    free_srp_client_session(client);
    free_srp_client_handshake(client_handshake);
    free_srp_server_handshake(forged_server_handshake);

    free_byte_arrays(hmac, salt, NO_BA);
    cleanup_gmp();
    cleanup_random_encrypt();
    return password_cracked == false;
}
