#include <stdio.h>
#include <stdlib.h>

#include "cryptopals_random.h"
#include "cryptopals_srp.h"

int main(int argc, char ** argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s seed email password\nHack Secure Remote Password (SRP)\n", argv[0]);
        return 1;
    }
    unsigned int seed = atoi(argv[1]);
    const char * email = argv[2];
    const char * password = argv[3];
    init_random_encrypt(seed);
    init_gmp(seed);

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
    srp_params * params = init_srp(modulus, 2, 3);
    byte_array * salt = random_128_bits();
    register_user_server(params, email, password, salt);


    // HACKER LOGIN ATTEMPTS
    // Hacker does not have access to password, only email, but breaks in anyway.
    // Hacker needs no prior knowledge of salt, as server will return it in handshake.

    int ret = 0;
    for (unsigned int multiplier = 0; multiplier < 5; ++multiplier) {
        srp_client_handshake * client_handshake =
            forge_client_handshake(modulus, multiplier, email);

        // Server does not have safeguard for bad A value and will calculate a shared secret
        // of "0". Server passes back its own handshake.
        srp_server_session * server;
        srp_server_handshake * server_handshake =
            receive_client_handshake(&server, params, client_handshake);

        // Hacker has forced bad shared secret value, and calculates HMAC based on that.
        byte_array * hmac = forge_hmac("0", get_salt_const_p(server_handshake));

        // Server validates hacker who never had the password, unless it has safeguards to
        // prevent use of bad A value.
        bool pass = validate_client_hmac(server, params, hmac);

        if (pass) {
            printf("Success. Hacker broke in without password using A = modulus * %d.\n", multiplier);
        } else {
            printf("Failure. Hacker denied entry using A = modulus * %d.\n", multiplier);
            ++ret;
        }

        free_srp_client_handshake(client_handshake);
        free_srp_server_session(server);
        free_srp_server_handshake(server_handshake);
        free_byte_array(hmac);
    }

    free_srp_params(params);
    free_byte_array(salt);
    cleanup_gmp();
    cleanup_random_encrypt();
    return ret;
}
