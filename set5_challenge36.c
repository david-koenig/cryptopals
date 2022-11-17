#include <stdio.h>
#include <stdlib.h>

#include "cryptopals_random.h"
#include "cryptopals_srp.h"

int main(int argc, char ** argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s seed email password\nSecure Remote Password (SRP)\n", argv[0]);
        return 1;
    }
    unsigned int seed = atoi(argv[1]);
    const char * email = argv[2];
    const char * password = argv[3];
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
    
    // Server configures itself for SRP.
    srp_params * params = init_srp(modulus, 2, 3);

    // From a security point of view, either side can generate the salt, but in practice the
    // client does, so that the registration of a username/password can be done in one step.
    byte_array salt = random_128_bits();

    // Client registers its email (username) and password with server.
    register_user_server(params, email, password, salt);


    // LOGIN ATTEMPT

    // User types email into client, which constructs handshake to begin login attempt.
    srp_client_session * client;
    srp_client_handshake * client_handshake =
        construct_client_handshake(&client, params, email);

    // Server receives client handshake and now has enough information to calculate
    // shared secret. Server passes back its own handshake.
    srp_server_session * server;
    srp_server_handshake * server_handshake =
        receive_client_handshake(&server, params, client_handshake);

    // Server handshake is received, and user types password into client. Client now has
    // enough information to calculate shared secret. Client sends HMAC of shared secret
    // to server.
    byte_array hmac =
        calculate_client_hmac(client, params, server_handshake, password);

    // Server compares its HMAC of the shared secret to the one received from client,
    // and decides whether to allow the login.
    bool pass = validate_client_hmac(server, params, hmac);

    int ret;
    if (pass) {
        printf("Success. Server validates client's password securely.\n");
        ret = 0;
    } else {
        printf("Failure. Wrong username or password.\n");
        ret = 1;
    }

    free_srp_params(params);
    free_srp_client_session(client);
    free_srp_client_handshake(client_handshake);
    free_srp_server_session(server);
    free_srp_server_handshake(server_handshake);

    free_byte_arrays(hmac, salt, NO_BA);
    cleanup_gmp();
    cleanup_random_encrypt();
    return ret;
}
