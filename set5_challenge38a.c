#include <stdio.h>
#include <stdlib.h>

#include "cryptopals_random.h"
#include "cryptopals_srp.h"

int main(int argc, char ** argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s seed email password\n"
                "Simplified SRP normal usage\n", argv[0]);
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
    
    // Simplified SRP is same as regular SRP with k=0. This still works in normal usage
    // if both sides behave well, but it creates a security weakness that a hacker can
    // take advantage of by posing as the server in a MITM attack. Normal usage is below.
    srp_params * params = init_srp(modulus, 2, 0);

    byte_array * salt = random_128_bits();
    register_user_server(params, email, password, salt);


    // LOGIN ATTEMPT

    // k is not used in construction of client handshake, so protocol unchanged so far.
    srp_client_session * client;
    srp_client_handshake * client_handshake =
        construct_client_handshake(&client, params, email);

    // Server's public key calculation simplifies to: B = kv + g**b = g**b mod N
    srp_server_session * server;
    srp_server_handshake * server_handshake =
        receive_client_handshake(&server, params, client_handshake);

    // Client's shared secret calculation simplifies to: S = B ** (a + u * x) mod N
    byte_array * hmac =
        calculate_client_hmac(client, params, server_handshake, password);

    // Server's shared secret calculation is unchanged: S = (A * v ** u)**b mod N
    bool pass = validate_client_hmac(server, params, hmac);

    int ret;
    if (pass) {
        printf("Success. Server validates client's password using simplified SRP.\n");
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

    free_byte_array(hmac);
    free_byte_array(salt);
    cleanup_gmp();
    cleanup_random_encrypt();
    return ret;
}
