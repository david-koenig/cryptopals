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
    
    const char * modulus =
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
        "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
        "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
        "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
        "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
        "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
        "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
        "fffffffffffff";
    
    byte_array * salt = random_128_bits();
    srp_params * params = init_srp(modulus, 2, 3);
    register_user_server(params, email, password, salt);

    srp_session * session = init_srp_session();
    calculate_client_keys(params, session);
    calculate_server_keys(params, session);
    calculate_u(session);

    calculate_client_shared_secret(params, session, password, salt);
    calculate_server_shared_secret(params, session);

    compare_shared_secrets(session);
    
    free_srp_params(params);
    free_srp_session(session);
    free_byte_array(salt);
    cleanup_gmp();
    cleanup_random_encrypt();
}
