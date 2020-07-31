#include <stdio.h>
#include <stdlib.h>

#include "cryptopals_dh.h"
#include "cryptopals_derived_key.h"
#include "cryptopals.h"
#include "cryptopals_random.h"

// Not bothering with the MITM negotiation to fool the initiator and responder to use bad "g".
// Just assuming they've already established a bad "g" and showing the results on encryption.
int main(int argc, char ** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s seed\nMITM attack on Diffie-Helman with bad g parameter\n", argv[0]);
        return 1;
    }
    unsigned int seed =	atoi(argv[1]);
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

    const char * modulus_minus_one =
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
        "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
        "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
        "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
        "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
        "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
        "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
        "ffffffffffffe";

    const char * generators[] = {"1", modulus, modulus_minus_one};
    const char * secrets[] = {"1", "0", NULL};
    const char * description[] = {"Attack when g = 1  =>  s = 1",
                                  "Attack when g = p  =>  s = 0",
                                  "Attack when g = p-1  =>  s = 1 or s = p-1"};
    
    for (int idx = 0; idx < 3; ++idx) {
        printf("\n%s\n\n", description[idx]);
        dh_params initiator_params = prehandshake_g_hex_str(modulus, generators[idx]);
        dh_params responder_params = handshake1(initiator_params.public);
        handshake2(initiator_params, responder_params.public);

        // Initiator sends a message to responder
        byte_array * message = cstring_to_bytes("Sending out an SOS.");
        byte_array * initiator_key = derive_key(get_shared_secret_bytes(initiator_params));
        byte_array * encryption = encrypt_aes_128_cbc_prepend_iv(message, initiator_key);
        printf("%-32s: ", "Initiator sends");
        print_byte_array_ascii(message);

        byte_array * hacker_key;
        byte_array * hacker_decryption;
        if (secrets[idx]) {
            hacker_key = derive_key(secrets[idx]);
            hacker_decryption = decrypt_aes_128_cbc_prepend_iv(encryption, hacker_key);
        } else {
            printf("Attacker attempts with secret \"1\"\n");
            hacker_key = derive_key("1");
            hacker_decryption = decrypt_aes_128_cbc_prepend_iv(encryption, hacker_key);
            if (!hacker_decryption) {
                printf("Attacker attempts with secret \"p-1\"\n");
                free_byte_array(hacker_key);
                hacker_key = derive_key(modulus_minus_one);
                hacker_decryption = decrypt_aes_128_cbc_prepend_iv(encryption, hacker_key);
                if (hacker_decryption) {
                    printf("Attack succeeded!\n");
                } else {
                    fprintf(stderr, "Attack failed!\n");
                    abort();
                }
            }
        }
        printf("%-32s: ", "Hacker reads");
        print_byte_array_ascii(hacker_decryption);
        
        byte_array * responder_key = derive_key(get_shared_secret_bytes(responder_params));
        byte_array * decryption = decrypt_aes_128_cbc_prepend_iv(encryption, responder_key);
        printf("%-32s: ", "Responder reads");
        print_byte_array_ascii(decryption);

        byte_array * message2 = cstring_to_bytes("Message in a bottle.");
        byte_array * encryption2 = encrypt_aes_128_cbc_prepend_iv(message2, responder_key);
        printf("%-32s: ", "Responder sends");
        print_byte_array_ascii(message2);

        byte_array * hacker_decryption2 = decrypt_aes_128_cbc_prepend_iv(encryption2, hacker_key);
        printf("%-32s: ", "Hacker reads");
        print_byte_array_ascii(hacker_decryption2);

        byte_array * decryption2 = decrypt_aes_128_cbc_prepend_iv(encryption2, initiator_key);
        printf("%-32s: ", "Initiator reads");
        print_byte_array_ascii(decryption2);
        
        free_dh_params(initiator_params);
        free_dh_params(responder_params);
        free_byte_array(message);
        free_byte_array(initiator_key);
        free_byte_array(encryption);
        free_byte_array(hacker_key);
        free_byte_array(hacker_decryption);
        free_byte_array(responder_key);
        free_byte_array(decryption);
        free_byte_array(message2);
        free_byte_array(encryption2);
        free_byte_array(hacker_decryption2);
        free_byte_array(decryption2);
    }

    cleanup_gmp();
    cleanup_random_encrypt();
    return 0;
}
