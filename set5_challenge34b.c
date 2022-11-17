#include <stdio.h>
#include <stdlib.h>

#include "cryptopals_dh.h"
#include "cryptopals_derived_key.h"
#include "cryptopals.h"
#include "cryptopals_random.h"

int main(int argc, char ** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s seed\nMITM key-fixing attack on Diffie-Helman exchange\n", argv[0]);
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
    const unsigned int generator = 2;

    // Initiator generates parameters for handshake.
    dh_params initiator_params = prehandshake(modulus, generator);

    // Attacker receives public parameters and uses them to generate
    // phony parameters with public key equal to modulus.
    dh_public_params * hacked_public = hacked_params(modulus, generator);

    // Attacker sends hacked parameters instead of real ones to responder,
    // causing responder to calculate a shared secret of zero.
    dh_params responder_params = handshake1(hacked_public);

    // Responder sends its public key back to MITM attacker. Attacker ignores it
    // and sends public key equal to modulus back to intiator instead, causing
    // initiator to calculate a shared secret of zero.
    handshake2(initiator_params, hacked_public);

    // Initiator sends a message intercepted by attacker.
    byte_array message = cstring_to_bytes("Sending out an SOS.");
    printf("%-32s: ", "Initiator sends");
    print_byte_array_ascii(message);
    byte_array initiator_key = derive_key(get_shared_secret_bytes(initiator_params));
    byte_array encryption = encrypt_aes_128_cbc_prepend_iv(message, initiator_key);

    // Attacker decrypts it using the derived key of "0"
    byte_array hacked_key = derive_key("0");
    byte_array hacked_decryption1 = decrypt_aes_128_cbc_prepend_iv(encryption, hacked_key);
    printf("%-32s: ", "Hacker reads initiator's message");
    print_byte_array_ascii(hacked_decryption1);

    // Attacker passes encryption on to responder, who
    // decrypts message then echoes it back, encrypted with its own IV.
    byte_array responder_key = derive_key(get_shared_secret_bytes(responder_params));
    byte_array decryption = decrypt_aes_128_cbc_prepend_iv(encryption, responder_key);
    printf("%-32s: ", "Responder receives");
    print_byte_array_ascii(decryption);

    byte_array message2 = cstring_to_bytes("Message in a bottle.");
    printf("%-32s: ", "Responder sends");
    print_byte_array_ascii(message2);
    byte_array encryption2 = encrypt_aes_128_cbc_prepend_iv(message2, responder_key);

    printf("%-32s: ", "Hacker reads responder's message");
    byte_array hacked_decryption2 = decrypt_aes_128_cbc_prepend_iv(encryption2, hacked_key);
    print_byte_array_ascii(hacked_decryption2);
    
    // Initiator decrypts message from responder
    byte_array decryption2 = decrypt_aes_128_cbc_prepend_iv(encryption2, initiator_key);
    printf("%-32s: ", "Initiator receives");
    print_byte_array_ascii(decryption2);
    
    free_dh_params(initiator_params);
    free_hacked_params(hacked_public);
    free_dh_params(responder_params);
    free_byte_arrays(message, initiator_key, encryption, hacked_key, hacked_decryption1, responder_key,
                     decryption, message2, encryption2, hacked_decryption2, decryption2, NO_BA);

    cleanup_gmp();
    cleanup_random_encrypt();
    return 0;
}
