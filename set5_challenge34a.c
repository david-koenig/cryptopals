#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "cryptopals_dh.h"
#include "cryptopals_derived_key.h"
#include "cryptopals.h"
#include "cryptopals_random.h"

int main(int argc, char ** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s seed\nNormal Diffie-Helman exchange\n", argv[0]);
        return 1;
    }
    init_random_encrypt(atoi(argv[1]));
    
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

    dh_params initiator_params = prehandshake(modulus, generator);
    dh_params responder_params = handshake1(initiator_params.public);
    handshake2(initiator_params, responder_params.public);

    // initiator sends a message to responder
    byte_array * message = cstring_to_bytes("Sending out an SOS. Message in a bottle.");
    byte_array * initiator_key = derive_key(get_shared_secret(initiator_params));
    byte_array * encryption = encrypt_aes_128_cbc_prepend_iv(message, initiator_key);

    // responder decrypts message then echoes it back, encrypted with its own IV
    byte_array * responder_key = derive_key(get_shared_secret(responder_params));
    byte_array * decryption = decrypt_aes_128_cbc_prepend_iv(encryption, responder_key);
    byte_array * reencryption = encrypt_aes_128_cbc_prepend_iv(decryption, responder_key);

    // initiator decrypts message from responder and prints out both original message and response
    byte_array * redecryption = decrypt_aes_128_cbc_prepend_iv(reencryption, initiator_key);
    printf("Sent     : ");
    print_byte_array_ascii(message);
    printf("Received : ");
    print_byte_array_ascii(redecryption);
    assert(byte_arrays_equal(message, redecryption));
    printf("Response matches!\n");
    
    free_dh_params(initiator_params);
    free_dh_params(responder_params);
    free_byte_array(message);
    free_byte_array(initiator_key);
    free_byte_array(encryption);
    free_byte_array(responder_key);
    free_byte_array(decryption);
    free_byte_array(reencryption);
    free_byte_array(redecryption);
    cleanup_random_encrypt();
    return 0;
}
