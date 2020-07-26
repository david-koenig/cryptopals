#pragma once

typedef struct dh_public_params dh_public_params;
typedef struct dh_private_params dh_private_params;

typedef struct dh_params {
    dh_public_params * public;
    dh_private_params * private;
} dh_params;

// Free memory of Diffie-Hellman parameter structure
void free_dh_params(dh_params params);

// Run by initiator to initialize all Diffie-Helman parameters except shared secret.
// Generates a random private key. Parameter object must be deallocated with free_dh_params.
// inputs: modulus as null-terminated hex string, generator
dh_params prehandshake(const char * p_hex_str, unsigned int g);

// Run by responder who has been given all of initiator's public parameters. Initializes
// all of responder's Diffie-Helman parameters, including a random private key and shared
// secret. Parameter object must be deallocated with free_dh_params.
dh_params handshake1(const dh_public_params * initiator_public);

// Run by initiator who has been given responder's public key to calculate shared secret.
void handshake2(dh_params params, const dh_public_params * responder_public);

char * get_shared_secret(const dh_params params);
int get_shared_secret_len(const dh_params params);

// Create a public params struct with public key same as modulus.
// Used by man-in-the-middle hacker.
dh_public_params * hacked_params(const char * p_hex_str, unsigned int g);

// Free memory of hacked parameters object.
void free_hacked_params(dh_public_params * public);
