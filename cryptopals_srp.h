#pragma once
#include "cryptopals_utils.h"
#include "cryptopals_gmp.h"

// User must run init_gmp(seed) before using the functions below, and must run
// cleanup_gmp() afterward.

// Struct holding the global parameters (N, g, k) of SRP visible to everyone.
// Also includes a subsection of long-term data only visible to server.
// This is the only data that persists across different login attempts.
typedef struct srp_params srp_params;

// Session means a single login attempt. This is the ephemeral data that
// client and server calculate during a login attempt.
typedef struct srp_client_session srp_client_session;
typedef struct srp_server_session srp_server_session;

// The data that client hands to server (including username but nothing about
// password) when beginning a login attempt.
typedef struct srp_client_handshake srp_client_handshake;

// The data that server hands back to client to enable a secure exchange
// of the HMAC of the password.
typedef struct srp_server_handshake srp_server_handshake;

// Initialize server to do Secure Remote Password (SRP) protocol
srp_params * init_srp(const char * N, unsigned int g, unsigned int k);

// Register an email (username) and password combination with server.
// The protocol for doing this registration is not specified by SRP.
void register_user_server(srp_params * params,
                          const char * email,
                          const char * password,
                          const byte_array * salt);

// Client constructs handshake to begin login attempt. Allocates a
// handshake object and a session object, both of which must be freed.
srp_client_handshake * construct_client_handshake(srp_client_session ** client,
                                                  srp_params * params,
                                                  const char * email);

// Server processes client handshake and constructs its own handshake to
// return to client. Allocates a handshake object and a session object,
// both of which must be freed.
srp_server_handshake * receive_client_handshake(srp_server_session ** server,
                                                srp_params * params,
                                                srp_client_handshake * handshake);

// Client processes handshake and returns an HMAC of the shared secret.
byte_array * calculate_client_hmac(srp_client_session * client,
                                   srp_params * params,
                                   srp_server_handshake * handshake,
                                   const char * password);

// Server validates client's HMAC. If valid, server knows client has the correct
// password and function returns true. If invalid, server knows client has wrong
// password and function returns false.
bool validate_client_hmac(srp_server_session * server,
                          srp_params * params,
                          const byte_array * client_hmac);

void free_srp_params(srp_params * params);
void free_srp_client_session(srp_client_session * client);
void free_srp_client_handshake(srp_client_handshake * handshake);
void free_srp_server_session(srp_server_session * server);
void free_srp_server_handshake(srp_server_handshake * handshake);

