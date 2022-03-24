#pragma once

#include <stdbool.h>
#include <stdio.h>

// This is the certificate file. If the file is added as an include of sorts in
// the
#define CERTFILE "cert.crt"
#define KEYFILE "key.pem"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/timing.h"

/**
 * Struct to hold the internal state of the DTLS connection.
 */
typedef struct dtls_state_s {
  mbedtls_net_context server_fd;
  mbedtls_entropy_context entropy;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_timing_delay_context timer;
  mbedtls_x509_crt all_certs;
  mbedtls_pk_context private_key;
  mbedtls_x509_crt *client_cert;
  mbedtls_x509_crt *ca_chain;
} dtls_state_t;

/**
 * Connect to the server.
 */
bool dtls_connect(dtls_state_t *state, const char *server_addr,
                  const char *port);

/**
 * Send data to peer.
 */
bool dtls_send(dtls_state_t *state, const void *buf, size_t len);

/**
 * Receive data from peer.
 */
size_t dtls_receive(dtls_state_t *state, void *buf, size_t len);

/**
 * Close connection and release resources
 */
bool dtls_close(dtls_state_t *state);
