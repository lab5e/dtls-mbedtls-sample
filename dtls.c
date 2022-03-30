#include "dtls.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include <string.h>

const char *pers = "dtls_client1";

// Debug level for mbedtls. Set to 0 for no output, 5 for very verbose output.
// This can be useful if you have to debug the traffic.
#define DEBUG_LEVEL 0

// Read timeout is set to 1 second. This can be increased or decreased as
// needed, depending on the latency of the network. Cellular IoT networks might
// have latencies of multiple seconds, Roundtrip times on the Internet might be
// 500 ms or more.
#define READ_TIMEOUT_MS 1000

/* -----------------------------------------------------------------------------------------
 * Debug function for the mbedtls library
 */
static void debug_print(void *ctx, int level, const char *file, int line,
                        const char *str) {
  printf("Debug: %s:%04d: %s\n", file, line, str);
}

/* -----------------------------------------------------------------------------------------
 * Print mbedtls error
 */
void print_mbedtls_error(const char *msg, int err) {
  char error_buf[100];
  mbedtls_strerror(err, error_buf, 100);
  printf("%s: %d - %s\n", msg, err, error_buf);
}

/* -----------------------------------------------------------------------------------------
 * Connect to the server
 */
bool dtls_connect(dtls_state_t *state, const char *server_addr,
                  const char *port) {
  int ret = 0;

  // Set up socket descriptors
  mbedtls_net_init(&state->fd);

  // Set up SSL configuration
  mbedtls_ssl_config_init(&state->conf);
  // Set defaults for configuration
  if ((ret = mbedtls_ssl_config_defaults(&state->conf, MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    print_mbedtls_error("Error configuring defaults", ret);
    return false;
  }

  // Set up up entropy
  mbedtls_entropy_init(&state->entropy);

  // Set up context for RNG
  mbedtls_ctr_drbg_init(&state->ctr_drbg);
  // Seed RNG
  if ((ret = mbedtls_ctr_drbg_seed(&state->ctr_drbg, mbedtls_entropy_func,
                                   &state->entropy, (const unsigned char *)pers,
                                   strlen(pers))) != 0) {
    print_mbedtls_error("Error initalizing seed", ret);
    return false;
  }

  // Assign RNG to the TLS config
  mbedtls_ssl_conf_rng(&state->conf, mbedtls_ctr_drbg_random, &state->ctr_drbg);

  // Set up SSL connection
  mbedtls_ssl_init(&state->ssl);

  // Set up certificate chain
  mbedtls_x509_crt_init(&state->all_certs);

  // Set debug level
  mbedtls_debug_set_threshold(DEBUG_LEVEL);

  // Parse certificates
  ret = mbedtls_x509_crt_parse_file(&state->all_certs, CERTFILE);
  if (ret < 0) {
    print_mbedtls_error("Error parsing certificate file", ret);
    return false;
  }

  // The certificate file has a series of certificates. The first one must be
  // the client certificate and the rest is the intermediate and root CA. The
  // client cert is set to the first and the ca_chain
  state->client_cert = &state->all_certs;
  state->ca_chain = state->all_certs.next;

  // Load the private key
  mbedtls_pk_init(&state->private_key);
  ret = mbedtls_pk_parse_keyfile(&state->private_key, KEYFILE, NULL);
  if (ret < 0) {
    print_mbedtls_error("Error parsing key file", ret);
    return false;
  }

  // Set debug output
  mbedtls_ssl_conf_dbg(&state->conf, debug_print, stdout);

  // Set configuration options
  // Verify server certificates
  mbedtls_ssl_conf_authmode(&state->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  // Set the trusted certificates for the session, ie the ones in the
  // certificate file
  mbedtls_ssl_conf_ca_chain(&state->conf, state->ca_chain, NULL);
  // Set read timeout
  mbedtls_ssl_conf_read_timeout(&state->conf, READ_TIMEOUT_MS);
  // Client certificate
  mbedtls_ssl_conf_own_cert(&state->conf, state->client_cert,
                            &state->private_key);
  // Enable CA list
  mbedtls_ssl_conf_cert_req_ca_list(&state->conf,
                                    MBEDTLS_SSL_CERT_REQ_CA_LIST_ENABLED);

  // Assign configuration to SSL connection
  if ((ret = mbedtls_ssl_setup(&state->ssl, &state->conf)) != 0) {
    print_mbedtls_error("Error setting up SSL connection", ret);
    return false;
  }

  // Connect the underlying socket
  ret =
      mbedtls_net_connect(&state->fd, server_addr, port, MBEDTLS_NET_PROTO_UDP);
  if (ret != 0) {
    print_mbedtls_error("Error connecting", ret);
    return false;
  }

  // Link the socket weapper to the TLS session structure and assign the send
  // and receive functions that will be used. This is the default send and
  // receive functions
  mbedtls_ssl_set_bio(&state->ssl, &state->fd, mbedtls_net_send,
                      mbedtls_net_recv, mbedtls_net_recv_timeout);

  // Set timer callbacks
  mbedtls_ssl_set_timer_cb(&state->ssl, &state->timer, mbedtls_timing_set_delay,
                           mbedtls_timing_get_delay);

  // Do the handshake. This sets up the connection
  do {
    ret = mbedtls_ssl_handshake(&state->ssl);
  } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  if (ret != 0) {
    // If the handshake fails the CA certificates are probably out of whack.
    print_mbedtls_error("Error doing DTLS handshake", ret);
    return false;
  }

  uint32_t flags = 0;

  // Verify results from the handshake
  if ((flags = mbedtls_ssl_get_verify_result(&state->ssl)) != 0) {
    char vrfy_buf[2048];
    mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
    printf("Failed certificate verification: %s\n", vrfy_buf);
    return false;
  }
  return true;
}

/* -----------------------------------------------------------------------------------------
 * Send data to server
 */
bool dtls_send(dtls_state_t *state, const void *buf, size_t len) {
  int ret = 0;
  do {
    ret = mbedtls_ssl_write(&state->ssl, buf, len);
  } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE);
  if (ret < 0) {
    print_mbedtls_error("Error sending data to server", ret);
    return false;
  }
  return true;
}

/* -----------------------------------------------------------------------------------------
 * Receive data from server
 */
size_t dtls_receive(dtls_state_t *state, void *buf, size_t len) {
  int ret = 0;
  do {
    ret = mbedtls_ssl_read(&state->ssl, buf, len);
  } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  if (ret <= 0) {
    switch (ret) {
    case MBEDTLS_ERR_SSL_TIMEOUT:
      printf("Receive timeout\n");
      return 0;

    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
      printf("Connection was closed gracefully\n");
      return 0;

    default:
      print_mbedtls_error("Error reading data from server", ret);
      return 0;
    }
  }
  return (size_t)ret;
}

/* -----------------------------------------------------------------------------------------
 * Close DTLS connection and release resources
 */
bool dtls_close(dtls_state_t *state) {
  int ret = 0;
  /* No error checking, the connection might be closed already */
  do {
    ret = mbedtls_ssl_close_notify(&state->ssl);
  } while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  mbedtls_net_free(&state->fd);
  mbedtls_x509_crt_free(&state->all_certs);
  mbedtls_ssl_free(&state->ssl);
  mbedtls_ssl_config_free(&state->conf);
  mbedtls_ctr_drbg_free(&state->ctr_drbg);
  mbedtls_entropy_free(&state->entropy);
  mbedtls_pk_free(&state->private_key);
  return true;
}