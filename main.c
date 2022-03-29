#include <stdio.h>
#include <string.h>

#include "dtls.h"

#define MESSAGE "Echo this"

#define HOST "data.lab5e.com"
#define PORT "1234"

// This is a very simple
int main(int argc, char *argv[]) {
  dtls_state_t dtls;

  if (!dtls_connect(&dtls, HOST, PORT)) {
    dtls_close(&dtls);
    return 2;
  }

  printf("Connected to %s:%s\n", argv[1], argv[2]);

  if (!dtls_send(&dtls, MESSAGE, strlen(MESSAGE))) {
    dtls_close(&dtls);
    return 3;
  }
  printf("Sent message\n");

  char receive_buf[1024];
  size_t read_bytes = dtls_receive(&dtls, receive_buf, sizeof(receive_buf) - 1);
  if (read_bytes > 0) {
    printf("received %d bytes from server (%s)\n", read_bytes, receive_buf);
  }

  dtls_close(&dtls);
  printf("Closed connection\n");

  return 0;
}
