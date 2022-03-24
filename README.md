# Sample DTLS client implementation with mbedtls

This is a DTLS client sample in C that uses the [mbedtls](https://tls.mbed.org) library. This is a library 
used in both Zephy, ESP-IDF and other projects. 

## Client certificate and private key

The sample code reads the certificate and private key from the files `cert.crt` and `key.pem`. Both files must be PEM-encoded. The `cert.crt` contains the client certificate, intermediates and root and the `key.pem` file contains the private key.

Use the [span CLI](https://github.com/lab5e/spancli) to generate a certificate and key file.

## Building on Raspberry Pi

This example buidls on Raspberr Pi (including Zero) - run `sudo apt-get install libmbedtls-dev` to install the mbedtls headers, then `make` to build to example. 
