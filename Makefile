all:
	gcc dtls.c main.c -o dtls-sample -lmbedtls -lmbedx509 -lmbedcrypto
