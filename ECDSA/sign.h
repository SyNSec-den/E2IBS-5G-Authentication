#ifndef HEADERFILE_H
#define HEADERFILE_H
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <stdbool.h>
#include <assert.h>

bool verifyECDSASign(char* data,size_t len,unsigned char* sign,size_t sign_len);
void createECDSASign(char* data,size_t len,unsigned char** sign,size_t* sign_len );
unsigned char* getDigest(char* data, size_t len);
void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length);
void Base64Encode( const unsigned char* buffer, size_t length, char** base64Text);
size_t calcDecodeLength(const char* b64input);
int generateKeys();

// keys
char* publicKey;
char* privateKey;
char* trust_anchor_pub;

/* 
char* trust_anchor =  "-----BEGIN CERTIFICATE-----\n" \
                      "MIIB1zCCAToCAQEwCQYHKoZIzj0EATA1MQswCQYDVQQGEwJVUzESMBAGA1UECgwJ\n" \
                      "Q2FibGVMYWJzMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjIwNjEzMjAyNTA0WhcN\n" \
                      "MjMwNjEzMjAyNTA0WjA1MQswCQYDVQQGEwJVUzESMBAGA1UECgwJQ2FibGVMYWJz\n" \
                      "MRIwEAYDVQQDDAlsb2NhbGhvc3QwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAE6\n" \
                      "VV0gKdp6mNJNagDoTURy5HnIL8pU4psOE6J9QHP1JKwGlRc87NjA8SdcdJztwnUa\n" \
                      "6Z7Z80sGzTIB4JYmgiPBWAH1wD/tkktBF9r5znsGI33CCeUxKprDaU4fmcEmPLx9\n" \
                      "KweTddfWPaPL6e+6wcPJIwTfpYOkb6nXWI2d3YBIGNL/5DAJBgcqhkjOPQQBA4GL\n" \
                      "ADCBhwJCAPCNxUilfH+zOBcJy7rg0S/A2YqNNpXNmm+aq4Ev8Lp83CHf6+CrzL9v\n" \
                      "jVnJE+d36SwHRA7tj7xxVZ8GZKw6+4AWAkEUm27C77njfwFMpZNof9rTzqH1tyNc\n" \
                      "wTiWeF5AHx2OR1U2VmP9o/aQaKSlddjsyNATMyY33EBk+4EUPs5dWEm7fg==\n" \
                      "-----END CERTIFICATE-----\n";
*/
#endif