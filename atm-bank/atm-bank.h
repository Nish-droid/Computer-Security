#ifndef __ATMBANK_H__
#define __ATMBANK_H__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <endian.h>
#include <limits.h>
#include <openssl/ecdh.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

#define P                 23
#define G                 5
#define SECRET_LEN        32
#define HEADER_LEN        9
#define IV                (uint8_t *)"0000000000000000"
#define MAX_PACKET_SIZE   1000
#define PIN_SIZE          4
#define MAX_USERNAME_SIZE 250
#define MAGIC_NUMBER      0x24050710
#define BEGIN_REQ		  0x7F
#define BEGIN_FAIL		  0x29
#define BEGIN_SUCCESS     0xE6
#define PIN_REQ	          0x88
#define PIN_RESP		  0xB1
#define AUTHORIZED        0xFB
#define NOT_AUTHORIZED    0x33
#define WITHDRAW_REQ	  0x59
#define WITHDRAW_FAIL	  0xB3
#define WITHDRAW_SUCCESS  0xA9
#define BALANCE_REQ	      0x91
#define BALANCE_FAIL	  0xC3
#define BALANCE_SUCCESS	  0x66
#define END_REQ           0x7B
#define END_FAIL          0x2E
#define END_SUCCESS       0xFF
#define NO_USER_EXISTS	  0x51


typedef struct _Header
{
	uint32_t len;
	uint32_t magic;
	uint8_t  cmd;
} __attribute__((packed)) Header;

typedef struct _Cipher
{
	uint16_t len;
	uint8_t ciphertext[MAX_PACKET_SIZE];
} __attribute__((packed)) Cipher;

typedef struct _KE
{
	uint32_t len;
	BIO *key;
} __attribute__((packed)) KE;

typedef struct derivedKey {
    uint8_t* secret;
    int length;
} derivedKey;

int64_t power(int64_t a, int64_t b, int64_t p);
void get_key(uint64_t shared, uint8_t *key, uint8_t *input, uint16_t input_len);
void get_hash (uint8_t *input, size_t len, uint8_t *output);
int decrypt(uint8_t *ciphertext, int ciphertext_len, uint8_t *key,
            uint8_t *iv, uint8_t *plaintext);
int encrypt(uint8_t *plaintext, int plaintext_len,
            uint8_t *key, uint8_t *iv,
            uint8_t *ciphertext);
bool validate_pin (char *pin);
bool validate_username (char* username);
bool validate_balance (int balance);
Header *create_header(uint32_t len, char cmd);
void remove_newline(char *line);
derivedKey* deriveShared(EVP_PKEY *publicKey, EVP_PKEY *privateKey);
EVP_PKEY* extractPublicKey(EVP_PKEY *privateKey);
EVP_PKEY* generateKey();
void handleErrors();
void handleDerivationErrors(int x);
bool validate_amount (long int amount);
bool checkDigits(char * str, int len); //signature for new method -kthant
#endif
