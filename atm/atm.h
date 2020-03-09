/*
 * The ATM interfaces with the user.  User commands should be
 * handled by atm_process_command.
 *
 * The ATM can read .card files, but not .pin files.
 *
 * Feel free to update the struct and the processing as you desire
 * (though you probably won't need/want to change send/recv).
 */

#ifndef __ATM_H__
#define __ATM_H__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

typedef struct _ATM
{
    // Networking state
    int sockfd;
    struct sockaddr_in rtr_addr;
    struct sockaddr_in atm_addr;

    // Protocol state
    // TODO add more, as needed
    bool in_session;
    char *active_user;
    uint8_t key[SHA256_DIGEST_LENGTH];
} ATM;

ATM* atm_create();
void atm_free(ATM *atm);
ssize_t atm_send(ATM *atm, char *data, size_t data_len);
ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len);
void atm_process_command(ATM *atm, char *command);
uint64_t atm_dhke(ATM *atm);
ssize_t atm_recv_encrypted(ATM *atm, uint8_t *data, size_t max_data_len);
ssize_t atm_send_encrypted(ATM *atm, uint8_t *data, size_t data_len);
bool validate_card(char *username, uint8_t *card);

uint64_t atm_dhke_(ATM *atm);


#endif