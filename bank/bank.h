/*
 * The Bank takes commands from stdin as well as from the ATM.  
 *
 * Commands from stdin be handled by bank_process_local_command.
 *
 * Remote commands from the ATM should be handled by
 * bank_process_remote_command.
 *
 * The Bank can read both .card files AND .pin files.
 *
 * Feel free to update the struct and the processing as you desire
 * (though you probably won't need/want to change send/recv).
 */

#ifndef __BANK_H__
#define __BANK_H__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "util/hash_table.h"
#include "atm-bank/atm-bank.h"

typedef struct _User
{
	char username[MAX_USERNAME_SIZE + 1];
	char pin[PIN_SIZE + 1];
	uint32_t balance;
	bool active;
    uint8_t card[SHA256_DIGEST_LENGTH + 1]; 
} User;

typedef struct _Bank
{
    // Networking state
    int sockfd;
    struct sockaddr_in rtr_addr;
    struct sockaddr_in bank_addr;

    // Protocol state
    // TODO add more, as needed
    uint8_t key[SHA256_DIGEST_LENGTH];
    HashTable *user_db;
    User *active_user;
} Bank;

Bank* bank_create();
bool user_exists(Bank *bank, char *username);
ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len);
ssize_t bank_recv_encrypted(Bank *bank, uint8_t *data, size_t max_data_len);
ssize_t bank_send(Bank *bank, char *data, size_t data_len);
ssize_t bank_send_encrypted(Bank *bank, uint8_t *data, size_t data_len);
uint64_t bank_dhke(Bank *bank);
User *create_new_user(char* username, int user_len, char *pin, uint32_t balance);
void balance_command(Bank *bank, char *command, size_t len);
void bank_free(Bank *bank);
void bank_process_local_command(Bank *bank, char *command, size_t len);
void bank_process_remote_command(Bank *bank, char *command, size_t len);
void create_user_command(Bank *bank, char *command, size_t len);
void deposit_command(Bank *bank, char *command, size_t len);
void begin_remote_command (Bank *bank, char *command);
void withdraw_remote_command (Bank *bank, char *command);
void balance_remote_command (Bank *bank, char *command);
void end_remote_command (Bank *bank, char *command);
int decrypt_command(Bank *bank, char *command, char *plaintext);
void issue_card(Bank *bank, char *username);

uint64_t bank_dhke_(Bank *bank);


#endif

