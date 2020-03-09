#include "atm.h"
#include "atm-bank/atm-bank.h"
#include "ports.h"

ATM* atm_create()
{
    ATM *atm = (ATM*) malloc(sizeof(ATM));
    if(atm == NULL)
    {
        perror("Could not allocate ATM");
        exit(1);
    }

    // Set up the network state
    atm->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&atm->rtr_addr,sizeof(atm->rtr_addr));
    atm->rtr_addr.sin_family = AF_INET;
    atm->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->rtr_addr.sin_port = htons(ROUTER_PORT);

    bzero(&atm->atm_addr, sizeof(atm->atm_addr));
    atm->atm_addr.sin_family = AF_INET;
    atm->atm_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->atm_addr.sin_port = htons(ATM_PORT);
    bind(atm->sockfd,(struct sockaddr *)&atm->atm_addr,sizeof(atm->atm_addr));

    atm->in_session = false;
    atm->active_user = NULL;
    // Set up the protocol state
    // TODO set up more, as needed

    return atm;
}

void atm_free(ATM *atm)
{
    if(atm != NULL)
    {
        close(atm->sockfd);
        free(atm);
    }
}

ssize_t atm_send(ATM *atm, char *data, size_t data_len)
{
    int num_bytes;
    // Returns the number of bytes sent; negative on error
    num_bytes = sendto(atm->sockfd, data, data_len, 0,
      (struct sockaddr*) &atm->rtr_addr, sizeof(atm->rtr_addr));
    if (num_bytes < 0)
    {
        perror("sendto failed");
        exit(EXIT_FAILURE);
    }
    return num_bytes;
}

ssize_t atm_send_encrypted(ATM *atm, uint8_t *data, size_t data_len)
{
    uint8_t ciphertext[MAX_PACKET_SIZE];
    int cipher_len = encrypt(data, data_len, atm->key, IV, ciphertext);
    Cipher cipher;
    cipher.len = htons(cipher_len);
    memcpy(cipher.ciphertext, ciphertext, cipher_len);
    return atm_send(atm, (char *) &cipher, cipher_len + 2);
}

ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len)
{
    int num_bytes;
    // Returns the number of bytes received; negative on error
    num_bytes = recvfrom(atm->sockfd, data, max_data_len, 0, NULL, NULL);

    if (num_bytes < 0)
    {
        perror("recvfrom failed");
        exit(EXIT_FAILURE);
    }
    return num_bytes;
}

ssize_t atm_recv_encrypted(ATM *atm, uint8_t *data, size_t max_data_len)
{
    char buffer[MAX_PACKET_SIZE];
    atm_recv(atm, buffer, MAX_PACKET_SIZE);

    //get ciphertext len and setup buffer
    uint16_t len;
    memcpy(&len, buffer, 2);
    len = ntohs(len);
    uint8_t ciphertext[len];
    memcpy(ciphertext, buffer + 2, len);

    //decrypt ciphertext
    int plaintext_len = decrypt(ciphertext, len, atm->key, IV, data);
    data[plaintext_len] = '\0';
    return plaintext_len;
}

void atm_process_command(ATM *atm, char *command)
{
    remove_newline(command);

    if (strncmp(command, "begin-session", 13) == 0)
    {
        //get username from .card
        char cmd[MAX_USERNAME_SIZE];
        char username[MAX_USERNAME_SIZE + 1];
        memset(username, '\0', MAX_USERNAME_SIZE + 1);


        if (atm->in_session)
        {
            fprintf(stderr, "A user is already logged in\n\n");
        }
        else if (sscanf(command, "%s %s", cmd, username) < 0)
        {
            fprintf(stderr, "Usage:\tbegin-session <user-name>\n\n");
        }
        else if (!validate_username(username))
        {
            fprintf(stderr, "Usage:\tbegin-session <user-name>\n\n");
        }
        else
        {
              //create packet struct for sending
            int user_len = strlen(username);

            typedef struct _Packet {
                Header header;
                uint16_t len;
                uint8_t user[user_len];
            }__attribute__((packed)) Packet;

            //construct packet and send
            Packet packet;
            packet.header.len   = htonl(2 + user_len);
            packet.header.magic = htonl(MAGIC_NUMBER);
            packet.header.cmd   = BEGIN_REQ;
            packet.len          = htons(user_len);
            strncpy((char *)packet.user, (char *)username, user_len);
            atm_send(atm, (char *)&packet, sizeof(packet));

            //connect with server and calc shared secret
            uint64_t shared = atm_dhke(atm);

            //get key using shared secret
            get_key(shared, atm->key, (uint8_t *) username, user_len);

            //receive confirmation, request for pin or error
            uint8_t plaintext[MAX_PACKET_SIZE];
            atm_recv_encrypted(atm, plaintext, MAX_PACKET_SIZE);

            //parse revc packet
            Header *header = (Header *) plaintext;

            if (header->magic == MAGIC_NUMBER && header->cmd == PIN_REQ)
            {
        //grab card hash from bank and check
                uint8_t card_hash[SHA256_DIGEST_LENGTH];
                memcpy(card_hash, plaintext + HEADER_LEN, SHA256_DIGEST_LENGTH);
                if (!validate_card(username, card_hash))
                {
                    fprintf(stdout, "Unable to access %s's card\n\n", username);
                }
                else
                {
            //prepare for and ask for pin
                    char pin[PIN_SIZE + 1];
                    memset(pin, '\0', PIN_SIZE + 1);
                    char *len = malloc(PIN_SIZE + 1);

                    fprintf(stdout, "Pin?  ");
                    fgets(len, PIN_SIZE + 1, stdin);
                    sscanf(len, "%s", pin);
                    pin[PIN_SIZE] = '\0';

            //validate pin
                    if (validate_pin(pin))
                    {
                        getchar();
                        
                    }
                    else
                    {
                        free(len);
                    } 
            //build new struct to send header and pin
                    typedef struct _PIN_SEND
                    {
                        Header header;
                        char pin[PIN_SIZE];
                    } PIN_SEND;

                    PIN_SEND pin_send;

                //build pin header **NOTE using create_header causes issues
                    pin_send.header.len   = 0x4;
                    pin_send.header.magic = MAGIC_NUMBER;
                    pin_send.header.cmd   = PIN_RESP;
                    memcpy(pin_send.pin, pin, PIN_SIZE);

                //send encrypted packet
                    atm_send_encrypted(atm, (uint8_t *) &pin_send, sizeof(PIN_SEND));

                //prepare to receive authorization, reused plaintext
                    memset(plaintext, '\0', MAX_PACKET_SIZE);
                    atm_recv_encrypted(atm, plaintext, MAX_PACKET_SIZE);
                    Header *header = (Header *) plaintext;

                    if(header->magic == MAGIC_NUMBER && header->cmd == AUTHORIZED)
                    {
                        int user_len = strlen(username);
                        atm->active_user = malloc(user_len + 1);
                        atm->in_session = true;
                        strncpy(atm->active_user, username, user_len);
                        atm->active_user[user_len] = '\0';
                        fprintf(stderr, "Authorized\n\n");
                    }
                    else
                    {
                        fprintf(stderr, "Not Authorized\n\n");
                    }
                }
            }
            else if (header->magic == MAGIC_NUMBER && 
                header->cmd == NO_USER_EXISTS)
            {
                fprintf(stderr, "No such user\n\n");
            }
            
        }
    }

    else if (strncmp(command, "withdraw", 8) == 0)
    {
        remove_newline(command);
        int amount;
        char cmd[MAX_USERNAME_SIZE];

        sscanf(command, "%s %u", cmd, &amount);

        //Checks amount inputs and see whether they are all digits and not alphabets
        //- kthant
        char amtStr[MAX_USERNAME_SIZE];
        sscanf(command, "%s %s", cmd, amtStr);
        if(!checkDigits(amtStr, strlen(amtStr))){
          fprintf(stdout, "Usage:\twithdraw <amt>\n\n");
      }

        //----------------------
      else if(!atm->in_session)
      {
        fprintf(stdout, "No user logged in\n\n");
    }
    else if (!validate_amount(amount))
    {
        fprintf(stdout, "Usage:\twithdraw <amt>\n\n");
    }
    else
    {
        typedef struct _SEND_WITHDRAW
        {
            Header header;
            int amount;
        } __attribute__((packed)) SEND_WITHDRAW;

        SEND_WITHDRAW packet;

        packet.header.len   = 0x4;
        packet.header.magic = MAGIC_NUMBER;
        packet.header.cmd   = WITHDRAW_REQ;
        packet.amount = amount;

        atm_send_encrypted(atm, (uint8_t *) &packet, sizeof(SEND_WITHDRAW));

        uint8_t buffer[MAX_PACKET_SIZE];

        atm_recv_encrypted(atm, buffer, MAX_PACKET_SIZE);

        Header *header = (Header *) buffer;

        if (header->magic == MAGIC_NUMBER && header->cmd == WITHDRAW_SUCCESS)
        {
            fprintf(stdout, "$%d dispensed\n\n", amount);
        }
        else
        {
            fprintf(stdout, "Insufficient funds\n\n");
        }
    }
}
else if (strncmp(command, "balance", 7) == 0)
{
    if(!atm->in_session)
    {
        fprintf(stdout, "No user logged in\n\n");
    }
        //to make sure the argument is only 'balance' and no extra arguments
        //-kthant
    else if(strlen(command)>8 || (strlen(command) == 8 && command[7] != ' ')){
        fprintf(stdout, "Usage:\tbalance\n\n");
    }
        //----------------------
    else
    {
        Header *header = create_header(0x0, BALANCE_REQ);
        atm_send_encrypted(atm, (uint8_t *) header, sizeof(Header));

        uint8_t buffer[MAX_PACKET_SIZE];
        atm_recv_encrypted(atm, buffer, MAX_PACKET_SIZE);
        header = (Header *) buffer;

        if (header->magic == MAGIC_NUMBER && header->cmd == BALANCE_SUCCESS)
        {
            int balance;
            memcpy(&balance, buffer + HEADER_LEN, 4);

            fprintf(stdout, "$%d\n\n", balance);
        }
        else
        {
                fprintf(stdout, "Usage:\tbalance\n\n");  //deleted <amt> -kthant
            }
        }
    }
    else if (strncmp(command, "end-session", 11) == 0)
    {

        if(!atm->in_session)
        {
            fprintf(stdout, "No user logged in\n\n");
        }
        else
        {
            Header *header = create_header(0x0, END_REQ);
            atm_send_encrypted(atm, (uint8_t *) header, sizeof(Header));

            atm->in_session = false;
            atm->active_user = NULL;
            memset(atm->key, '\0', SHA256_DIGEST_LENGTH);
            fprintf(stdout, "User logged out\n\n");
        }
    }
    else
    {
        fprintf(stderr, "Invalid command\n\n");
    }
}

uint64_t atm_dhke(ATM *atm)
{
    srand(time(0));
    uint64_t a = (rand() % 6) + 2;

    uint64_t atm_pub_key = power(G, a, P);
    uint64_t atm_pub_key_nl = htobe64(atm_pub_key);
    atm_send(atm, (char *) &atm_pub_key_nl, sizeof(uint64_t));

    uint64_t bank_pub_key;
    atm_recv(atm, (char *) &bank_pub_key, sizeof(uint64_t));
    bank_pub_key = be64toh(bank_pub_key);

    uint64_t secret_key = power(bank_pub_key, a, P);

    return secret_key;
}

bool validate_card(char *username, uint8_t *card)
{
    OpenSSL_add_all_algorithms();
    char card_name[strlen(username) + 6];
    memset(card_name, '\0', strlen(username) + 6);
    strncpy(card_name, username, strlen(username));
    strcat(card_name, ".card");

    FILE *fp = fopen(card_name, "r");
    X509 *cert;
    if (!fp) {
        return false;
    }
    else
    {
        cert = PEM_read_X509(fp, NULL, NULL, NULL);
        if (!cert)
        {
            fclose(fp);
            X509_free(cert);
            return false;
        }
        else
        {
            int verified = X509_verify(cert, X509_get_pubkey(cert));
            if (verified != 1)
            {
                fclose(fp);
                X509_free(cert);
                return false;
            }
            else
            {
                uint8_t buf[SHA256_DIGEST_LENGTH];
                const EVP_MD *digest = EVP_sha256();
                unsigned len;

                int rc = X509_digest(cert, digest, (unsigned char*) buf, &len);
                X509_free(cert);
                fclose(fp);
                if (rc == 0 || len != SHA256_DIGEST_LENGTH || memcmp(buf, card, SHA256_DIGEST_LENGTH) != 0) { return false; }
                return true;
            }
        }
    }
    return true;
}


/* -------experimental --------*/

//  uint64_t atm_dhke_(ATM *atm)
// {
//     printf("Alice's generated KeyPair:");
//     EVP_PKEY *alicePrivateKey = generateKey();

//     //printf("\n\nBob's generated KeyPair:");
//     //EVP_PKEY *bobPrivateKey = generateKey();

//     // Extract the public key from the private key of Alice and Bob,
//     // So that Alice can be given Bob's public key and Bob can be given Alice's.
//     // Using ECDH, Alice and Bob will then compute a shared secret, which will be same

//     EVP_PKEY *alicePubKey = extractPublicKey(alicePrivateKey);
//     //EVP_PKEY *bobPubKey = extractPublicKey(bobPrivateKey);


//     uint8_t buffer[MAX_PACKET_SIZE];
//     atm_recv(atm, (char *) buffer, MAX_PACKET_SIZE);

//     BIO* bio = BIO_new(BIO_s_mem());
//     PEM_write_bio_PUBKEY(bio, keypair);

//     atm_send(atm, (char *) &pubkey, sizeof(PUBKEY));



//     // Here we give to Alice, Bob's public key and Alice computes the shared secret using her private key.
//     derivedKey* secretAlice = deriveShared(bobPublicKey, alicePrivateKey);

//     // Here we give to Bob, Alice's public key and Bob computes the shared secret using his private key.
//     //derivedKey* secretBob = deriveShared(alicePubKey, bobPrivateKey);

//     //The following lines of code just print out the shared secret computed by Alice and Bob.
//     BIGNUM *secretAliceBN = BN_new();

//     //BIGNUM *secretBobBN = BN_new();

//     BN_bin2bn(secretAlice->secret, secretAlice->length, secretAliceBN);

//     //BN_bin2bn(secretBob->secret, secretBob->length, secretBobBN);

//     printf("\n\nSecret computed by Alice :\n");

//     BN_print_fp(stdout, secretAliceBN);

//     //printf("\nSecret computed by Bob : \n");

//     //BN_print_fp(stdout, secretBobBN);

//     //NOTE! It is not recommended to use the computed shared secret as is, usually it should be passed to some
//     //hash function and then used.

//     BN_free(secretAliceBN);

//     //BN_free(secretBobBN);

//     return 0;
// }
