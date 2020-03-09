/* 
 * The main program for the Bank.
 *
 * You are free to change this as necessary.
 */

#include <string.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include "bank.h"
#include "atm-bank/atm-bank.h"
#include "ports.h"

static const char prompt[] = "BANK: ";

int main(int argc, char**argv)
{
   int n;
   char sendline[MAX_PACKET_SIZE];
   char recvline[MAX_PACKET_SIZE];

  if (access(argv[1], F_OK) == -1)
  {
    fprintf(stdout, "Error opening bank initialization file\n\n");
    return 64;
  }

   Bank *bank = bank_create();
   printf("%s", prompt);

   while(1)
   {
       fflush(stdout);
       fd_set fds;
       FD_ZERO(&fds);
       FD_SET(0, &fds);
       FD_SET(bank->sockfd, &fds);
       select(bank->sockfd+1, &fds, NULL, NULL, NULL);

       if(FD_ISSET(0, &fds))
       {
           fgets(sendline, MAX_PACKET_SIZE, stdin);
           bank_process_local_command(bank, sendline, strlen(sendline));
           fflush(stdout);
           printf("%s", prompt);
       }
       else if(FD_ISSET(bank->sockfd, &fds))
       {
           if (bank->active_user == NULL)
           {
                n = bank_recv(bank, recvline, MAX_PACKET_SIZE);
                bank_process_remote_command(bank, recvline, n);
           }
           else
           {
               char plaintext[MAX_PACKET_SIZE + 1];
               int plaintext_len = bank_recv_encrypted(bank, (uint8_t *) plaintext, MAX_PACKET_SIZE);
               plaintext[plaintext_len] = '\0';
               bank_process_remote_command(bank, plaintext, plaintext_len);
           }
           
       }
   }

   return EXIT_SUCCESS;
}
