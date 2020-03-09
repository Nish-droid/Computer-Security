/* 
 * The main program for the ATM.
 *
 * You are free to change this as necessary.
 */

#include "atm.h"
#include "atm-bank/atm-bank.h"
#include <stdio.h>
#include <stdlib.h>

static const char prompt[] = "ATM: ";

int main(int argc, char **argv)
{
    if (access(argv[1], F_OK) == -1)
    {
        fprintf(stdout, "Error opening ATM initialization file\n\n");
        return 64;
    }

    char user_input[MAX_PACKET_SIZE + 1];

    ATM *atm = atm_create();

    printf("%s", prompt);
    fflush(stdout);

    while (1)
    {
        memset(user_input, '\0', MAX_PACKET_SIZE + 1);
        fflush(stdin);
        fgets(user_input, MAX_PACKET_SIZE + 1, stdin);
        user_input[MAX_PACKET_SIZE] = '\0';
        atm_process_command(atm, user_input);
        
        if (atm->in_session)
        {
            fprintf(stdout, "ATM (%s): ", atm->active_user);
        }
        else
        {
            printf("%s", prompt);
        }
        
        fflush(stdout);
    }
    return EXIT_SUCCESS;
}
