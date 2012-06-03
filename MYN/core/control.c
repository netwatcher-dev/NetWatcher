/*
                    GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

                            Preamble

  The GNU General Public License is a free, copyleft license for
software and other kinds of works.

  The licenses for most software and other practical works are designed
to take away your freedom to share and change the works.  By contrast,
the GNU General Public License is intended to guarantee your freedom to
share and change all versions of a program--to make sure it remains free
software for all its users.  We, the Free Software Foundation, use the
GNU General Public License for most of our software; it applies also to
any other work released this way by its authors.  You can apply it to
your programs, too.

  When we speak of free software, we are referring to freedom, not
price.  Our General Public Licenses are designed to make sure that you
have the freedom to distribute copies of free software (and charge for
them if you wish), that you receive source code or can get it if you
want it, that you can change the software or use pieces of it in new
free programs, and that you know you can do these things.

  To protect your rights, we need to prevent others from denying you
these rights or asking you to surrender the rights.  Therefore, you have
certain responsibilities if you distribute copies of the software, or if
you modify it: responsibilities to respect the freedom of others.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef __gnu_linux__

#define _SVID_SOURCE
#define _BSD_SOURCE
#define _POSIX_SOURCE
#include <sys/types.h>

#endif

#include <stdio.h> /*printf, fprintf*/
#include <stdlib.h> /*exit*/
#include <sys/socket.h> /*socket, bind, listen*/
#include <strings.h> /*bzero*/
#include <netinet/in.h> /*struct sockaddr*/
#include <signal.h> /*sigset*/
#include <unistd.h> /*fork, close, getenv*/
#include <netinet/ip.h> /*struct ip*/
#include <sys/shm.h>
#include <errno.h>

#include "./controllib/controllib.h"
#include "./sharedmemorylib/sharedmemorylib.h"

int manageClient(int descriptor);

int from_collector, to_collector, dispatch_id;
mymemory * mem;

int capture_mode; /* Don't care */

#define SERVEUR_PORT 22222
#define QUEUE_LENGTH 1

char * home_directory;

int main(int argc, char *argv[])
{
    int serveur_socket, client_socket, shmDesc, semDesc;
    struct sockaddr_in adresse_ecoute, adresse_client;
    socklen_t adresse_size;
    
    #ifdef DEV
    home_directory = ".";
    #else
    home_directory = getenv("HOME");
    #endif
    
    /*###########################################################*/
    /*##################### ARGUMENTS CHECKS ####################*/
    /*###########################################################*/
        
    if(argc != 6)
    {
        fprintf(stderr,"(control) argument count must be 4, get %d\n",argc);
        kill(0, SIGINT);
        return EXIT_FAILURE;
    }
    
    shmDesc = strtol(argv[1],NULL,10);
    if(errno == ERANGE || errno == EINVAL)
    {
        perror("(control) failed to convert shared memory descriptor : ");
        kill(0, SIGINT);
        return EXIT_FAILURE;
    }
    
    semDesc = strtol(argv[2],NULL,10);
    if(errno == ERANGE || errno == EINVAL)
    {
        perror("(control) failed to convert semaphore descriptor : ");
        kill(0, SIGINT);
        return EXIT_FAILURE;
    }
    
    to_collector = strtol(argv[3],NULL,10);
    if(errno == ERANGE || errno == EINVAL)
    {
        perror("(control) failed to convert pipe id to_collector : ");
        kill(0, SIGINT);
        return EXIT_FAILURE;
    }
    
    from_collector = strtol(argv[4],NULL,10);
    if(errno == ERANGE || errno == EINVAL)
    {
        perror("(control) failed to convert pipe id from_collector : ");
        kill(0, SIGINT);
        return EXIT_FAILURE;
    }
    
    dispatch_id = strtol(argv[5],NULL,10);
    if(errno == ERANGE || errno == EINVAL)
    {
        perror("(control) failed to convert dispatch_id : ");
        kill(0, SIGINT);
        return EXIT_FAILURE;
    }
    
    printf("(control) start : shmDesc:(%d), semDesc:(%d), to_collector:(%d), from_collector:(%d), dispatch_id:(%d)\n",shmDesc,semDesc,to_collector,from_collector,dispatch_id);
    
    /*###########################################################*/
    /*##################### SYSTEM INIT #########################*/
    /*###########################################################*/
    
    /*preparation de la memoire partagee*/
    if( (mem = createMemory(shmDesc,3,semDesc,0)) == NULL)
    {
        fprintf(stderr,"(control) failed to create shared memory\n");
        kill(0, SIGINT);
        return EXIT_FAILURE;
    }
    
    /*preparation d'une socket tcp*/
    if(  (serveur_socket = socket(PF_INET,SOCK_STREAM,0)) < 0  )
    {
        perror("(control) socket error in core");
        kill(0, SIGINT);
        exit(EXIT_FAILURE);
    }

    /*preparation de l'adresse de la socket*/
    bzero((char *) &adresse_ecoute , sizeof( adresse_ecoute )); /*on met la structure a zero*/
    adresse_ecoute.sin_family      = AF_INET; /* address family : Internet */
    adresse_ecoute.sin_addr.s_addr = htonl(INADDR_ANY); 
    adresse_ecoute.sin_port        = htons(SERVEUR_PORT);

    /*on associe l'adresse a la socket*/
    if (bind(serveur_socket, (struct sockaddr *) &adresse_ecoute , sizeof( adresse_ecoute )) < 0 )
    {
        perror("(control) bind error in core");
        kill(0, SIGINT);
        exit(EXIT_FAILURE);
    }

    /* on prepare la queue de connexion */
    if(listen(serveur_socket,QUEUE_LENGTH)<0)
    {
        perror("(control) listen error in core");
        kill(0, SIGINT);
        exit(-1);
    }
     
    /*###########################################################*/
    /*##################### SYSTEM START ########################*/
    /*###########################################################*/
       
    while(1)
    {
        printf("(control) Wait for a client\n");
        /*on attend un client*/
        if ((client_socket = accept(serveur_socket, (struct sockaddr *) &adresse_client , &adresse_size)) < 0)
        {      
            perror("(control) accept error in core");
            kill(0, SIGINT);
            exit(EXIT_FAILURE);
        }
        
        /*on lance le processus de traitement*/
        if( manageClient(client_socket) == EXIT_SUCCESS)
        {
            printf("(control) successfull client exit\n");
            close(client_socket);
        }
        else
        {
            printf("(control) client exitted with error\n");
            close(client_socket);
        }
    }
    
    return EXIT_SUCCESS;
}


/*
 * manageClient, this function manage a client connection and execute all the command
 *
 * @param descriptor, the socket descriptor of the client link
 * @return, 0 if success, -1 if an error has occured
 */
int manageClient(int descriptor)
{
    sint8 command;
    int size;
    
    while(1)
    {
        if(  (size = recv(descriptor, &command, sizeof(sint8),MSG_WAITALL)) != sizeof(sint8))
        {
            if(size == 0)
                return EXIT_SUCCESS;
            
            perror("(control) manageClient, failed to received command");
            return EXIT_FAILURE;
        }
        
        switch(command)
        {
            case COMMAND_DEVICE_LIST:
                printf("(control) list device\n");
                if(sendEntries(descriptor) != 0)
                    return EXIT_FAILURE;
                break;
                
            case COMMAND_GET_PROTOCOL_LIST:
                printf("(control) get protocol listing\n");
                if(getProtocolList(descriptor) != 0)
                    return EXIT_FAILURE;
                break;
            
            case COMMAND_CLEAR_PROTO_LIST:
                printf("(control) clear protocol listing\n");
                if(clearProtocolList(descriptor) != 0)
                    return EXIT_FAILURE;
                break;

            case COMMAND_SET_BUFFER_LENGTH_PROTO_LIST:
                printf("(control) set length protocol listing\n");
                if(setLengthProtocolList(descriptor) != 0)
                    return EXIT_FAILURE;    
                break;

            case COMMAND_SELECT_CAPTURE_DEVICE_WITH_MONITORING:
            case COMMAND_SELECT_CAPTURE_DEVICE:
                printf("(control) select capture device\n");

                if(setCaptureMode(LIVE_MODE) != 0) /* Set capture mode in collector */
                    return EXIT_FAILURE;
                    
                if(selectCaptureDevice(descriptor,command) != 0)
                    return EXIT_FAILURE;
                break;
                
            case COMMAND_DISABLE_CAPTURE_DEVICE:
                printf("(control) disable capture device\n");
                if(disable_device(descriptor) != 0)
                    return EXIT_FAILURE;
                break;
                
            case COMMAND_SELECT_CAPTURE_FILE:
                printf("(control) select capture file\n");
                
                if(setCaptureMode(FILE_MODE) != 0) /* Set capture mode in collector */
                    return EXIT_FAILURE;
                    
                if(selectCaptureFile(descriptor) != 0)
                    return EXIT_FAILURE;
                break;
                
            case COMMAND_SET_SPEED:
                printf("(control) set speed\n");
                if(setSpeed(descriptor) != 0)
                    return EXIT_FAILURE;
                break;
                
            case COMMAND_FLUSH_SEGMENT:
                printf("(control) flush segment list\n");
                if(directTransmit(descriptor,COMMAND_FLUSH_SEGMENT) != 0)
                    return EXIT_FAILURE;
                break;
                
            case COMMAND_PARSE_FILE:
                printf("(control) parse file\n");
                if(directTransmit(descriptor,COMMAND_PARSE_FILE) != 0)
                    return EXIT_FAILURE;
                break;
                
            case COMMAND_START_CAPTURE:
                printf("(control) start capture\n");
                if(setFilter(descriptor, command) != 0)
                    return EXIT_FAILURE;
                break;
                
            case COMMAND_SET_MASTER_FILTER:
                printf("(control) set master filter\n");
                if(setFilter(descriptor, command) != 0)
                    return EXIT_FAILURE;
                break;
                
            case COMMAND_TEST_MASTER_FILTER:
                printf("(control) test master filter\n");
                if(setFilter(descriptor, command) != 0)
                    return EXIT_FAILURE;
                break;
                
            case COMMAND_STOP_CAPTURE:
                printf("(control) stop capture\n");
                if(stopCapture(descriptor) != 0)
                    return EXIT_FAILURE;
                break;
                
            case COMMAND_STOP_ALL_CAPTURE:
                printf("(control) stop all capture\n");
                if(directTransmit(descriptor,COMMAND_STOP_ALL_CAPTURE) != 0)
                    return EXIT_FAILURE;
                break;
                
            case COMMAND_LIST_FILE:
                printf("(control) list files\n");
                if(listFiles(descriptor) != 0)
                    return EXIT_FAILURE;
                break;
                
            case COMMAND_START_RECORD:
                printf("(control) start record\n");
                if(startRecord(descriptor) != 0)
                    return EXIT_FAILURE;
                break;
                
            case COMMAND_STOP_RECORD:
                printf("(control) stop record\n");
                if(directTransmit(descriptor,COMMAND_STOP_RECORD) != 0)
                    return EXIT_FAILURE;
                break;
                
            case COMMAND_STREAM_PAUSE:
                printf("(control) pause the stream\n");
                if(directTransmit(descriptor,COMMAND_STREAM_PAUSE) != 0)
                    return EXIT_FAILURE;
                break;
                    
            case COMMAND_STREAM_RESUME:
                printf("(control) resume the stream\n");
                if(directTransmit(descriptor,COMMAND_STREAM_RESUME) != 0)
                    return EXIT_FAILURE;
                break;
                
            case COMMAND_FILE_READ:
                printf("(control) read file\n");
                if(directTransmit(descriptor,COMMAND_FILE_READ) != 0)
                    return EXIT_FAILURE;
                break;
            case COMMAND_FILE_STOP:
                printf("(control) stop file\n");
                if(directTransmit(descriptor,COMMAND_FILE_STOP) != 0)
                    return EXIT_FAILURE;
                break;
            case COMMAND_FILE_GOTO:
                printf("(control) go to\n");
                if(file_goto(descriptor,COMMAND_FILE_GOTO) != 0)
                    return EXIT_FAILURE;
                break;
            case COMMAND_FILE_GOTO_AND_READ:
                    printf("(control) go to and read\n");
                    if(file_goto(descriptor,COMMAND_FILE_GOTO_AND_READ) != 0)
                        return EXIT_FAILURE;
                    break;
            case COMMAND_GET_STATE:
                printf("(control) get state\n");
                if(get_state(descriptor) != 0)
                    return EXIT_FAILURE;
                break;
                
            default:
                fprintf(stderr,"(control) unknown command : %d\n",command);
        }
    }
    
    return 0;
}

