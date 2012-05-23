#ifdef __gnu_linux__

#define _BSD_SOURCE
#define _POSIX_SOURCE
#include <sys/time.h>
#include <sys/types.h>

#endif

#include <stdio.h> /*printf, perror, sprintf*/
#include <unistd.h> /*fork, execvp*/
#include <signal.h>
#include <stdlib.h> /*exit*/
#include <fcntl.h>
#include <sys/socket.h> 
#include <netinet/ip.h> /*struct ip*/
#include <strings.h> /*bzero*/
#include <string.h>
#include <netinet/in.h> /*struct sockaddr*/
#include <errno.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <inttypes.h>
#include "core_type.h"
#include "./delayedlib/delayedlib.h"
#include "./wait_communication.h"

#define BUFFER_SIZE 1024
#define TIMER_DEFAULT_TIME 500000

/*void set_non_blocking(int sock);*/
void handler(int sig);

int client_connected;

int main(int argc, char *argv[])
{
    int p, p2;
    int s_sock, c_sock, needToDelay;
    struct sockaddr_in sockaddr_client;
    socklen_t addr_size;
    uint8 buff[BUFFER_SIZE], command_arg;
    unsigned int data_to_receive, size_to_read, recv_size;
    fd_set fifo_read, ready_read; /* File descriptor */    
    struct sigaction action;
    struct timeval ts;
    struct time_packet * tpacket;

    if(argc != 6)
    {
        fprintf(stderr,"(wait) argument count must be 5, get %d\n",argc-1);
        return EXIT_FAILURE;
    }
    
    /*init program's vars*/
    s_sock = atoi(argv[1]); /* Socket descriptor */
    p = atoi(argv[2]); /* Pipe fd */
    p2 = atoi(argv[3]); /* Pipe fd */
    client_connected = 0; /*no client connected yet*/

    delay_init();
    
    if(strcmp(argv[4], "1") != 0 && (delay_flags & DELAYED_FLAG_ENABLE))
    {
        delay_flags ^= DELAYED_FLAG_ENABLE;
    }
    
    delay_factor = strtol(argv[5], NULL,10);
    
    printf("(wait) start : server socket:(%d), packet pipe:(%d), control pipe (%d), buffer enable (%s), speed (%s)\n"
    ,s_sock,p, p2, argv[4], argv[5]);
    
    /*init signal management*/
    action.sa_flags = 0;
    action.sa_handler=handler;
    sigemptyset(&action.sa_mask);
    sigaddset(&action.sa_mask,SIGPIPE); /*on bloque le SIGPIPE pendant sa reception*/
    sigaction(SIGPIPE,&action,(struct sigaction *)0);

    /*init tcp connexion queue*/
    if(listen(s_sock,1)<0)
    {
        perror("(wait) listen error");
        exit(EXIT_FAILURE);
    }
    
    /*init select set*/
    FD_ZERO(&fifo_read);
    FD_SET(p2, &fifo_read);
    FD_SET(p, &fifo_read);
    FD_SET(s_sock, &fifo_read);
    
    while(1)
    {
        /*DEBUG INFO
        printf("filecount : (%u)/(%u), input_count : (%u)/(%u), output_count : (%u)/(%u)\n",file_count,DELAYED_MAX_FILE_COUNT,input_buffer_size,DELAYED_MAX_PACKET_IN_MEMORY,output_buffer_size,DELAYED_MAX_PACKET_IN_MEMORY);
        END*/
        
        /*wait for an event*/
        ready_read = fifo_read;
        ts.tv_sec = 0;
        ts.tv_usec = 500000;   
             
        if((recv_size = select(FD_SETSIZE, &ready_read, NULL, NULL, &ts )) < 0)
        {
            perror("(wait) failed in the select function : ");
            exit(EXIT_FAILURE);
        }
        
        /*update reference time in the delay system*/
        delay_updateTime(); 
        
        /*TIMEOUT EVENT, do nothing*/
        if(recv_size == 0)
        {
            /*packets in buffer to forward?*/
            delay_sendDelayedPacket(c_sock, &client_connected);
            continue;
        }
        
        /*FROM COMMAND PIPE*/
        if(FD_ISSET(p2,&ready_read))
        {
            if( (recv_size = read(p2, &command_arg, sizeof(command_arg))) <= 0) /* command to execute */
            {
                if(recv_size == 0)/*end of stream*/
                {
                    printf("(wait) pipe end of stream, normal exit %d : %d : %d\n",s_sock, p, p2);
                    exit(EXIT_SUCCESS); 
                }
                
                perror("(wait) read failed");
                exit(EXIT_FAILURE);
            }
            
            switch(command_arg)
            {
                case PAUSE_EVENT:
                    printf("(wait) pause\n");
                    delay_flags |= DELAYED_FLAG_PAUSE;
                    break;
                case RESUME_EVENT:
                    printf("(wait) resume\n");
                    if(delay_flags & DELAYED_FLAG_PAUSE)
                    {
                        delay_flags ^= DELAYED_FLAG_PAUSE;
                    }
                    
                    break;
                case DELAY_PARAM:
                    printf("(wait) set delay\n");
                    delay_flags |= DELAYED_FLAG_ENABLE;
                    
                    if( (recv_size = read(p2, &delay_factor, sizeof(delay_factor))) <= 0) /* speed to read */
                    {
                        if(recv_size == 0)/*end of stream*/
                        {
                            printf("(wait) pipe end of stream, normal exit %d : %d : %d\n",s_sock, p, p2);
                            exit(EXIT_SUCCESS); 
                        }

                        perror("(wait) read failed");
                        exit(EXIT_FAILURE);
                    }
                    
                    break;
                case DISABLE_BUFFER:
                    printf("(wait) disable buffer\n");
                    if(delay_flags & DELAYED_FLAG_ENABLE)
                    {
                        delay_flags ^= DELAYED_FLAG_ENABLE;
                    }
                    
                    delay_flush();
                    break;
                case FLUSH_EVENT:
                    printf("(wait) flush\n");
                    delay_flush();
                    break;
                case KILL_YOU:
                    printf("(wait) kill command\n");
                    exit(EXIT_SUCCESS);
                    break;
            }
        }
    
        /* FROM SOCKET */
        if(FD_ISSET(s_sock,&ready_read))
        {    
            printf("(wait) connection from a client\n");  
            addr_size = sizeof(struct sockaddr);
            if ((c_sock = accept(s_sock, (struct sockaddr *) &sockaddr_client , &addr_size)) < 0)
            {              
                perror("(wait) accept error");
                exit(EXIT_FAILURE);
            }
            /* Client connected */
            client_connected = 1;
            printf("(wait) Client connected \n");
        }
        
        /*dans le cas ou ce n'est ps un sigalarm event, on attend de voir si un client se connecte avant de jeter les paquets*/
        delay_sendDelayedPacket(c_sock, &client_connected);

        /* FROM PIPE */
        if(FD_ISSET(p,&ready_read))
        {
            /*read the TIMESTAMP*/
            if( (recv_size = read(p, &ts, sizeof(struct timeval))) <= 0) /* Size to read */
            {
                if(recv_size == 0)/*end of stream*/
                {
                    printf("(wait) pipe end of stream, normal exit %d : %d : %d\n",s_sock, p, p2);
                    exit(EXIT_SUCCESS); 
                }
                
                perror("(wait) read failed");
                exit(EXIT_FAILURE);
            }
            
            /*read the packet SIZE*/
            if( (recv_size = read(p, &data_to_receive, sizeof(data_to_receive))) <= 0) /* Size to read */
            {
                if(recv_size == 0)/*end of stream*/
                {
                    printf("(wait) pipe end of stream, normal exit %d : %d : %d\n",s_sock, p, p2);
                    exit(EXIT_SUCCESS);  
                }
                
                perror("(wait) read failed");
                exit(EXIT_FAILURE);
            }

            if((needToDelay = delay_needToDelay(&ts)))
            {
                tpacket = delay_allocateTemporalPaquet(data_to_receive, &ts);
            }
            /*    printf("bufferize packet\n");
            }
            else
            {
                printf("direct forward\n");
            }*/

            /*read the PACKET*/
            size_to_read = BUFFER_SIZE; /* Default buffer size */
            while(data_to_receive > 0) /* Reading data */
            {
                if(data_to_receive < BUFFER_SIZE) /* Smaller buffer size */
                    size_to_read = data_to_receive;

                if((recv_size = read(p, buff, size_to_read)) <= 0)
                {
                    if(recv_size == 0)/*end of stream*/
                    {
                        printf("(wait) pipe end of stream, normal exit %d : %d : %d\n",s_sock, p, p2);
                        exit(EXIT_SUCCESS); 
                    }
                    
                    perror("(wait) read failed");
                    exit(EXIT_FAILURE);
                }

                if(needToDelay)
                {
                    if(tpacket != NULL)
                    {
                        memcpy(&tpacket->datas[tpacket->size - data_to_receive],buff,recv_size);
                    }
                    data_to_receive -= recv_size;
                }
                else if(client_connected)
                {
                    data_to_receive -= recv_size;
                    if(send(c_sock, buff, recv_size,0) < recv_size)
                    {
                        perror("(wait) send ");
                        continue;
                    }
                }
                else
                {
                    data_to_receive -= recv_size;
                }
            }    
        }
    }

    return EXIT_SUCCESS;    
}

void handler(int sig)
{
    if(sig == SIGPIPE)
    {
        printf("(wait) Client disconnected, received SIGPIPE\n");
        client_connected = 0;
    }
}