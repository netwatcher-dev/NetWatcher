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
#include <netinet/in.h> /*struct sockaddr*/
#include <errno.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include "core_type.h"

#define BUFFER_SIZE 1024

void set_non_blocking(int sock);
void handler(int sig);

int client_connected, normal_signal;

int main(int argc, char *argv[])
{
    int p;
    int s_sock, c_sock, i;
    struct sockaddr_in sockaddr_client;
    socklen_t addr_size;
    uint8 buff[BUFFER_SIZE];
    unsigned int data_to_receive, size_to_read, recv_size;
    fd_set fifo_read, ready_read; /* File descriptor */    
    struct sigaction action;
    struct itimerval timer;
    struct timeval ts;

    printf("(wait) start\n");

    if(argc != 3)
    {
        fprintf(stderr,"(wait) argument count must be 2, get %d\n",argc-1);
        return EXIT_FAILURE;
    }
    
    for(i = 0; i < argc;i++)
    {
        printf("(wait) arg %d : %s\n",i,argv[i]);
    }
    
    s_sock = atoi(argv[1]); /* Socket descriptor */
    p = atoi(argv[2]); /* Pipe fd */
    client_connected = 0;
    normal_signal = 0;
    
    action.sa_flags = 0;
    action.sa_handler=handler;
    sigemptyset(&action.sa_mask);
    sigaddset(&action.sa_mask,SIGPIPE); /*on bloque le SIGPIPE pendant sa reception*/
    sigaddset(&action.sa_mask,SIGALRM); /*on bloque le SIGPIPE pendant sa reception*/
    sigaction(SIGPIPE,&action,(struct sigaction *)0);
    action.sa_flags = SA_RESTART;
    sigaction(SIGALRM,&action,(struct sigaction *)0);
    
    /*le timer explose apres 500 millisecondes*/
    timer.it_value.tv_sec = 0; 
    timer.it_value.tv_usec = 500000;
    
    /*pas de repetition*/
    timer.it_interval.tv_sec = 0; 
    timer.it_interval.tv_usec = 0;

    if(listen(s_sock,1)<0)
    {
        perror("(wait) listen error");
        exit(EXIT_FAILURE);
    }

    setitimer (ITIMER_REAL, &timer, NULL); 
    /*set_non_blocking(s_sock);  Non Blocking mode */

    FD_ZERO(&fifo_read);
    FD_SET(p, &fifo_read);
    FD_SET(s_sock, &fifo_read);

    while(1)
    {
        ready_read = fifo_read;

        normal_signal = 1;
        if(select(FD_SETSIZE, &ready_read, NULL, NULL, NULL ) < 0)
        {
            if(normal_signal)
            {
                perror("(wait) failed in the select function : ");
                exit(EXIT_FAILURE);
            }
        }
        
        if(normal_signal == 0)
        {
            normal_signal = 1;
            continue;
            /*vider le buffer*/
        }
    
        /* FROM SOCKET */
        if(FD_ISSET(s_sock,&ready_read))
        {    
            printf("(wait) connection from a client\n");  
            addr_size = sizeof(struct sockaddr);
            normal_signal = 1;
            if ((c_sock = accept(s_sock, (struct sockaddr *) &sockaddr_client , &addr_size)) < 0)
            {    
                if(normal_signal)
                {                
                    perror("(wait) accept error");
                    exit(EXIT_FAILURE);
                }
            }
            /* Client connected */
            client_connected = 1;
            printf("(wait) Client connected \n");
        }

        /* FROM PIPE */
        if(FD_ISSET(p,&ready_read))
        {
            /*printf("read\n");*/
            /*read the TIMESTAMP*/
            if( (recv_size = read(p, &ts, sizeof(struct timeval))) < 0) /* Size to read */
            {
                perror("(wait) read failed");
                return EXIT_FAILURE;
            }
            
            /*printf("%u, %u\n",ts.tv_sec,ts.tv_usec);*/
            
            if(recv_size == 0)
            {
                /*end of stream*/
                printf("(wait) pipe end of stream, normal exit\n");
                close(p);
                close(c_sock);
                close(s_sock);
                return EXIT_SUCCESS;
            }
            
            /*read the packet SIZE*/
            if( (recv_size = read(p, &data_to_receive, sizeof(data_to_receive))) < 0) /* Size to read */
            {
                perror("(wait) read failed");
                return EXIT_FAILURE;
            }
            
            if(recv_size == 0)
            {
                /*end of stream*/
                printf("(wait) pipe end of stream, normal exit\n");
                close(p);
                close(c_sock);
                close(s_sock);
                return EXIT_SUCCESS;
            }
            
            /*RECEPTION D'UNE COMMANDE*/
            
            /*DECISION DE MISE EN CACHE*/
            
                /*EMISSION IMMEDIATE*/
                
                /*MISE EN CACHE*/

            size_to_read = BUFFER_SIZE; /* Default buffer size */
            while(data_to_receive > 0) /* Reading data */
            {
                if(data_to_receive < BUFFER_SIZE) /* Smaller buffer size */
                    size_to_read = data_to_receive;

                if((recv_size = read(p, buff, size_to_read)) < 0)
                {
                    perror("(wait) read failed");
                    return EXIT_FAILURE;
                }

                if(recv_size == 0)
                {
                    /*end of stream*/
                    printf("(wait) pipe end of stream, normal exit\n");
                    close(p);
                    close(c_sock);
                    close(s_sock);
                    return EXIT_SUCCESS;  
                }
                
                data_to_receive -= recv_size;
                
                if(client_connected)
                {
                    if(send(c_sock, buff, recv_size,0) < recv_size)
                    {
                        perror("(wait) send ");
                        continue;
                    }
                }
            }         
        }
    }

    return EXIT_SUCCESS;    
}

void set_non_blocking(int sock)
{
    int opts;

    opts = fcntl(sock,F_GETFL);
    if (opts < 0) {
        perror("fcntl(F_GETFL)");
        exit(EXIT_FAILURE);
    }
    opts = (opts | O_NONBLOCK);
    if (fcntl(sock,F_SETFL,opts) < 0) {
        perror("fcntl(F_SETFL)");
        exit(EXIT_FAILURE);
    }
    return;
}


void handler(int sig)
{
    if(sig == SIGPIPE)
    {
        printf("(wait) Client disconnected, received SIGPIPE\n");
        client_connected = 0;
    }
    else if(sig == SIGALRM)
    {
        printf("SIGALRM\n");
        normal_signal = 0;
    }
}