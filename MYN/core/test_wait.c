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

#define _BSD_SOURCE
#define _POSIX_SOURCE
#define _ISOC99_SOURCE
#include <sys/time.h>
#include <sys/types.h>

#endif

#include <stdio.h> /*printf, perror, sprintf*/
#include <stdlib.h> /*exit*/
#include <unistd.h> /*fork*/
#include <strings.h> /*bzero,*/
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>

int sendRequest(int pipe);

int main(int argc, char *argv[])
{
    char arg1[10], arg2[10], arg3[10], arg4[10];
    int s, pipes[2], pipes2[2], i;
    struct sockaddr_in sockaddr_server;
            
    /*init socket*/
    if((s = socket(PF_INET,SOCK_STREAM,0)) < 0 )
    {
        perror("(dispatch) manage_command, failed to create socket");
        return -1;
    }
    
    bzero((char *) &sockaddr_server , sizeof(sockaddr_server)); 
    sockaddr_server.sin_addr.s_addr = htonl(INADDR_ANY);
    sockaddr_server.sin_family = AF_INET;
    sockaddr_server.sin_port = htons(44447);

    if(bind(s, (struct sockaddr *) &sockaddr_server, sizeof(sockaddr_server)) < 0)
    {
        perror("manage_command, bind error");
        close(s);
        return -1;
    }
    
    if(pipe(pipes)<0)
    {
        perror("failed to pipe (1)");
        return -1;
    }
    
    if(pipe(pipes2)<0)
    {
        perror("failed to pipe (2)");
        return -1;
    }
    
    /*start wait*/
    if(fork()==0)
    {
        close(pipes[1]);
        sprintf(arg1,"%d",s);
        sprintf(arg2,"%d",pipes[0]);
        sprintf(arg3,"%d",pipes2[0]);
        sprintf(arg4,"%u",173);
        
        if( execlp("./wait","wait", arg1, arg2,"1",arg3,arg4, (char *)0) < 0)
        {
            perror("(dispatch) manage_command,failed to execlp wait");
            exit(EXIT_FAILURE);
        }
    }
    close(pipes[0]);
    
    /*send request*/
    printf("send request\n");
    for(i =  0;i< 1000;i++)
    {
        /*printf("write\n");*/
        if(sendRequest(pipes[1]) < 0)
        {
            fprintf(stderr,"send request error\n");
            return -1;
        }
        usleep(100000);
    }
    close(pipes[1]);
    close(s);
    return 0;
}

int sendRequest(int pipe)
{
    struct timeval ts;
    uint8_t tab[1500];
    unsigned int size,i;
    
    if(gettimeofday(&ts,NULL) != 0)
    {
        perror("(segmentlib) createEntry, failed to init mod_time : ");
        return -1;
    }
    
    /*timestamp*/
    write(pipe,&ts,sizeof(struct timeval));
    
    while(  (size = random()%1500) <= 0);
    
    /*size
    printf("send %u\n",size);*/
    write(pipe,&size,sizeof(size));
    
    for(i=0;i<size;i++)
    {
        tab[i] = (uint8_t)random()%256;
    }
    
    /*data*/
    write(pipe,tab,size);
    
    return 0;
}