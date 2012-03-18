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
    char arg1[10], arg2[10];
    int s, pipes[2], i;
    struct sockaddr_in sockaddr_server;
    
    srandomdev();
    
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
        perror("failed to pipe");
        return -1;
    }
    
    /*start wait*/
    if(fork()==0)
    {
        sprintf(arg1,"%d",s);
        sprintf(arg2,"%d",pipes[0]);
        if( execlp("./wait","wait", arg1, arg2, (char *)0) < 0)
        {
            perror("(dispatch) manage_command,failed to execlp wait");
            exit(EXIT_FAILURE);
        }
    }
    close(pipes[0]);
    
    /*send request*/
    printf("send request\n");
    for(i =  0;i< 50000;i++)
    {
        /*printf("write\n");*/
        if(sendRequest(pipes[1]) < 0)
        {
            fprintf(stderr,"send request error\n");
            return -1;
        }
        usleep(2000);
    }
    close(pipes[0]);
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