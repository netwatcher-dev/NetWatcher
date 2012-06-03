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
#include <strings.h>

#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "./utillib/utillib.h"
#include <errno.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "command.h"

#include <inttypes.h>
#include <limits.h>
#include <sys/types.h>

int shell(int socket);
int execute(int socket, int argc,char * argv[]);
int getStringList(int socket, sint8 command);
int sendOrder(int socket, sint8 command);
int sendCommandWithString(int socket, sint8 command, const char * string);
int sendCommandWithString2(int socket, sint8 command, int argc,char * argv[]);
int sendTwoUINT32(int socket, sint8 command, uint32 int1, uint32 int2);
int getState(int socket, struct core_state * state, char ** file_path);
void usage();

int setSpeed(int socket, uint8 value);
/*int startCapture(int socket, int argc,char * argv[]);*/
int stopCapture(int socket, uint16 id);

int getProtocolList(int socket);
/*int clearProtocolList(int socket);*/
int setLengthProtocolList(int socket, sint16 value);

int checkResp(sint32 resp);

int main(int argc, char *argv[])
{
    int client_socket, port, ret;
    struct sockaddr_in server_address;
    
    if(argc < 2 || strcmp("help", argv[1]) == 0)
    {
        usage();        
        return EXIT_SUCCESS;
    }
    
    if(argc < 4)
    {
        fprintf(stderr,"need at least 3 arg : SERVER_URL SERVER_PORT COMMAND [ARGS ...]\n");
        return EXIT_FAILURE;
    }
    
    port = (int)strtol(argv[2],(char **)NULL,10);
    if(errno == ERANGE || errno == EINVAL || port == 0 || port <1 || port > 65532)
    {
        fprintf(stderr,"invalid port number : %s\n",argv[2]);
        return EXIT_FAILURE;
    }
    
    /*Initialisation of the server's address*/
    bzero((char *) &server_address, sizeof(server_address));
    server_address.sin_family      = AF_INET;
    if( (server_address.sin_addr.s_addr = inet_addr(argv[1])) == INADDR_NONE)
    {
        fprintf(stderr,"invalid ip address : %s\n",argv[1]);
        return EXIT_FAILURE;
    }
    server_address.sin_port = htons(port);

    /*Creation of a TCP socket*/
    if ( (client_socket = socket(PF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket error : ");
        exit(EXIT_FAILURE);
    }

    /*Connexion to the server*/
    if (connect(client_socket , (struct sockaddr *) &server_address , sizeof ( server_address )) < 0)
    {
        perror("connect error : ");
        exit(EXIT_FAILURE);
    }
    
/*############################################################*/

    if(strcmp("shell",argv[3]) == 0)
    {
        ret = shell(client_socket);
    }
    else
    {
        if( (argc-3) < 0 )
        {
            ret = execute(client_socket, argc-3, NULL);
        }
        else
        {
            ret = execute(client_socket, argc-3, &argv[3]);
        }
    }
    
    close(client_socket);
    
    return ret;
}

void usage()
{
    printf("usage: SERVER_URL SERVER_PORT COMMAND [ARGS ...]\nCommand : \n\texit : exit shell\n\thelp : print help list\n\tdlist : list all device\n\tflist : list available file\n\tdset : set a device \n\tfset : set a file\n\trstart : start a record\n\trstop : stop a record\n\tastop : stop all capture\n\tfparse : parse a file\n\tdstop : disable capture device\n\tsset : set speed\n\tcstart : start a capture\n\tcstop : stop a capture\n");
    printf("\tplist : list protocols\n\tplength <int>: maximum number of streams in the protocol list\n\tpclear : clean the protocol list\n");
}

int execute(int socket, int argc,char * argv[])
{
    int speed1;
    uint8 speed2;
    uint32 id;
    uint16 port;
    
    uint32 secs,micro_secs;
    
    struct core_state state;
    char * file_path;
    
    if(strcmp("help", argv[0]) == 0)
    {
        usage();        
        return EXIT_SUCCESS;
    }
    else if(strcmp("dlist", argv[0]) == 0) /*device list*/
    {  
        return getStringList(socket, COMMAND_DEVICE_LIST);
    }
    else if(strcmp("flist", argv[0]) == 0) /*files list*/
    {  
        return getStringList(socket, COMMAND_LIST_FILE);
    }
    else if(strcmp("dset", argv[0]) == 0) /*device set*/
    {  
        if(argc < 2)
        {
            fprintf(stderr,"need at least 1 more arg : DEVICE_NAME\n");
            usage();
            return EXIT_FAILURE;
        }
        
        return sendCommandWithString(socket, COMMAND_SELECT_CAPTURE_DEVICE, argv[1]);
    }
    else if(strcmp("dsetm", argv[0]) == 0) /*device set*/
    {  
        if(argc < 2)
        {
            fprintf(stderr,"need at least 1 more arg : DEVICE_NAME\n");
            usage();
            return EXIT_FAILURE;
        }
        
        return sendCommandWithString(socket, COMMAND_SELECT_CAPTURE_DEVICE_WITH_MONITORING, argv[1]);
    }
    else if(strcmp("fset", argv[0]) == 0) /*file set*/
    {  
        if(argc < 2)
        {
            fprintf(stderr,"need at least 1 more arg : FILE_NAME\n");
            usage();
            return EXIT_FAILURE;
        }
        
        return sendCommandWithString(socket, COMMAND_SELECT_CAPTURE_FILE, argv[1]);
    }
    else if(strcmp("rstart", argv[0]) == 0) /*record start*/
    {
        if(argc < 2)
        {
            fprintf(stderr,"need at least 1 more arg : FILE_NAME\n");
            usage();
            return EXIT_FAILURE;
        }
        
        return sendCommandWithString(socket,COMMAND_START_RECORD, argv[1]);
    }
    else if(strcmp("rstop", argv[0]) == 0) /*record stop*/
    {
        return sendOrder(socket,COMMAND_STOP_RECORD);
    }
    else if(strcmp("astop", argv[0]) == 0) /*stop all capture*/
    {
        return sendOrder(socket,COMMAND_STOP_ALL_CAPTURE);
    }
    else if(strcmp("fparse", argv[0]) == 0) /*parse current file*/
    {
        return sendOrder(socket,COMMAND_PARSE_FILE);
    }
    else if(strcmp("fread", argv[0]) == 0) /*stop all capture*/
    {
        return sendOrder(socket,COMMAND_FILE_READ);
    }
    else if(strcmp("fstop", argv[0]) == 0) /*stop all capture*/
    {
        return sendOrder(socket,COMMAND_FILE_STOP);
    }
    else if(strcmp("info", argv[0]) == 0) /*stop all capture*/
    {
        speed1 = getState(socket, &state, &file_path);
        if(speed1 >= 0)
        {
            printf("Running : %d, Recording : %d, File : %d, Stream : %d, Parsing : %d, Reading : %d, Pause : %d, Goto : %d, Parsed : %d, Finished : %d\n",
                (IS_RUNNING((&state))?1:0), (IS_RECORDING((&state))?1:0),(IS_FILE((&state))?1:0),(IS_STREAM((&state))?1:0),(IS_PARSING((&state))?1:0),
                (IS_READING((&state))?1:0), (IS_PAUSE((&state))?1:0),(IS_GOTO((&state))?1:0),(IS_PARSED((&state))?1:0),(IS_FINISHED((&state))?1:0));


            printf("%llu,%.6llu of %llu,%.6llu\n",state.file_current_tv_sec,state.file_current_tv_usec,state.file_duration_tv_sec,state.file_duration_tv_usec);
            printf("%d packet(s) on %d\n",state.packet_readed, state.packet_in_file);
            printf("file/interface : %s\n",(file_path == NULL)?"none":file_path);
            
            if(file_path != NULL)
            {
                free(file_path);
            }
        }
        return speed1;
    }
    else if(strcmp("fgoto", argv[0]) == 0 || strcmp("fgotor", argv[0]) == 0) /*goto timestamp in file*/
    {
        /*COMMAND_FILE_GOTO*/
        if(argc < 3)
        {
            fprintf(stderr,"need 2 more arg : SECONDS MICROSECONDS\n");
            usage();
            return EXIT_FAILURE;
        }
        
        if(strlen(argv[1]) > 10 || strlen(argv[1]) <1)
        {
            fprintf(stderr,"SECONDS must be between 0 and 4 294 967 295\n");
            usage();
            return EXIT_FAILURE;
        }
        
        secs = strtol(argv[1],NULL,10);
        
        if(errno == ERANGE || errno == EINVAL)
        {
            fprintf(stderr,"failed to convert seconds, SECONDS must be between 0 and 4 294 967 295\n");
            usage();
            return EXIT_FAILURE;
        }
        printf("secs : %u\n",secs);
        
        if(strlen(argv[2]) > 6 || strlen(argv[2]) <1)
        {
            fprintf(stderr,"MICROSECONDS must be between 0 and 999 999\n");
            usage();
            return EXIT_FAILURE;
        }
        
        micro_secs = strtol(argv[2],NULL,10);
        
        if(errno == ERANGE || errno == EINVAL)
        {
            fprintf(stderr,"failed to convert microseconds, MICROSECONDS must be between 0 and 999 999\n");
            usage();
            return EXIT_FAILURE;
        }
        printf("micro_secs : %u\n",micro_secs);
        
        if( ! (micro_secs >= 0 && micro_secs <= 999999) )
        {
            fprintf(stderr,"MICROSECONDS must be between 0 and 999 999\n");
            usage();
            return EXIT_FAILURE;
        }
                
        if(strcmp("fgoto", argv[0]) == 0)
        {
            return sendTwoUINT32(socket, COMMAND_FILE_GOTO, htonl(secs), htonl(micro_secs));
        }
        else
        {
            return sendTwoUINT32(socket, COMMAND_FILE_GOTO_AND_READ, htonl(secs), htonl(micro_secs));
        }
        
    }
    else if(strcmp("pause", argv[0]) == 0) /*stop all capture*/
    {
        return sendOrder(socket,COMMAND_STREAM_PAUSE);
    }
    else if(strcmp("resume", argv[0]) == 0) /*stop all capture*/
    {
        return sendOrder(socket,COMMAND_STREAM_RESUME);
    }
    else if(strcmp("dstop", argv[0]) == 0) /*disable capture device*/
    {
        return sendOrder(socket,COMMAND_DISABLE_CAPTURE_DEVICE);
    }
    else if(strcmp("sset", argv[0]) == 0) /*set speed*/
    {
        if(argc < 2)
        {
            fprintf(stderr,"need at least 1 more arg : SPEED\n");
            usage();
            return EXIT_FAILURE;
        }
        
        if(strlen(argv[1]) > 4 || strlen(argv[1]) <1)
        {
            fprintf(stderr,"SPEED must be between -127 and 127\n");
            usage();
            return EXIT_FAILURE;
        }
        
        speed1 = strtol(argv[1],NULL,10);
        
        if(errno == ERANGE || errno == EINVAL)
        {
            fprintf(stderr,"failed to convert port id, ID must be between 1 and 65532\n");
            usage();
            return EXIT_FAILURE;
        }
        
        if(speed1 < -127 || speed1 > 127)
        {
            fprintf(stderr,"SPEED must be between -127 and 127\n");
            usage();
            return EXIT_FAILURE;
        }
        
        speed2 = 0;
        if (speed1 < 0)
        {
            speed2 |= 0x80;
            speed1 *= -1;
        }
        
        speed2 |= (speed1 & 0x7F); 
        
        return setSpeed(socket,speed2);
    }
    else if(strcmp("mset", argv[0]) == 0) /*master filter set*/
    {  
        if(argc == 1)
        {
            return sendCommandWithString(socket, COMMAND_SET_MASTER_FILTER," ");
        }
        
        return sendCommandWithString2(socket, COMMAND_SET_MASTER_FILTER,argc-1,&argv[1]);
    }
    else if(strcmp("cstart", argv[0]) == 0) /*capture start*/
    {   
        if(argc == 1)
        {
            speed1 = sendCommandWithString(socket, COMMAND_START_CAPTURE," ");
        }
        else
        {
            speed1 = sendCommandWithString2(socket, COMMAND_START_CAPTURE,argc-1,&argv[1]);
        }

        if(speed1 == 0)
        {
            /*receive the port number*/
            if( (speed1=recv(socket, &port, sizeof(uint16),MSG_WAITALL)) != sizeof(uint16))
            {
                if(speed1 == 0)
                {
                    printf("connection reset by peer\n");
                }
                else
                {
                    perror("failed to receive port");
                }
                return EXIT_FAILURE;
            }
            printf("port : %u\n",ntohs(port));
            return EXIT_SUCCESS;
        }
        return EXIT_FAILURE;
    }
    else if(strcmp("mtest", argv[0]) == 0) /*capture start*/
    {
        if(argc == 1)
        {
            return sendCommandWithString(socket, COMMAND_TEST_MASTER_FILTER," ");
        }
        
        return sendCommandWithString2(socket, COMMAND_TEST_MASTER_FILTER,argc-1,&argv[1]);
    }
    else if(strcmp("cstop", argv[0]) == 0) /*capture stop*/
    {   
        if(argc < 2)
        {
            fprintf(stderr,"need at least 1 more arg : ID\n");
            usage();
            return EXIT_FAILURE;
        }
        
        if(strlen(argv[1]) > 5 || strlen(argv[1]) <1)
        {
            fprintf(stderr,"ID must be between 1 and 65532\n");
            usage();
            return EXIT_FAILURE;
        }
        id = strtol(argv[1],NULL,10);
        
        if(errno == ERANGE || errno == EINVAL)
        {
            fprintf(stderr,"failed to convert port id, ID must be between 1 and 65532\n");
            usage();
            return EXIT_FAILURE;
        }
        return stopCapture(socket,htons(id));
    }
    else if(strcmp("plist", argv[0]) == 0) /*get protocol list*/
    {
        return getProtocolList(socket);
    }
    else if(strcmp("pclear", argv[0]) == 0) /*clear protocol list*/
    {
        return sendOrder(socket,COMMAND_CLEAR_PROTO_LIST);
    }
    else if(strcmp("flush", argv[0]) == 0) /*clear protocol list*/
    {
        return sendOrder(socket,COMMAND_FLUSH_SEGMENT);
    }
    else if(strcmp("plength", argv[0]) == 0) /*maximum timeout for protocol list*/
    {
        if(argc < 2)
        {
            fprintf(stderr,"need at least 1 more arg : SECONDS\n");
            usage();
            return EXIT_FAILURE;
        }
        
        return setLengthProtocolList(socket, (sint16)atoi(argv[1]));
    }
    else
    {
        /*unknown*/
        printf("unknown command <%s>\n",argv[0]);
        return EXIT_SUCCESS;
    }
}

int shell(int socket)
{
    char cmd[1024], *cmd2, *cmd_tmp = NULL;
    char **ap, *argv[100];
    int ret, count = 0;
    
    while(1)
    {
        /*printf("cmd:>");
        if(fgets(cmd,1024,stdin) == NULL)
        {
            perror("fgets error : ");
            return EXIT_FAILURE;
        }*/
        
        cmd_tmp = readline("NetWatcher:>");
        
        if(cmd_tmp == NULL)
        {
            return 0;
        }

        if(strlen(cmd_tmp) < 1)
        {
            continue;
        }
        
        /*cmd[strlen(cmd)-1]='\0';*/
        add_history(cmd_tmp);
        
        if(strcmp(cmd_tmp,"exit") == 0)
        {
            return EXIT_SUCCESS;
        }
        
        strcpy(cmd,cmd_tmp);
        
        cmd2 = cmd;
        count = 0;
        for (ap = argv; (*ap = strsep(&cmd2," ")) != NULL;)
        {
            if (**ap != '\0' && *ap != NULL)
            {
                if (++ap >= &argv[100])
                {
                    break;
                }
                count++; 
            }          
        }

        if( (ret = execute(socket,count,argv)) != EXIT_SUCCESS)
        {
            return ret;
        }
    }
    
    
    return 0;
}

int sendOrder(int socket, sint8 command)
{
    sint32 resp; 
    int size;
    
    if( send(socket,&command, sizeof(sint8), 0) < sizeof(sint8))
    {
        fprintf(stderr,"failed to send order\n");
        return EXIT_FAILURE;
    }
    
    if(  (size = recv(socket, &resp, sizeof(sint32),MSG_WAITALL)) != sizeof(sint32))
    {
        if(size == 0)
        {
            printf("connection reset by peer\n");
        }
        else
        {
            perror("read failed");
        }
        return EXIT_FAILURE;
    }
    
    checkResp(ntohl(resp));
    
    return 0;
}

int getState(int socket, struct core_state * state, char ** file_path)
{
    sint32 resp; 
    int size;
    sint8 command = COMMAND_GET_STATE;
    
    if( send(socket,&command, sizeof(sint8), 0) < sizeof(sint8))
    {
        fprintf(stderr,"failed to send order\n");
        return EXIT_FAILURE;
    }
    
    if(  (size = recv(socket, &resp, sizeof(sint32),MSG_WAITALL)) != sizeof(sint32))
    {
        if(size == 0)
        {
            printf("connection reset by peer\n");
        }
        else
        {
            perror("read failed");
        }
        return EXIT_FAILURE;
    }
    
    if(checkResp(ntohl(resp)) != 0)
    {
        return EXIT_FAILURE;
    }
    
    if((size = recv(socket,&state->state, sizeof(state->state), MSG_WAITALL)) != sizeof(state->state))
    {
        if(size == 0)
        {
            printf("connection reset by peer\n");
        }
        else
        {
            perror("failed to receive state");
        }
        return EXIT_FAILURE;
    }
    state->state = ntohl(state->state);
    
    if((size = recv(socket,&state->packet_readed, sizeof(state->packet_readed), MSG_WAITALL)) != sizeof(state->packet_readed))
    {
        if(size == 0)
        {
            printf("connection reset by peer\n");
        }
        else
        {
            perror("failed to receive packet_readed");
        }
        return EXIT_FAILURE;
    }
    state->packet_readed = ntohl(state->packet_readed);
    
    if((size = recv(socket,&state->packet_in_file, sizeof(state->packet_in_file), MSG_WAITALL)) != sizeof(state->packet_in_file))
    {
        if(size == 0)
        {
            printf("connection reset by peer\n");
        }
        else
        {
            perror("failed to receive packet_in_file");
        }
        return EXIT_FAILURE;
    }
    state->packet_in_file = ntohl(state->packet_in_file);
    
    if((size = recv(socket,&state->file_current_tv_sec, sizeof(state->file_current_tv_sec), MSG_WAITALL)) != sizeof(state->file_current_tv_sec))
    {
        if(size == 0)
        {
            printf("connection reset by peer\n");
        }
        else
        {
            perror("failed to receive file_current.tv_sec");
        }
        return EXIT_FAILURE;
    }
    state->file_current_tv_sec = ntohll(state->file_current_tv_sec);
    
    if((size = recv(socket,&state->file_current_tv_usec, sizeof(state->file_current_tv_usec), MSG_WAITALL)) != sizeof(state->file_current_tv_usec))
    {
        if(size == 0)
        {
            printf("connection reset by peer\n");
        }
        else
        {
            perror("failed to receive file_current.tv_usec");
        }
        return EXIT_FAILURE;
    }
    state->file_current_tv_usec = ntohll(state->file_current_tv_usec);
    
    if((size = recv(socket,&state->file_duration_tv_sec, sizeof(state->file_duration_tv_sec), MSG_WAITALL)) != sizeof(state->file_duration_tv_sec))
    {
        if(size == 0)
        {
            printf("connection reset by peer\n");
        }
        else
        {
            perror("failed to receive file_duration.tv_sec");
        }
        return EXIT_FAILURE;
    }
    state->file_duration_tv_sec = ntohll(state->file_duration_tv_sec);
    
    if((size = recv(socket,&state->file_duration_tv_usec, sizeof(state->file_duration_tv_usec), 0)) != sizeof(state->file_duration_tv_usec))
    {
        if(size == 0)
        {
            printf("connection reset by peer\n");
        }
        else
        {
            perror("failed to receive file_duration.tv_usec");
        }
        return EXIT_FAILURE;
    }
    state->file_duration_tv_usec = ntohll(state->file_duration_tv_usec);
    
    /*envoyer la source*/
    if( ((*file_path) = readString(socket)) == NULL)
    {
        fprintf(stderr,"failed to receive file path\n");
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

int getStringList(int socket, sint8 command)
{
    char * device;
    
    if(sendOrder(socket, command) != 0)
    {
        return EXIT_FAILURE;
    }
    
    while(1)
    {
        device = readString(socket);
        
        if(device == NULL)
        {
            break;
        }
        
        printf("%s\n",device);
        free(device);
    }
    
    return 0;
}

int sendCommandWithString2(int socket, sint8 command, int argc,char * argv[])
{
    char * tmp;
    int i,size = 0;
        
    for(i=0;i<argc;i++)
    {
        size += strlen(argv[i])+1;
    }
    
    if( (tmp = malloc(sizeof(char)*size)) == NULL )
    {
        perror("failed to allocate memory");
        return -1;
    }
    
    strcpy(tmp,"");
    for(i=0;i<argc;i++)
    {
        strcat(tmp,argv[i]);
        if(i+1 < argc)
        {
            strcat(tmp," ");
        }
    }
    size = sendCommandWithString(socket,command,tmp);
    free(tmp);
    return size;
}

int sendCommandWithString(int socket, sint8 command, const char * string)
{
    sint32 resp; 
    int size;
    
    printf("<%s>\n",string);
    
    /*on envoi l'ordre*/
    if( send(socket,&command, sizeof(sint8), 0) < sizeof(sint8))
    {
        perror("failed to send order");
        return EXIT_FAILURE;
    }
        
    /*on envoi la string*/
    if(writeString(socket,string) != 0)
    {
        fprintf(stderr,"failed to write string\n");
        return EXIT_FAILURE;
    }
    
    /*on recoit la reponse*/
    if(  (size = recv(socket, &resp, sizeof(sint32),MSG_WAITALL)) != sizeof(sint32))
    {
        if(size == 0)
        {
            printf("connection reset by peer\n");
        }
        else
        {
            perror("read failed");
        }
        return EXIT_FAILURE;
    }
    
    return checkResp(ntohl(resp));
}

int setSpeed(int socket, uint8 value)
{
    sint8 command = COMMAND_SET_SPEED;
    sint32 resp;
    int received;
    
    if( send(socket,&command, sizeof(sint8), 0) < sizeof(sint8))
    {
        fprintf(stderr,"failed to send order\n");
        return EXIT_FAILURE;
    }
    
    if( send(socket,&value, sizeof(sint8), 0) < sizeof(sint8))
    {
        fprintf(stderr,"failed to send order\n");
        return EXIT_FAILURE;
    }
    
    if(  (received=recv(socket, &resp, sizeof(sint32),MSG_WAITALL)) != sizeof(sint32))
    {
        if(received == 0)
        {
            printf("connection reset by peer\n");
        }
        else
        {
            perror("read failed");
        }
        return EXIT_FAILURE;
    }
    
    checkResp(ntohl(resp));
    
    return 0;
}

int sendTwoUINT32(int socket, sint8 command, uint32 int1, uint32 int2)
{
    int received;
    sint32 resp;
    
    printf("%u, %u\n",int1,int2);
    
    if( send(socket,&command, sizeof(sint8), 0) < sizeof(sint8))
    {
        fprintf(stderr,"failed to send order\n");
        return EXIT_FAILURE;
    }
    
    if( send(socket,&int1, sizeof(int1), 0) < sizeof(int1))
    {
        fprintf(stderr,"failed to send order\n");
        return EXIT_FAILURE;
    }
    
    if( send(socket,&int2, sizeof(int2), 0) < sizeof(int2))
    {
        fprintf(stderr,"failed to send order\n");
        return EXIT_FAILURE;
    }
    
    if(  (received=recv(socket, &resp, sizeof(sint32),MSG_WAITALL)) != sizeof(sint32))
    {
        if(received == 0)
        {
            printf("connection reset by peer\n");
        }
        else
        {
            perror("read failed");
        }
        return EXIT_FAILURE;
    }
    
    checkResp(ntohl(resp));
    
    return 0;
}

int stopCapture(int socket, uint16 id)
{
    sint8 command = COMMAND_STOP_CAPTURE;
    sint32 resp;
    int received;
    
    if( send(socket,&command, sizeof(sint8), 0) < sizeof(sint8))
    {
        fprintf(stderr,"failed to send order\n");
        return EXIT_FAILURE;
    }
    
    if( send(socket,&id, sizeof(uint16), 0) < sizeof(uint16))
    {
        fprintf(stderr,"failed to send id\n");
        return EXIT_FAILURE;
    }
    
    if(  (received=recv(socket, &resp, sizeof(sint32),MSG_WAITALL)) != sizeof(sint32))
    {
        if(received == 0)
        {
            printf("connection reset by peer\n");
        }
        else
        {
            perror("read failed");
        }
        return EXIT_FAILURE;
    }
    checkResp(ntohl(resp));
    
    return 0;
}

int getProtocolList(int socket)
{
    sint8 command = COMMAND_GET_PROTOCOL_LIST;
    sint32 nb_entries;
    sint32 resp;
    collector_entry entry;
    int received;

    /* Send the command to control */
    if( send(socket,&command, sizeof(sint8), 0) < sizeof(sint8))
    {
        fprintf(stderr,"failed to send order\n");
        return EXIT_FAILURE;
    }
    /* Entries count */
    if( (received = recv(socket, &nb_entries, sizeof(sint32), MSG_WAITALL)) < 0)  /*Size to read */
    {
        if(received == 0)
        {
            printf("connection reset by peer\n");
        }
        else
        {
            perror("read failed");
        }
        
        return EXIT_FAILURE;    
    }
    /* Entries */
    nb_entries = ntohl(nb_entries);
    while((nb_entries--) > 0)
    {
        if( (received=recv(socket, &entry, (sizeof(collector_entry)-2*sizeof(uint8)),MSG_WAITALL)) < 0)
        {
            if(received == 0)
            {
                printf("connection reset by peer\n");
            }
            else
            {
                perror("read failed");
            }
            return EXIT_FAILURE;
        }

        printf("[protocole=%u, ver=%u]",entry.protocol,entry.ver);
        printf("[ip.src=%d.%d.%d.%d ip.dst=%d.%d.%d.%d port.dst=%d port.src=%d time=%d ]\n",entry.sip[0],entry.sip[1],entry.sip[2],entry.sip[3],entry.dip[0],entry.dip[1],entry.dip[2],entry.dip[3],ntohs(entry.dport),ntohs(entry.sport),ntohl(entry.epoch_time));

    }
    /* Response code */
    if( (received=recv(socket, &resp, sizeof(sint32),MSG_WAITALL)) != sizeof(sint32))
    {
        if(received == 0)
        {
            printf("connection reset by peer\n");
        }
        else
        {
            perror("read failed");
        }
        return EXIT_FAILURE;
    }
    checkResp(ntohl(resp));
    return 0;
}

int setLengthProtocolList(int socket, sint16 value)
{
    sint8 command = COMMAND_SET_BUFFER_LENGTH_PROTO_LIST;
    sint32 resp;
    int received;

    if(value <= 0)
    {
        fprintf(stderr,"value can't be nul or negative\n");
        return EXIT_FAILURE;
    }

    /* Send the command to control */
    if( send(socket,&command, sizeof(sint8), 0) < sizeof(sint8))
    {
        fprintf(stderr,"failed to send order\n");
        return EXIT_FAILURE;
    }

    /* Send the value to control */
    value = htons(value);
    if( send(socket,&value, sizeof(sint16), 0) < sizeof(sint16))
    {
        fprintf(stderr,"failed to send order\n");
        return EXIT_FAILURE;
    }

    /* Response code */
    received = recv(socket, &resp, sizeof(sint32),MSG_WAITALL);
    if(received < sizeof(sint32))
    {
        if(received == 0)
        {
            printf("connection reset by peer\n");
        }
        else
        {
            perror("failed to received response");
        }
        
        return EXIT_FAILURE;
    }

    checkResp(ntohl(resp));

    return 0;
}

int checkResp(sint32 resp)
{
    switch(resp)
    {
        case STATE_NO_ERROR : printf("command successful\n"); break;
        case STATE_NO_DEVICE_SELECTED : printf("no device selected\n"); break;
        case STATE_UNKNOWN_CAPTURE_DEVICE : printf("unknown capture device\n"); break;
        case STATE_UNKNOWN_FILE : printf("unknown file\n"); break;
        case STATE_NOT_ALLOWED_IN_FILE_MODE : printf("not allowed in file mode\n"); break;
        case STATE_NOT_ALLOWED_IN_DEVICE_MODE : printf("not allowed in device mode\n"); break;
        case STATE_MUST_STOP_CAPTURE_BEFORE : printf("capture must be stopped before with dstop\n"); break;
        case STATE_CAPTURE_NOT_STARTED : printf("no capture started\n"); break;
        case STATE_PCAP_ERROR : printf("pcap error\n"); break;
        case STATE_FAILED_TO_RECEIVED_STRING : printf("failed to receive string\n"); break;
        case STATE_SERVER_ERROR : printf("internal server error\n"); break;
        case STATE_SEND_COMMAND_TO_DISPATCH_FAILED : printf("failed to send command to dispatch\n"); break;
        case STATE_NO_FILE_SELECTED : printf("no file selected\n"); break;
        case STATE_ARG_WRONG_OR_MISSING : printf("one argument is wrong or missing\n"); break;
        /*case STATE_IP_VER_MUST_BE_DEFINE_FIRST : printf("an ip version must be defined before others arguments\n"); break;
        case STATE_CAN_T_MERGE_IP_VER : printf("can't build a filter with ipv4 and ipv6\n"); break;
        case STATE_UNKNOWN_FILTER_PARAM : printf("a parameter key is unknown\n"); break;
        case STATE_PARAM_CAN_T_APPEAR_TWICE : printf("a argument is used twice\n"); break;*/
        case STATE_VALUE_POSITIVE_INVALID : printf("value must be positive\n"); break;
        case STATE_WRONG_BPF : printf("wrong bpf filter\n");break;
        case STATE_RECORD_ALREADY_STARTED : printf("a record has already started\n");break;
        case STATE_NOTHING_SELECTED : printf("a file or a device must be selected before\n");break;
        case STATE_DATALINK_NOT_MANAGED : printf("this interface use a not managed datalink type\n");break;
        case STATE_NO_MORE_PORT_AVAILABLE : printf("there is no more port available in the server\n");break;
        case STATE_NOT_IMPLEMENTED_YET : printf("this function is not yet implemented\n"); break;
        case STATE_NOT_RUNNING : printf("the system is not running\n"); break;
        case STATE_NOT_IN_PAUSE : printf("the system is not in pause\n"); break;
        case STATE_ZERO_VALUE : printf("zero value is not allowed\n"); break;
        case STATE_ALREADY_RUNNING : printf("this action is not available while the system is running\n");break;
        case STATE_INVALID_IDENTIFIER : printf("the identifier is unknown or invalid\n");break;
        case STATE_MONITOR_MODE_NOT_AVAILABLE : printf("the monitor mode is not available on this device\n");break;
        
        default : printf("unknwon code %d\n",resp);
    }
    return resp;
}




