#ifdef __gnu_linux__

#define _SVID_SOURCE
#define _BSD_SOURCE
#define _POSIX_SOURCE
#include <sys/types.h>

#endif

#include <pcap.h>
#include <ctype.h> /*isprint*/
#include <string.h> /*memset*/
#include <stdio.h> /*printf, fprintf*/
#include <stdlib.h> /*exit*/
#include <sys/socket.h> /*send*/
#include <strings.h> /*bzero*/
#include <signal.h> /*sigprocmask*/
#include <netinet/ip.h> /*struct ip*/
#include <arpa/inet.h>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <errno.h>
#include <ifaddrs.h>
#include <math.h>

#include "./structlib/structlib.h"
#include "./capturefilterlib/capturefilterlib.h"
#include "./collectorlib/collectorlib.h"
#include "./sharedmemorylib/sharedmemorylib.h"
#include "./utillib/utillib.h"
#include "command.h"
#include "core_type.h"

/*##################### FUNCTIONS PROTOTYPE ####################*/
int setDatalink(int type_link);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void goto_func(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void haltpcap();
void handler(int sig);
int manage_command(mymemory *  mem);
void stopRecording();
pcap_t * pcap_open_live_wifi(const char *source, int snaplen, int promisc, int to_ms, char *errbuf);
/*##################### TCP RESEQ global vars ####################
sequence_entry * seq_start = NULL;
sequence_entry * seq_last = NULL;*/

/*##################### PCAP vars ####################*/
pcap_t * descr; /*pcap descriptor*/
pcap_dumper_t * dumper_descr; /*pcap descriptor to output packet to a file*/
char errbuf[PCAP_ERRBUF_SIZE]; /*pcap error buffer*/
char * local_pcap_file;

/*##################### WORKING vars ####################*/
datalink_info link_info; /*information de la couche liaison de donnée*/
int act, state, init, init2, speed_state; /*control/state variable*/
int to_collector; /*communication pipe*/
uint8 speed; /*facteur de vitesse non recalculé*/
long int speed_factor; /*facteur de vitesse recalculé*/
struct ifaddrs *ifp; /*liste des adresses locale*/
struct timeval prec_packet, goto_val; /*timestamp pour le goto*/
sigset_t old_set, block_set; /*masque de signaux pour le sigsuspend, sigprocmask,...*/
datalink_check checker;

/*##################### STATE vars ####################*/
uint32 packet_readed, packet_in_file;
struct timeval file_first_paquet,file_current,file_duration;

#ifdef DEBUG_MEMORY_SEG
int count_entry, cont_buffer;
#endif

int main(int argc, char *argv[])
{
    int shmDesc, semDesc;
    struct sigaction action;
    mymemory *  mem; /*shared memory*/
    
    descr = NULL;
    dumper_descr = NULL;
    ifp = NULL;
    state = 0;
    act = 0;
    speed = 0x81;
    local_pcap_file = NULL;
    checker = datalink_check_function_plop[DATALINK_MANAGED-1];

    initFilter();

    sigemptyset(&old_set);
    sigemptyset(&block_set);
    sigaddset(&block_set, SIGUSR1);

    if(argc != 4)
    {
        fprintf(stderr,"(dispatch) argument count must be 4, get %d\n",argc);
        return EXIT_FAILURE;
    }
    
    /*arg0 = prgr_name, arg1 = from_control, arg2 = to_control, arg3 = to_collector*/
    
    shmDesc = strtol(argv[1],NULL,10);
    if(errno == ERANGE || errno == EINVAL)
    {
        perror("(dispatch) failed to convert pipe id from_control : ");
        return EXIT_FAILURE;
    }
    
    semDesc = strtol(argv[2],NULL,10);
    if(errno == ERANGE || errno == EINVAL)
    {
        perror("(dispatch) failed to convert pipe id to_control : ");
        return EXIT_FAILURE;
    }
    
    to_collector = strtol(argv[3],NULL,10);
    if(errno == ERANGE || errno == EINVAL)
    {
        perror("(dispatch) failed to convert pipe id to_collector : ");
        return EXIT_FAILURE;
    }
    
    if( (mem = createMemory(shmDesc,3,semDesc,0)) == NULL)
    {
        fprintf(stderr,"(dispatch) failed to create shared memory\n");
        return EXIT_FAILURE;
    }
    
    printf("(dispatch) start : shmDesc:(%d), semDesc:(%d), to_collector:(%d)\n",shmDesc,semDesc,to_collector);
    
    /*on bloque le signal SIGUSR1, il ne peut être reçu qu'en dehors des sections critiques*/
    sigprocmask(SIG_BLOCK, &block_set, &old_set);
    
    /*on definit le handler*/
    action.sa_flags = 0;
    action.sa_handler=handler;
    sigemptyset(&action.sa_mask);
    sigaddset(&action.sa_mask,SIGUSR1); /*on bloque le SIGUSR1 pendant sa reception*/
    sigaction(SIGUSR1,&action,(struct sigaction *)0);

    while(1)
    {           
        if(act == ACT_STOP || ((state&STATE_FILE) && (act&ACT_PAUSE))) /*si rien a faire, on attend un signal*/
        {   
            printf("(dispatch) wait for an order... \n");
            sigemptyset(&block_set);
            sigsuspend(&block_set);
        }
        
        if(act & ACT_HANDLE_SIGNAL)
        {
            act ^= ACT_HANDLE_SIGNAL;
            if(openMemory(mem)< 0)
            {
                perror("(dispatch) failed to open memory:");
                return EXIT_FAILURE;
            }
            
            manage_command(mem);
            
            if(closeMemory(mem)< 0)
            {
                perror("(dispatch) failed to close memory:");
                return EXIT_FAILURE;
            }
            
            printf("ACTION : stop(%d), start(%d), parse(%d), signal(%d), goto(%d), read(%d), pause(%d), resume(%d)\n",
            (act == ACT_STOP)?1:0, (act&ACT_START)?1:0, (act&ACT_PARSE)?1:0, (act&ACT_HANDLE_SIGNAL)?1:0, (act&ACT_GOTO)?1:0, (act&ACT_READ)?1:0, (act&ACT_PAUSE)?1:0, (act&ACT_RESUME)?1:0); 
            
            printf("STATE : nothing(%d), running(%d), recording(%d), file(%d), stream(%d), parsing(%d), reading(%d), pause(%d)\n",
            (state == STATE_NOTHING)?1:0, (state&STATE_RUNNING)?1:0, (state&STATE_RECORDING)?1:0, (state&STATE_FILE)?1:0, (state&STATE_STREAM)?1:0, (state&STATE_PARSING)?1:0, (state&STATE_READING)?1:0, (state&STATE_PAUSE)?1:0);
            
        }
        
        if( (state&STATE_FILE) && (act & ACT_PAUSE))
        {
            continue;
        }
        
        if(act & ACT_GOTO)
        {
            printf("(dispatch) start to goto\n");
            sigemptyset(&block_set);
            sigprocmask(SIG_SETMASK, &block_set, &old_set);
            switch(pcap_loop(descr, -1, goto_func, NULL))
            {   
                case 0:
                    printf("(dispatch) end of file\n");
                    state = STATE_FILE;
                    act = ACT_STOP;/*on stop*/
                    break;
                case -2: /*pcap_breakloop case*/
                    printf("(dispatch) pcap_loop : pcap_breakloop case\n");
                    if( state & STATE_GOTO)
                    {
                        act |= ACT_GOTO; /*needed to continued*/
                    }
                    break;
                case -1: /*error case*/
                    pcap_perror(descr,"(dispatch) pcap_loop : error case :");
                default:
                    printf("(dispatch) pcap_loop : error case\n");
                    act = ACT_STOP;/*on stop*/
            }
        }
        else if(act & ACT_START)
        {
            if(ifp != NULL)
            {
                freeifaddrs(ifp);
                ifp = NULL;
            }
            
            if(getifaddrs(&ifp) < 0)
            {
                perror("(dispatch) get interface addresses failed");
                ifp = NULL;
            }
            
            printf("(dispatch) start to listen data\n");
            sigemptyset(&block_set);
            sigprocmask(SIG_SETMASK, &block_set, &old_set);
            switch(pcap_loop(descr, -1, got_packet, NULL))
            {   
                case -2: /*pcap_breakloop case*/
                    printf("(dispatch) pcap_loop : pcap_breakloop case\n");
                    act |= ACT_START; /*needed to restart*/
                    break;
                case -1: /*error case*/
                    pcap_perror(descr,"(dispatch) pcap_loop : error case :");
                default:
                    printf("(dispatch) pcap_loop : error case\n");
                    act = ACT_STOP;/*on stop*/
            }
        }
        else if((act & ACT_PARSE) || (act & ACT_READ) || ((state&STATE_FILE) && (act&ACT_RESUME)))
        {
            printf("(dispatch) start to parse/read file\n");
            sigemptyset(&block_set);
            sigprocmask(SIG_SETMASK, &block_set, &old_set);
            switch(pcap_loop(descr, -1, got_packet, NULL))
            {   
                case 0:
                    printf("(dispatch) end of file\n");
                    haltpcap();
                    
                    packet_in_file = packet_readed;
                    file_duration = file_current;
                    state = STATE_PARSED;
                    
                    /*try to reset the ressource*/
                    if(pcap_file != NULL)
                    {
                        if( (descr = pcap_open_offline(local_pcap_file,errbuf)) == NULL)
                        {
                            fprintf(stderr,"(dispatch) pcap_open_offline : %s\n",errbuf);
                        }
                        else
                        {
                            state |= STATE_FILE;
                        }
                    }
                    
                    flushAllSegment();/*on detruit la liste des segments tcp*/
                    act = ACT_STOP;
                    break;
                case -2: /*pcap_breakloop case*/
                    printf("(dispatch) pcap_loop : pcap_breakloop case\n");
                    if(state & STATE_PARSING)
                    {
                        act |= ACT_PARSE; /*needed to restart in parsing*/
                    }
                    else if(state & STATE_READING)
                    {
                        act |= ACT_READ; /*needed to restart in reading*/
                    }
                    
                    break;
                case -1: /*error case*/
                    pcap_perror(descr,"(dispatch) pcap_loop, error case, halt :");
                    haltpcap();
                    act = ACT_STOP;/*on stop*/
                    break;
                default:
                    /*unknwon event*/
                    fprintf(stderr,"(dispatch) pcap_loop : unknown event, halt\n");
                    haltpcap();
                    act = ACT_STOP;/*on stop*/
            }
        }
        else
        {
            act = ACT_STOP;/*on stop*/
        }

        /*au prochain tour de boucle, on rentre en section critique, on ne peut plus etre dérangé par un signal*/
        sigemptyset(&block_set);
        sigaddset(&block_set, SIGUSR1);
        sigprocmask(SIG_BLOCK, &block_set, &old_set);
    }
    
    printf("(dispatch) exit\n");
    return 0;
}

void handler(int sig)
{
    printf("(dispatch) receiving signal\n");
    if(sig == SIGUSR1)/*est ce bien le signal qui nous interesse */
    {
        printf("(dispatch) SIGUSR1\n");
        act |= ACT_HANDLE_SIGNAL;
        if((state & STATE_RUNNING) && descr != NULL)/*on est en train de dispatcher, il faut interrompre*/
        {
            pcap_breakloop(descr); /*on brise la boucle s'il y en a une*/
        }
        /*sigemptyset(&block_set);
        sigaddset(&block_set, SIGUSR1);
        sigprocmask(SIG_SETMASK,&block_set, &old_set);*/
    }
}

int manage_command(mymemory *  mem)
{
    int to_send = STATE_NO_ERROR, size, pipes[2], pipes2[2], i;
    char * buffer, arg1[10], arg2[10], arg3[10], arg4[10];
    struct bpf_program filter;
    uint16 id;
    struct sockaddr_in sockaddr_server;
    struct core_state cstate;
    struct pcap_stat stat;
    
    printf("(dispatch) manage command\n");
    
    switch(getAction(mem))
    {
    /*####################################################################################################################*/
        case COMMAND_SELECT_CAPTURE_DEVICE:
        case COMMAND_SELECT_CAPTURE_DEVICE_WITH_MONITORING:
        
            if(getAreaMemory(mem, 0,(void **) &buffer, &size) < 0) /*don't care about size, it's a string*/
            {
                fprintf(stderr,"(dispatch) manage_command, argument 0 is wrong or missing\n");
                to_send = STATE_ARG_WRONG_OR_MISSING; break;
            }
        
            printf("(dispatch) manage_command, select capture device : <%s>\n", buffer);
            
            /*set capture device variable*/
            if(descr != NULL)
            {
                to_send = STATE_MUST_STOP_CAPTURE_BEFORE;break;
            }
            
            if(getAction(mem) == COMMAND_SELECT_CAPTURE_DEVICE)
            {
                if( (descr = pcap_open_live(buffer, MAXBYTES2CAPTURE, 1, 512, errbuf)) == NULL)
                {
                    fprintf(stderr,"(dispatch) pcap_open_live : %s\n",errbuf);
                    to_send = STATE_PCAP_ERROR; break;
                }
            }
            else
            {
                if( (descr = pcap_open_live_wifi(buffer, MAXBYTES2CAPTURE, 1, 512, errbuf)) == NULL)
                {
                    fprintf(stderr,"(dispatch) pcap_open_live : %s\n",errbuf);
                    to_send = STATE_PCAP_ERROR; break;
                }
            }
            
            /*if(pcap_set_buffer_size(descr,50000000) != 0)
            {
                fprintf(stderr,"(dispatch) pcap_set_buffer_size : %s\n",errbuf);
                haltpcap();
                to_send = STATE_PCAP_ERROR;break;
            }*/
            
            if(setDatalink(pcap_datalink(descr)) < 0)
            {
                fprintf(stderr,"(dispatch) datalink type not supported  : %s\n",pcap_datalink_val_to_name(pcap_datalink(descr)));
                haltpcap();
                to_send = STATE_DATALINK_NOT_MANAGED;break;
            }
            
            capture_setSpeed(speed); /*enable buffering in wait and set speed*/
            capture_flush(); /*flush buffering in wait*/
            
            state = STATE_STREAM;
            state |= STATE_RUNNING;
            act  = ACT_START;
            
            break;
    /*####################################################################################################################*/
        case COMMAND_SELECT_CAPTURE_FILE:
            if(getAreaMemory(mem, 0,(void **) &buffer, &size) < 0) /*don't care about size, it's a string*/
            {
                fprintf(stderr,"(dispatch) manage_command, argument 0 is wrong or missing\n");
                to_send = STATE_ARG_WRONG_OR_MISSING; break;
            }
        
            printf("(dispatch) select capture file : <%s>\n", buffer);
            if(descr != NULL)
            {
                to_send = STATE_MUST_STOP_CAPTURE_BEFORE;break;
            }
            
            if(local_pcap_file != NULL)
            {
                free(local_pcap_file);
            }
            
            if( (local_pcap_file = malloc(size * sizeof(char))) == NULL )
            {
                perror("(dispatch) failed to get memory to pcap file");
                to_send = STATE_PCAP_ERROR;break;
            }
            
            strcpy(local_pcap_file, buffer);
            
            if( (descr = pcap_open_offline(buffer,errbuf)) == NULL)
            {
                fprintf(stderr,"(dispatch) pcap_open_offline : %s\n",errbuf);
                free(local_pcap_file); local_pcap_file = NULL;
                to_send = STATE_PCAP_ERROR;break;
            }
            
            if(setDatalink(pcap_datalink(descr)) < 0)
            {
                fprintf(stderr,"(dispatch) datalink type not supported  : %s\n",pcap_datalink_val_to_name(pcap_datalink(descr)));
                free(local_pcap_file); local_pcap_file = NULL;
                haltpcap();
                to_send = STATE_DATALINK_NOT_MANAGED;break;
            }
            
            capture_setFileMode(); /*flush wait and disable buffering in wait*/
            state = STATE_FILE;
            
            break;
    /*####################################################################################################################*/
        case COMMAND_SET_MASTER_FILTER:
                if(descr == NULL)
                {
                    fprintf(stderr,"(dispatch) pcap descriptor is NULL\n");
                    to_send = STATE_NOTHING_SELECTED; break;
                }
                
                if(getAreaMemory(mem, 0,(void **) &buffer, &size) < 0) /*don't care about size, it's a string*/
                {
                    fprintf(stderr,"(dispatch) manage_command, argument 0 is wrong or missing\n");
                    to_send = STATE_ARG_WRONG_OR_MISSING; break;
                }
                
                if(pcap_compile(descr,&filter, buffer,1,0) != 0)
                {
                    fprintf(stderr,"(dispatch) pcap_compile : %s\n",pcap_geterr(descr));
                    to_send = STATE_PCAP_ERROR;break;
                }

                if(pcap_setfilter(descr,&filter) != 0)
                {
                    fprintf(stderr,"(dispatch) pcap_setfilter : %s\n",pcap_geterr(descr));
                    pcap_freecode(&filter);
                    to_send = STATE_PCAP_ERROR;break;
                }
                pcap_freecode(&filter);

                printf("(dispatch) set master filter : <%s>\n", buffer);
            break; 
    /*####################################################################################################################*/
        case COMMAND_DISABLE_CAPTURE_DEVICE:
            printf("(dispatch) disable capture device\n");
            
            if(descr != NULL)
            {
                stat.ps_ifdrop = 0;
            	if( pcap_stats(descr, &stat) < 0) 
            	{
            		fprintf(stderr, "pcap_stats: %s\n", pcap_geterr(descr));
            	}
            	else
            	{
            	    /*printf("%u packet%s captured", packets_captured);*/
                	printf("%u packet(s) received by filter\n", stat.ps_recv);
                	printf("%u packet(s) dropped by kernel\n", stat.ps_drop);
                	printf("%u packet(s) dropped by interface\n",stat.ps_ifdrop);
            	}
            }
            
            haltpcap();
            act = ACT_STOP; /*on remet a zero*/
            
            stopRecording(); /*stop recording*/
            capture_flush(); /*flush buffering in wait*/
            flushAllSegment(); /*free tcp list*/
            
            /*break; on stop l'ensemble des captures lors d'un changement de device, cela oblige de recréer les filtres 
            */
    /*####################################################################################################################*/
        case COMMAND_STOP_ALL_CAPTURE:
            printf("(dispatch) stop all capture\n");

            removeAllFilter();

            break;
    /*####################################################################################################################*/
        case COMMAND_SET_SPEED:
            if(getAreaMemory(mem, 0,(void **) &buffer, &size) < 0)
            {
                fprintf(stderr,"(dispatch) set speed, argument 0 is wrong or missing\n");
                to_send = STATE_ARG_WRONG_OR_MISSING; break;
            }
            
            if(size != 1)
            {
                fprintf(stderr,"(dispatch) set speed, argument 0 has a size different of 1 : %d\n", size);
                to_send = STATE_ARG_WRONG_OR_MISSING; break;
            }
            
            printf("(dispatch) set speed\n");
            speed = buffer[0];
            speed_factor = 100 + lround(sqrt(pow((speed&0x7F),3)));
            if(state & STATE_STREAM)
            {
                capture_setSpeed(speed);
            }
            
            break;
    /*####################################################################################################################*/
        case COMMAND_PARSE_FILE:
            printf("(dispatch) parse file\n");
            
            if(descr == NULL)
            {
                fprintf(stderr,"(dispatch) pcap descriptor is NULL\n");
                to_send = STATE_NO_FILE_SELECTED;break;
            }
            
            if( (state & STATE_STREAM) != 0)
            {
                fprintf(stderr,"(dispatch) try to parse in device mode\n");
                to_send = STATE_NOT_ALLOWED_IN_DEVICE_MODE;break;
            }
            
            if(state & STATE_RUNNING)
            {
                fprintf(stderr,"(dispatch) not allowed in running mode\n");
                to_send = STATE_ALREADY_RUNNING;break;
            }
            
            act = ACT_PARSE;
            state |= STATE_RUNNING;
            state |= STATE_PARSING;
            
            if( !(state & STATE_PARSED) )
            {
                packet_in_file = 0;
                file_duration.tv_usec = 0; file_duration.tv_sec = 0;
            }
            file_current.tv_usec = 0; file_current.tv_sec = 0;
            file_first_paquet.tv_usec = 0; file_first_paquet.tv_sec = 0;
            
            packet_readed = 0;
            init2 = 1;/*indique qu'on doit retenir le timestamp du premier packet*/
            break;
    /*####################################################################################################################*/
        case COMMAND_FILE_READ:
            printf("(dispatch) read file\n");
            
            if(descr == NULL)
            {
                fprintf(stderr,"(dispatch) pcap descriptor is NULL\n");
                to_send = STATE_NO_FILE_SELECTED;break;
            }
            
            if( (state & STATE_STREAM) != 0)
            {
                fprintf(stderr,"(dispatch) try to parse in device mode\n");
                to_send = STATE_NOT_ALLOWED_IN_DEVICE_MODE;break;
            }
            
            if(state & STATE_RUNNING)
            {
                fprintf(stderr,"(dispatch) not allowed in running mode\n");
                to_send = STATE_ALREADY_RUNNING;break;
            }
            
            act = ACT_READ;
            state |= STATE_RUNNING;
            state |= STATE_READING;
            
            if( !(state & STATE_PARSED) )
            {
                packet_in_file = 0;
                file_duration.tv_usec = 0; file_duration.tv_sec = 0;
            }
            file_current.tv_usec = 0; file_current.tv_sec = 0;
            file_first_paquet.tv_usec = 0; file_first_paquet.tv_sec = 0;
            
            packet_readed = 0;
            
            init = 1; /*indique qu'on doit retenir les infos du premier packet lu comme une reference*/
            init2 = 1; /*indique qu'on doit retenir le timestamp du premier packet*/
            break;
    /*####################################################################################################################*/
        case COMMAND_FLUSH_SEGMENT:
            printf("(dispatch) flush segment list\n");
            flushAllSegment();
            break;
    /*####################################################################################################################*/
        /*
         * CAPTURE MANAGER
         */
        case COMMAND_START_CAPTURE:
            printf("(dispatch) start capture\n");

            if(descr == NULL)
            {
                fprintf(stderr,"(dispatch) pcap descriptor is NULL\n");
                to_send = STATE_NOTHING_SELECTED; break;
            }

            /*recuperation du filtre bpf en provenance de la memoire partagée*/
            if(getAreaMemory(mem, 0,(void **) &buffer, &size) < 0) /*don't care about size, it's a string*/
            {
                fprintf(stderr,"(dispatch) manage_command, argument 0 is wrong or missing\n");
                to_send = STATE_ARG_WRONG_OR_MISSING; break;
            }

            if((size = socket(PF_INET,SOCK_STREAM,0)) < 0 )
            {
                perror("(dispatch) manage_command, failed to create socket");
                to_send = STATE_SERVER_ERROR; break;
            }
            printf("SOCKET : %d\n",size);
            /*ouverture du pipe de communication entre le dispatch et le wait*/
            if(pipe(pipes) < 0)
            {
                perror("(dispatch) manage_command, failed to open pipe (1)");
                close(size);
                to_send = STATE_SERVER_ERROR; break;
            }
            printf("PIPE : %d/%d\n", pipes[0], pipes[1]);
            
            if(pipe(pipes2) < 0)
            {
                perror("(dispatch) manage_command, failed to open pipe (2)");
                close(size);
                close(pipes[0]);close(pipes[1]);
                to_send = STATE_SERVER_ERROR; break;
            }
            printf("PIPE2 : %d/%d\n", pipes2[0], pipes2[1]);
            
            printf("socket : %d, pipe1 : (%d/%d), pipe2 : (%d/%d)\n",size, pipes[0], pipes[1], pipes2[0], pipes2[1]);
            /*ouverture du socket de communication du wait*/
            for(id = WAIT_START_PORT;id<WAIT_START_PORT+WAIT_MAX_PORT;id++)/*TODO faire un bitmap au lieu d'un integer limite*/
            {
                bzero((char *) &sockaddr_server , sizeof(sockaddr_server)); 
                sockaddr_server.sin_addr.s_addr = htonl(INADDR_ANY);
                sockaddr_server.sin_family = AF_INET;
                sockaddr_server.sin_port = htons(id);

                if(bind(size, (struct sockaddr *) &sockaddr_server, sizeof(sockaddr_server)) < 0)
                {
                    if(errno == EADDRINUSE)/*le port n'est pas disponible*/
                    {
                        continue;
                    }
                    perror("(dispatch) manage_command, bind error");
                    close(pipes[0]);close(pipes[1]);close(pipes2[0]);close(pipes2[1]);close(size);
                    to_send = STATE_SERVER_ERROR; goto break_mark;
                }
                break;
            }
            
            if(id == WAIT_START_PORT+WAIT_MAX_PORT)
            {
                close(pipes[0]);close(pipes[1]);close(pipes2[0]);close(pipes2[1]);close(size);
                to_send = STATE_NO_MORE_PORT_AVAILABLE; break;
            }

            /*add a capture struct in the list*/
            if(addFilter(buffer,id,pipes[1],pipes2[1]))
            {
                close(pipes[0]);close(pipes[1]);close(pipes2[0]);close(pipes2[1]);close(size);
                to_send = STATE_SERVER_ERROR; break;
            }
            
            /*start client manager*/
            i = fork();
            if(i == 0)
            {/*fils*/
                close(pipes[1]);/*close write*/
                close(pipes2[1]);/*close write*/
                sprintf(arg1,"%d",size);
                sprintf(arg2,"%d",pipes[0]);
                sprintf(arg3,"%d",pipes2[0]);
                sprintf(arg4,"%u",speed);
                if(state & STATE_FILE)
                {
                    /*disable buffering*/
                    if( execlp("./wait","wait", arg1, arg2, arg3,"0",arg4, (char *)0) < 0)
                    {
                        perror("(dispatch) manage_command,failed to execlp wait");
                        exit(EXIT_FAILURE);
                    }
                }
                else
                {
                    /*enable buffering*/
                    if( execlp("./wait","wait", arg1, arg2, arg3,"1",arg4, (char *)0) < 0)
                    {
                        perror("(dispatch) manage_command,failed to execlp wait");
                        exit(EXIT_FAILURE);
                    }
                }
                
            }
            else if(i < 0)
            {/*erreur*/
                perror("(dispatch) manage_command,failed to fork");
                close(pipes[0]);close(pipes[1]);close(pipes2[0]);close(pipes2[1]);close(size);
                removeFilter(id);
                to_send = STATE_SERVER_ERROR;
                break;
            }
            /*else
            {pere
                close(pipes[0]); close read
                close(pipes2[0]); close read
                close(size); close the server socket
            }*/
            
            /*ecrire le port dans la memoire*/
            cleanAreaMemories(mem);
            
            if( (buffer = getNextAvailableAreaMemory(mem, sizeof(id))) == NULL)
            {
                fprintf(stderr,"(dispatch) manage_command, failed to allocate memory area on shared memory\n");
                close(pipes[1]);close(pipes2[1]);close(size);
                removeFilter(id);
                
                state=STATE_SERVER_ERROR;
                break;
            }
            
            memcpy(buffer,&id,sizeof(id));
            break_mark:
            break;
    /*####################################################################################################################*/
        case COMMAND_STOP_CAPTURE:
            printf("(dispatch) stop capture\n");
            
            if(getAreaMemory(mem, 0, (void **) &buffer, &size) < 0)
            {
                fprintf(stderr,"(dispatch) manage_command, argument 0 is wrong or missing\n");
                to_send = STATE_ARG_WRONG_OR_MISSING; break;
            }
            
            if(size != 2)
            {
                fprintf(stderr,"(dispatch) set speed, argument 0 has a size different of 2 : %d\n", size);
                to_send = STATE_ARG_WRONG_OR_MISSING; break;
            }
            
            ((uint8*)(&id))[0] = buffer[0];
            ((uint8*)(&id))[1] = buffer[1];
            
            printf("(dispatch) id to remove : %u\n",id);
            if(removeFilter(id) != 0)
            {
                to_send = STATE_INVALID_IDENTIFIER;
            }

            break;
    /*####################################################################################################################*/
        /*
         * RECORD MANAGER
         */    
        case COMMAND_START_RECORD:
        
            if(getAreaMemory(mem, 0,(void **) &buffer, &size) < 0) /*it's a string, we don't care about size*/
            {
                fprintf(stderr,"(dispatch) manage_command, argument 0 is wrong or missing\n");
                to_send = STATE_ARG_WRONG_OR_MISSING; break;
            }
        
            printf("(dispatch) start record %s\n", buffer);
            
            if(descr == NULL)
            {
                fprintf(stderr,"(dispatch) pcap descriptor is NULL\n");
                to_send = STATE_NOTHING_SELECTED; break;
            }
            
            /*verifier qu'il n'y a pas deja une capture en cours*/
            if(dumper_descr != NULL)
            {
                fprintf(stderr,"(dispatch) capture already started\n");
                to_send = STATE_RECORD_ALREADY_STARTED; break;
            }
            
            /*pcap_dump_open*/
            if( (dumper_descr = pcap_dump_open(descr,buffer)) == NULL)
            {
                fprintf(stderr,"(dispatch) pcap_dump_open : %s\n",pcap_geterr(descr));
                to_send = STATE_PCAP_ERROR;break;
            }
            /*dans le code : pcap_dump*/
            /*change state*/
            state |= STATE_RECORDING;
            break;
    /*####################################################################################################################*/
        case COMMAND_STOP_RECORD:
            printf("(dispatch) stop record\n");
            stopRecording();
            
            break;
    /*####################################################################################################################*/
        case COMMAND_STREAM_PAUSE:
            printf("(dispatch) stream pause\n");
            
            if(!(state & STATE_RUNNING))
            {
                to_send = STATE_NOT_RUNNING;break;
            }
            
            
            state |= STATE_PAUSE;
            act |= ACT_PAUSE ;
            
            if(act & ACT_RESUME)
            {
                act ^= ACT_RESUME;
            }
            
            if(state & STATE_STREAM)
            {
                capture_pause();
            }
            else
            {
                state ^= STATE_RUNNING;/*on ne doit interrompre que lorsqu'il s'agit d'un file*/
            }

            break;
    /*####################################################################################################################*/
        case COMMAND_STREAM_RESUME:
            printf("(dispatch) stream resume\n");

            if(!(state & STATE_PAUSE))
            {
                to_send = STATE_NOT_IN_PAUSE;break;
            }
            
            state ^= STATE_PAUSE;
            act |= ACT_RESUME;
            
            if(act & ACT_PAUSE)
            {
                act ^= ACT_PAUSE;
            }
            
            if(state & STATE_STREAM)
            {
                capture_resume();
            }
            else
            {
                state |= STATE_RUNNING;
            }
            break;
    /*####################################################################################################################*/
        case COMMAND_FILE_GOTO:
            printf("(dispatch) file GOTO\n");
            
            if(descr == NULL)
            {
                fprintf(stderr,"(dispatch) pcap descriptor is NULL\n");
                to_send = STATE_NO_FILE_SELECTED;break;
            }
            
            if( (state & STATE_STREAM) != 0)
            {
                fprintf(stderr,"(dispatch) try to parse in device mode\n");
                to_send = STATE_NOT_ALLOWED_IN_DEVICE_MODE;break;
            }
            
            if(state & STATE_RUNNING)
            {
                fprintf(stderr,"(dispatch) not allowed in running mode\n");
                to_send = STATE_ALREADY_RUNNING;break;
            }
            
            if(getAreaMemory(mem, 0,(void **) &buffer, &size) < 0)
            {
                fprintf(stderr,"(dispatch) manage_command, argument 0 is wrong or missing\n");
                to_send = STATE_ARG_WRONG_OR_MISSING; break;
            }
            
            if(size != sizeof(struct timeval))
            {
                fprintf(stderr,"(dispatch) set speed, argument 0 has a size different of %lu : %d\n",sizeof(struct timeval), size);
                to_send = STATE_ARG_WRONG_OR_MISSING; break;
            }
            
            memcpy(&goto_val,buffer,sizeof(struct timeval));
            
            act = ACT_GOTO;
            state |= STATE_RUNNING;
            state |= STATE_GOTO;
            init = 1; /*indique qu'on doit retenir les infos du premier packet lu comme une reference*/
            break;
            
    /*####################################################################################################################*/        
        case COMMAND_GET_STATE:
        
            cleanAreaMemories(mem);
            
            if( (buffer = getNextAvailableAreaMemory(mem, sizeof(struct core_state))) == NULL)
            {
                fprintf(stderr,"(dispatch) manage_command, failed to allocate memory area on shared memory\n");
                state=STATE_SERVER_ERROR;break;
            }
            
            cstate.state = state;
            cstate.packet_readed = packet_readed;
            cstate.packet_in_file = packet_in_file;
            timevalSubstraction(&cstate.file_current,&file_current,&file_first_paquet);
            timevalSubstraction(&cstate.file_duration,&file_duration,&file_first_paquet);

            memcpy(buffer,&cstate,sizeof(struct core_state));
        
            break;
    /*####################################################################################################################*/
        default:
            fprintf(stderr,"(dispatch) unknown command : %d\n",getAction(mem));
    }
    
    setState(mem,to_send);
    
    if(unlockSem(mem->semDescr, 1) < 0)
    {
        perror("(controllib) sendCommandToDispatch, failed to wait semaphore from dispatch");
        return EXIT_FAILURE;
    }
    
    return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const uint8 * packet)
{
    int local = 0; /*0 s'il s'agit d'un paquet etrangé, 1 s'il s'agit d'un paquet local*/
    int iterateur = 0, iterateur_bis = 0;    
    int network_protocole, transport_protocole;
    collector_entry header_to_send;
    
    unsigned int network_size = 0;

#ifdef PRINT_PCAP
    char char_time[26];
#endif
    
    /*sigemptyset(&block_set);
    sigprocmask(SIG_SETMASK, &block_set, &old_set);*/
    
#ifdef DEBUG_MEMORY_SEG
    printf("memory, entry:%d, buffer:%d\n",count_entry, cont_buffer);
#endif
        
    /*RESET ERROR BUFFER*/
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    
    /*EMPTY PACKET*/
    if(packet == NULL)
    {
        printf("NULL PACKET \n\n");
        return;
    }
    
    /*RECORDING*/
    if(state & STATE_RECORDING)
    {
        pcap_dump((u_char *)dumper_descr,pkthdr,packet);
    }

#ifdef PRINT_PCAP
    printf("(Dispatch) Received packet size : %d, ",pkthdr->len);
    ctime_r(&pkthdr->ts.tv_sec,char_time);
    char_time[24] = '\0';
    printf("time : %s, %u (microsecs)\n",char_time, pkthdr->ts.tv_usec);
#endif

    if((state & STATE_FILE))
    {
        if((state & STATE_READING) )
        {
            /*if init, no wait*/
            if(init)
            {
                prec_packet = pkthdr->ts;
                init = 0;
            }
        
            /*delay*/
            if((speed&0x80))
            {
                /*if( usleep(  ((pkthdr->ts.tv_sec - prec_packet.tv_sec)*1000000 + (pkthdr->ts.tv_usec - prec_packet.tv_usec) ) * (speed&0x7F) ) < 0 && errno != EINTR)*/
                if( usleep(  (((pkthdr->ts.tv_sec - prec_packet.tv_sec)*1000000 + (pkthdr->ts.tv_usec - prec_packet.tv_usec) ) * speed_factor)/100 ) < 0 && errno != EINTR)
                {
                    perror("(dispatch) got_packet, failed to usleep");
                }
            }
            else
            {
                /*if( usleep(  ((pkthdr->ts.tv_sec - prec_packet.tv_sec)*1000000 + (pkthdr->ts.tv_usec - prec_packet.tv_usec) ) / (speed&0x7F) ) < 0 && errno != EINTR)*/
                if( usleep(  (((pkthdr->ts.tv_sec - prec_packet.tv_sec)*1000000 + (pkthdr->ts.tv_usec - prec_packet.tv_usec) ) *100)/speed_factor ) < 0 && errno != EINTR)
                {
                    perror("(dispatch) got_packet, failed to usleep");
                }
            }
        
            /*TODO ça ne va pas, on ne se base pas sur le delay du paquet precedent pour calculer le delay du paquet suivant*/
        
            prec_packet = pkthdr->ts;
        }
        
        if(init2)
        {
            file_first_paquet = pkthdr->ts;
            init2 = 0;
        }
        
        file_current = pkthdr->ts;
        packet_readed += 1;
    }
/*############# CHECKER #######################################################################################################*/
    /*DATALINK CHECKER*/
    if(checker.check(packet, pkthdr->len, &network_protocole) < 0)
    {
        #if defined(PRINT_DROP) || defined(PRINT_ETHERNET)
        printf("(dispatch) drop datalink frame\n");
        #endif
        
        return;
    }
    
    /*COLLECTOR */
    bzero(header_to_send.sip,sizeof(uint8)*16);
    bzero(header_to_send.dip,sizeof(uint8)*16);
    header_to_send.status = 0;
    
    /*NETWORK CHECKER*/
    for(iterateur = 0;iterateur<(NETWORK_MANAGED-1);iterateur+=1)
    {
        if(network_check_function[iterateur].protocol_type == network_protocole)
        {
            if(network_check_function[iterateur].check(packet, pkthdr->len,ifp,&network_size,&transport_protocole,&local,&header_to_send) < 0)
            {
                #if defined(PRINT_DROP) || defined(PRINT_IP)
                printf("(dispatch) drop network packet\n");
                #endif
                return;
            }
            
            /*TRANSPORT CHECKER*/
            for(iterateur_bis = 0;iterateur_bis<(TRANSPORT_MANAGED-1);iterateur_bis+=1)
            {
                if(network_check_function[iterateur].transport[iterateur_bis].protocol_type == transport_protocole)
                {
                    if(network_check_function[iterateur].transport[iterateur_bis].check(pkthdr,packet,local,&header_to_send) < 0)
                    {
                        #if defined(PRINT_DROP) || defined(PRINT_TCP) || defined(PRINT_UDP)
                        printf("(dispatch) drop transport segment\n");
                        #endif
                        return;
                    }
                    
                    break;
                }
            }
            
            /*cas de base, pas de protocole correspondant*/
            if(iterateur_bis == (TRANSPORT_MANAGED-1))
            {
                if(network_check_function[iterateur].transport[TRANSPORT_MANAGED-1].check(pkthdr,packet,local,&header_to_send) < 0)
                {
                    #if defined(PRINT_DROP) || defined(PRINT_TCP) || defined(PRINT_UDP)
                    printf("(dispatch) drop transport segment (default)\n");
                    #endif
                    return;
                }
            }
            
            break;
        }
    }
    
    /*cas de base, pas de protocole correspondant*/
    if(iterateur == (NETWORK_MANAGED-1))
    {
        if(network_check_function[NETWORK_MANAGED-1].check(packet, pkthdr->len,ifp,&network_size,&transport_protocole,&local,&header_to_send)
        || network_check_function[NETWORK_MANAGED-1].transport[0].check(pkthdr,packet,local,&header_to_send) < 0)
        {
            #if defined(PRINT_DROP) || defined(PRINT_TCP) || defined(PRINT_UDP)
            printf("(dispatch) drop data (default)\n");
            #endif
            return;
        }
    }
	
	/* COLLECTOR */
    header_to_send.epoch_time = pkthdr->ts.tv_sec;  /* Epoch time */
    write(to_collector,&header_to_send,sizeof(header_to_send));/*TODO WRITE check return value and continue the writting*/

    /*send to node*/
    if(!(state & STATE_PARSING))
    {
        sendToAllNode(packet,link_info.header_size+network_size,(pkthdr->ts));
    }
}

void goto_func(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    /*sigemptyset(&block_set);
    sigprocmask(SIG_SETMASK, &block_set, &old_set); */
    
    if(init)
    {
        init = 0;
        
        goto_val.tv_sec += pkthdr->ts.tv_sec;
        goto_val.tv_usec += pkthdr->ts.tv_usec;
        
        while(goto_val.tv_usec > 1000000)
        {
            goto_val.tv_sec += 1;
            goto_val.tv_usec -= 1000000;
        }
    }
    else
    {
        if(pkthdr->ts.tv_sec > goto_val.tv_sec || (pkthdr->ts.tv_sec == goto_val.tv_sec &&  pkthdr->ts.tv_usec > goto_val.tv_usec))
        {
            prec_packet = pkthdr->ts; /*necessaire pour le delay lors d'un read*/
            
            pcap_breakloop(descr); /*on brise la boucle*/
            state ^= STATE_GOTO; /*on arrete le goto*/
            state ^= STATE_RUNNING;
            act = ACT_STOP;
        }
    }
}

void haltpcap()
{
    if(descr != NULL)
    {
        pcap_breakloop(descr); /*on brise la boucle*/
        pcap_close(descr); /*on libère les ressources*/
    }
    descr = NULL;
    state = STATE_NOTHING;
}

void stopRecording()
{
    /*pcap_dump_flush, pcap_dump_close*/
    /*change state*/
    
    if(state & STATE_RECORDING)
    {
        pcap_dump_flush(dumper_descr); /*peu merder, et on fait quoi alors?*/
        pcap_dump_close(dumper_descr);
        dumper_descr = NULL;
    
        state ^= STATE_RECORDING;
    }
}

int setDatalink(int type_link)
{
    int i;
    
    for(i = 0;i<DATALINK_MANAGED-1;i+=1)
    {
        printf("(datalink) %d vs %d\n",datalink_check_function_plop[i].datalink_type,type_link);
        if(datalink_check_function_plop[i].datalink_type == type_link)
        {
            link_info.header_size = datalink_check_function_plop[i].header_size;
            link_info.frame_payload_max_size = datalink_check_function_plop[i].frame_payload_max_size;
            link_info.footer = datalink_check_function_plop[i].footer;
            checker = datalink_check_function_plop[i];
            return (link_info.datalink_type = datalink_check_function_plop[i].datalink_type);
        }
    }
    
    link_info.header_size = datalink_check_function_plop[DATALINK_MANAGED-1].header_size;
    link_info.frame_payload_max_size = datalink_check_function_plop[DATALINK_MANAGED-1].frame_payload_max_size;
    link_info.footer = datalink_check_function_plop[DATALINK_MANAGED-1].footer;
    checker = datalink_check_function_plop[DATALINK_MANAGED-1];
    
    fprintf(stderr,"(disptach) setDatalink, unknown datalink\n");
    
    return -1;
}

pcap_t *
pcap_open_live_wifi(const char *source, int snaplen, int promisc, int to_ms, char *errbuf)
{
	pcap_t *p;
	int status;

	p = pcap_create(source, errbuf);
	if (p == NULL)
		return (NULL);
	
	if(pcap_can_set_rfmon(p) == 1)
	{
	    status = pcap_set_rfmon(p, 1);
    	if (status < 0)
    		goto fail;
	}
	else
	{
        printf("(dispatch) pcap_open_live_wifi, monitor mode is not available for the interface %s\n",source);
	}
		
	status = pcap_set_snaplen(p, snaplen);
	if (status < 0)
		goto fail;
	status = pcap_set_promisc(p, promisc);
	if (status < 0)
		goto fail;
	status = pcap_set_timeout(p, to_ms);
	if (status < 0)
		goto fail;
	/*
	 * Mark this as opened with pcap_open_live(), so that, for
	 * example, we show the full list of DLT_ values, rather
	 * than just the ones that are compatible with capturing
	 * when not in monitor mode.  That allows existing applications
	 * to work the way they used to work, but allows new applications
	 * that know about the new open API to, for example, find out the
	 * DLT_ values that they can select without changing whether
	 * the adapter is in monitor mode or not.
	 */
	/*p->oldstyle = 1;*/
	status = pcap_activate(p);
	if (status < 0)
		goto fail;
	return (p);
fail:
	/*if (status == PCAP_ERROR)
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %s", source,p->errbuf);
	else if (status == PCAP_ERROR_NO_SUCH_DEVICE || status == PCAP_ERROR_PERM_DENIED || status == PCAP_ERROR_PROMISC_PERM_DENIED)
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %s (%s)", source, pcap_statustostr(status), p->errbuf);
	else
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %s", source, pcap_statustostr(status));
	*/
    printf("ERROR pcap_open_live_wifi %d\n",status);
	pcap_close(p);
	return (NULL);
}
