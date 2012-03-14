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

#include "./structlib/structlib.h"
#ifndef NO_RESEQ
#include "./segmentlib/segmentlib.h"
#endif
#include "./capturefilterlib/capturefilterlib.h"
#include "./collectorlib/collectorlib.h"
#include "./sharedmemorylib/sharedmemorylib.h"
#include "command.h"
#include "core_type.h"

#define ACT_STOP       0
#define ACT_START      1
#define ACT_PARSE      2
#define ACT_HANDLE_SIGNAL 4

#define STATE_NOTHING   0
#define STATE_RUNNING   1
#define STATE_RECORDING 2
#define STATE_FILE      4
#define STATE_STREAM    8
#define STATE_PARSING   16

/*##################### FUNCTIONS PROTOTYPE ####################*/
int setDatalink(int type_link);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void haltpcap();
void handler(int sig);
int manage_command(mymemory *  mem);
void stopRecording();

/*##################### TCP RESEQ global vars ####################*/
sequence_entry * seq_start = NULL;
sequence_entry * seq_last = NULL;

/*##################### PCAP vars ####################*/
pcap_t * descr; /*pcap descriptor*/
pcap_dumper_t * dumper_descr; /*pcap descripto to output packet to a file*/
char errbuf[PCAP_ERRBUF_SIZE]; /*pcap error buffer*/

/*##################### 2nd FILTER LAYER vars ####################*/
struct master_filter master_filter;

/*##################### WORKING vars ####################*/
datalink_info link_info;
int speed, act, state; /*control/state variable*/
int to_collector; /*communication pipe*/
struct ifaddrs *ifp;

#ifdef DEBUG_MEMORY_SEG
int count_entry, cont_buffer;
#endif

int main(int argc, char *argv[])
{
    int i, shmDesc, semDesc;
    sigset_t ens;
    struct sigaction action;
    mymemory *  mem; /*shared memory*/
    
    descr = NULL;
    dumper_descr = NULL;
    ifp = NULL;
    state = 0;
    act = 0;

    initFilter();

    printf("(dispatch) start\n");

    if(argc != 4)
    {
        fprintf(stderr,"(dispatch) argument count must be 4, get %d\n",argc);
        return EXIT_FAILURE;
    }
    
    /*arg0 = prgr_name, arg1 = from_control, arg2 = to_control, arg3 = to_collector*/
    for(i = 0; i < argc;i++)
    {
        printf("(dispatch) arg %d : %s\n",i,argv[i]);
    }
    
    shmDesc = strtol(argv[1],NULL,10);
    if( errno == ERANGE)
    {
        perror("(dispatch) failed to convert pipe id from_control : ");
        return EXIT_FAILURE;
    }
    
    semDesc = strtol(argv[2],NULL,10);
    if( errno == ERANGE)
    {
        perror("(dispatch) failed to convert pipe id to_control : ");
        return EXIT_FAILURE;
    }
    
    to_collector = strtol(argv[3],NULL,10);
    if(errno == ERANGE)
    {
        perror("(dispatch) failed to convert pipe id to_collector : ");
        return EXIT_FAILURE;
    }
    
    if( (mem = createMemory(shmDesc,3,semDesc,0)) == NULL)
    {
        fprintf(stderr,"(dispatch) failed to create shared memory\n");
        return EXIT_FAILURE;
    }
    
    /*on debloque le signal qui nous interesse*/
    sigemptyset(&ens);
    sigaddset(&ens,SIGUSR1);
    sigprocmask(SIG_UNBLOCK, &ens, NULL); 
    
    /*on definit le handler*/
    action.sa_flags = 0;
    action.sa_handler=handler;
    sigemptyset(&action.sa_mask);
    sigaddset(&action.sa_mask,SIGUSR1); /*on bloque le SIGIO pendant sa reception*/
    sigaction(SIGUSR1,&action,(struct sigaction *)0);
    
    /*on prepare l'ensemble pour le suspend*/
    sigemptyset(&ens);

    while(1)
    {
        if(act == ACT_STOP) /*si rien a faire, on attend un signal*/
        {
            printf("(dispatch) wait for an order... \n");
            sigsuspend(&ens);
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
            
        }
        
        if(act & ACT_START)
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
            switch(pcap_loop(descr, -1, got_packet, NULL))
            {   
                case -2: /*pcap_breakloop case*/
                    printf("pcap_loop : pcap_breakloop case\n");
                    act |= ACT_START;
                    break;
                case -1: /*error case*/
                    pcap_perror(descr,"(dispatch) pcap_loop : error case :");
                default:
                    printf("pcap_loop : error case\n");
                    act = ACT_STOP;/*on stop*/
            }
        }
        else if(act & ACT_PARSE)
        {
            /*TODO pour l'instant pareil que start*/
            printf("(dispatch) start to parse file\n");
            switch(pcap_loop(descr, -1, got_packet, NULL))
            {   
                case 0:
                    printf("(dispatch) end of file\n");
                    haltpcap();
                    act = ACT_STOP;
                    break;
                case -2: /*pcap_breakloop case*/
                    printf("pcap_loop : pcap_breakloop case\n");
                    act |= ACT_PARSE;
                    break;
                case -1: /*error case*/
                    pcap_perror(descr,"(dispatch) pcap_loop : error case :");
                default:
                    haltpcap();/*pas encore trouve de moyen pour reset la ressource, elle est inutilisable, autant la stopper*/
                    /*TODO recreer la ressource*/
                    act = ACT_STOP;/*on stop*/
            }
        }
        else
        {
            act = ACT_STOP;/*on stop*/
        }
    }
    
    printf("(dispatch) exit\n");
    return 0;
}

void handler(int sig)
{
    printf("(dispatch) receiving signal\n");
    if(sig == SIGUSR1)/*est ce bien le signal qui nous interesse */
    {
        act |= ACT_HANDLE_SIGNAL;
        if((state & STATE_RUNNING) && descr != NULL)/*on est en train de dispatcher, il faut interrompre*/
        {
            pcap_breakloop(descr); /*on brise la boucle s'il y en a une*/
        }
    }
}

int manage_command(mymemory *  mem)
{
    int to_send = STATE_NO_ERROR, size, pipes[2], i;
    char * buffer, arg1[10], arg2[10];
    struct bpf_program filter;
    uint16 id;
    struct sockaddr_in sockaddr_server;
    
    printf("(dispatch) manage command\n");
    
    /*TODO verifier la taille des arguments en fonction de l'action*/
    switch(getAction(mem))
    {
    /*####################################################################################################################*/
        case COMMAND_SELECT_CAPTURE_DEVICE:
        
            if(getAreaMemory(mem, 0,(void **) &buffer, &size) < 0)
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
            
            if( (descr = pcap_open_live(buffer, MAXBYTES2CAPTURE, 1, 512, errbuf)) == NULL)
            {
                fprintf(stderr,"(dispatch) pcap_open_live : %s\n",errbuf);
                to_send = STATE_PCAP_ERROR; break;
            }

            if(setDatalink(pcap_datalink(descr)) < 0)
            {
                fprintf(stderr,"(dispatch) datalink type not supported  : %s\n",pcap_datalink_val_to_name(pcap_datalink(descr)));
                to_send = STATE_DATALINK_NOT_MANAGED;break;
            }
            
            state |= STATE_STREAM;
            state |= STATE_RUNNING;
            act  = ACT_START;
            
            break;
    /*####################################################################################################################*/
        case COMMAND_SELECT_CAPTURE_FILE:
            if(getAreaMemory(mem, 0,(void **) &buffer, &size) < 0)
            {
                fprintf(stderr,"(dispatch) manage_command, argument 0 is wrong or missing\n");
                to_send = STATE_ARG_WRONG_OR_MISSING; break;
            }
        
            printf("(dispatch) select capture file : <%s>\n", buffer);
            if(descr != NULL)
            {
                to_send = STATE_MUST_STOP_CAPTURE_BEFORE;break;
            }
            
            if( (descr = pcap_open_offline(buffer,errbuf)) == NULL)
            {
                fprintf(stderr,"(dispatch) pcap_open_offline : %s\n",errbuf);
                to_send = STATE_PCAP_ERROR;break;
            }
            
            if(setDatalink(pcap_datalink(descr)) < 0)
            {
                fprintf(stderr,"(dispatch) datalink type not supported  : %s\n",pcap_datalink_val_to_name(pcap_datalink(descr)));
                to_send = STATE_DATALINK_NOT_MANAGED;break;
            }
            
            state |= STATE_FILE;
            
            break;
    /*####################################################################################################################*/
        case COMMAND_SET_MASTER_FILTER:
                if(descr == NULL)
                {
                    fprintf(stderr,"(dispatch) pcap descriptor is NULL\n");
                    to_send = STATE_NOTHING_SELECTED; break;
                }
                
                if(getAreaMemory(mem, 0,(void **) &buffer, &size) < 0)
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
            haltpcap();
            act = ACT_STOP; /*on remet a zero*/
            
            /*stop recording*/
            stopRecording();
            
            break;
    /*####################################################################################################################*/
        case COMMAND_SET_SPEED:
            if(getAreaMemory(mem, 0,(void **) &buffer, &size) < 0)
            {
                fprintf(stderr,"(dispatch) manage_command, argument 0 is wrong or missing\n");
                to_send = STATE_ARG_WRONG_OR_MISSING; break;
            }
            
            printf("(dispatch) set speed\n");
            speed = buffer[0];
            
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
            
            act = ACT_PARSE;
            state |= STATE_RUNNING;
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

            /*recuperation du filtre bpf en provenance de la memoire partagée*/
            if(getAreaMemory(mem, 0,(void **) &buffer, &size) < 0)
            {
                fprintf(stderr,"(dispatch) manage_command, argument 0 is wrong or missing\n");
                to_send = STATE_ARG_WRONG_OR_MISSING; break;
            }

            /*ouverture du pipe de communication entre le dispatch et le wait*/
            if(pipe(pipes) < 0)
            {
                perror("(dispatch) manage_command, failed to open pipe");
                to_send = STATE_SERVER_ERROR; break;
            }
            
            if((size = socket(PF_INET,SOCK_STREAM,0)) < 0 )
            {
                perror("(dispatch) manage_command, failed to create socket");
                to_send = STATE_SERVER_ERROR; break;
            }
            
            /*ouverture du socket de communication du wait*/
            for(id = WAIT_START_PORT;id<WAIT_START_PORT+WAIT_MAX_PORT;id++)
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
                    close(pipes[0]);
                    close(pipes[1]);
                    close(size);
                    to_send = STATE_SERVER_ERROR; goto break_mark;
                }
                break;
            }
            
            if(id == WAIT_START_PORT+WAIT_MAX_PORT)
            {
                to_send = STATE_NO_MORE_PORT_AVAILABLE; break;
            }

            /*add a capture struct in the list*/
            addFilter(buffer,id,pipes[1]);/*TODO test if fail*/
            
            /*start client manager*/
            i = fork();
            if(i == 0)
            {/*fils*/
                close(pipes[1]);/*close write*/
                printf("CHILD !!! \n");
                sprintf(arg1,"%d",size);
                sprintf(arg2,"%d",pipes[0]);
                
                if( execlp("./wait","wait", arg1, arg2, (char *)0) < 0)
                {
                    perror("(dispatch) manage_command,failed to execlp wait");
                    exit(EXIT_FAILURE);
                }
            }
            else if(i < 0)
            {/*erreur*/
                perror("(dispatch) manage_command,failed to fork");
                close(pipes[0]);
                close(pipes[1]);
                close(size);
                to_send = STATE_SERVER_ERROR;
                break;
            }
            else
            {/*pere*/
                close(pipes[0]); /*close read*/
                close(size); /*close the server socket*/
            }
            
            /*ecrire le port dans la memoire*/
            cleanAreaMemories(mem);
            
            if( (buffer = getNextAvailableAreaMemory(mem, sizeof(id))) == NULL)
            {
                fprintf(stderr,"(dispatch) manage_command, failed to allocate memory area on shared memory\n");
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
            
            ((uint8*)(&id))[0] = buffer[0];
            ((uint8*)(&id))[1] = buffer[1];
            /*((char*)(&id))[2] = buffer[2];
            ((char*)(&id))[3] = buffer[3];*/
            
            printf("(dispatch) id to remove : %u\n",id);
            
            if(removeFilter(id)!=0)
            {
                state = STATE_SERVER_ERROR;
            }

            break;
    /*####################################################################################################################*/
        case COMMAND_STOP_ALL_CAPTURE:
            printf("(dispatch) stop all capture\n");

            removeAllFilter();

            break;
    /*####################################################################################################################*/
        /*
         * RECORD MANAGER
         */    
        case COMMAND_START_RECORD:
        
            if(getAreaMemory(mem, 0,(void **) &buffer, &size) < 0)
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
                fprintf(stderr,"(dispatch) pcap_setfilter : %s\n",pcap_geterr(descr));
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
	char ip_version; /* IPv4 or IPv6 */
    unsigned int ip_header_size;
    int local;
    
    
    sniff_ethernet * ethernet;/*TODO manager other datalink type*/
    sniff_tcp *tcp; 
	sniff_udp *udp;
    sniff_ip *ip;
	sniff_ip6 *ip6;
    collector_entry header_to_send;
    
#ifndef NO_RESEQ
    sequence_entry * seq_entry;
    next_buffer * buff_tmp;
    uint8 * tmp;
#endif

#ifdef PRINT_PCAP
    char char_time[26];
#endif
    
    #ifdef DEBUG_MEMORY_SEG
    printf("memory, entry:%d, buffer:%d\n",count_entry, cont_buffer);
    #endif
    
    /*RESET BUFFER*/
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
    printf("Received packet size : %d, ",pkthdr->len);
    ctime_r(&pkthdr->ts.tv_sec,char_time);
    char_time[24] = '\0';
    printf("time : %s, %u (microsecs)\n",char_time, pkthdr->ts.tv_usec);
#endif

    ethernet = (sniff_ethernet*)(packet);
    if(checkETHERNET(ethernet, packet, pkthdr->len)) 
        return;
          
    /*check ethernet type*/
    if(ntohs(ethernet->ether_type) != ETHERNET_TYPE_IP && ntohs(ethernet->ether_type) != ETHERNET_TYPE_IP6)
    {
        #if defined(PRINT_ETHERNET) || defined(PRINT_DROP)
        printf("not an ip(v4/v6) packet %.4x : drop\n", ntohs(ethernet->ether_type));
        #endif
        
        return;
    }
    
    /*IP version*/
    ip_version = packet[link_info.header_size]>>4;

    /* COLLECTOR */
    bzero(header_to_send.sip,sizeof(uint8)*16);
    bzero(header_to_send.dip,sizeof(uint8)*16);
    header_to_send.status = 0;

	/* IPv4 */
	if(ip_version == 4)
	{
		ip = (sniff_ip*)(packet + link_info.header_size);
	    ip_header_size = IP4_HL(ip)*4;
	    if( (local = checkIPV4(ip, packet, pkthdr->len, ifp)) < 0)
	    {
	        return;
	    }
	
		/* TCP */
		if(ip->ip_p == IP_TYPE_TCP)
		{
			tcp = (sniff_tcp*)(packet + link_info.header_size + ip_header_size);
		    if(checkTCP(tcp, packet, pkthdr->len, ip,local) < 0)
		    {
		        return;
		    }
            /* COLLECTOR */
            header_to_send.sport = tcp->th_sport;
            header_to_send.dport = tcp->th_dport;
            header_to_send.status = tcp->th_flags;
		} 
		/* UDP */
		else if (ip->ip_p == IP_TYPE_UDP)
		{
			udp = (sniff_udp*)(packet+ link_info.header_size + ip_header_size);
			if(checkUDP(ip, (uint16*)packet,local) < 0)
		    {
				printf("(dispatch) UDP Checksum invalid!\n");
		        return;
		    }

            /* COLLECTOR */
            header_to_send.sport = udp->uh_sport;
            header_to_send.dport = udp->uh_dport;
		}
		else
		{
		     #if defined(PRINT_IP) || defined(PRINT_DROP)
			 printf("(dispatch) ipv4 : not a tcp or udp segment %x : drop\n",ip->ip_p);
			 #endif
			 
		     return;
		}
		sendToAllNode(packet,link_info.header_size+ntohs(ip->ip_len));
        /* COLLECTOR */
        header_to_send.protocol = ip->ip_p;
        memcpy(header_to_send.sip, &ip->ip_src.s_addr, sizeof(ip->ip_src.s_addr));
        memcpy(header_to_send.dip, &ip->ip_dst.s_addr, sizeof(ip->ip_dst.s_addr));
	}
	/* IPv6 */
	else if(ip_version == 6)
	{
		ip6 = (sniff_ip6*)(packet + link_info.header_size);
		ip_header_size = HL_IP6; /* Fixed */
		
		if(ip6->ip_p != IP_TYPE_TCP && ip6->ip_p != IP_TYPE_UDP)
	    {
	        #if defined(PRINT_IP) || defined(PRINT_DROP)
	        printf("(dispatch) ipv6 : not a tcp or udp segment %x : drop\n",ip6->ip_p); 
	        #endif
	        
	        return;
	    }
	    
	    /*TODO verifier la taille du paquet*/
	    
	    /*TODO adapter checkTCP & UDP pour de l'IPv6*/
	    sendToAllNode(packet,link_info.header_size+ip_header_size+ntohs(ip6->ip_len));
	}
	/*else
	{
		printf("Not IPv4 or IPv6 \n");
		return;other, forward
	}*/
	
	/* COLLECTOR */  
    header_to_send.epoch_time = pkthdr->ts.tv_sec;  /* Epoch time */
    write(to_collector,&header_to_send,sizeof(header_to_send));

    
#ifndef NO_RESEQ /*resequençage TCP*/
    if(ip->ip_p == IP_TYPE_TCP && (seq_entry = getEntry(ip->ip_src.s_addr,ip->ip_dst.s_addr,ntohs(tcp->th_sport),ntohs(tcp->th_dport))) != NULL)
    {      
        while(seq_entry->linked_buffer != NULL && seq_entry->linked_buffer->seq <= seq_entry->seq)
        {
            if(seq_entry->linked_buffer->seq + seq_entry->linked_buffer->dsize-1 > seq_entry->seq)
            {
                /*forge segment*/
                tmp = forgeSegment(seq_entry, seq_entry->linked_buffer,link_info.header_size);
                ip = (sniff_ip*)(tmp + link_info.header_size);
                
                #ifdef PRINT_TCP
                printf("\nSEND forged packet\n");
                #endif
                #ifdef PRINT_IP
                    printf("(dispatch f) : ip.size : %d, ip_len : %d, ip.src :  %s",IP4_HL(ip), ntohs(ip->ip_len), inet_ntoa(ip->ip_src));
                    printf(", ip.dst : %s, ip.ip_len %u\n",inet_ntoa(ip->ip_dst), ntohs(ip->ip_len));
                #endif
                
                tcp = (sniff_tcp*)(tmp + link_info.header_size + 20);
                #ifdef PRINT_TCP
                    printf("tcp.src : %u, tcp.dst : %u, tcp.seq : %u, tcp.ack %u", ntohs(tcp->th_sport), ntohs(tcp->th_dport),ntohl(tcp->th_seq),ntohl(tcp->th_ack));
                    printf(", tpc header size (word 32 bits) : %u, payload : %u\n",TH_OFF(tcp), htons(ip->ip_len) - 20 - TH_OFF(tcp)*4);
                #endif
                
                /*send segment*/
                sendToAllNode(tmp,ntohs(ip->ip_len)+link_info.header_size);
                free(tmp);
                
                /*on met a jour le prochain numero de sequence attendu*/
                seq_entry->seq = seq_entry->linked_buffer->seq + seq_entry->linked_buffer->dsize;     
            }
            #ifdef PRINT_TCP
            printf("old seq : %u new seq =  %u + %u \n",seq_entry->seq,seq_entry->linked_buffer->seq,seq_entry->linked_buffer->dsize );
            #endif

            /*on retire le buffer qu'on vient d'utiliser de la liste*/
            buff_tmp = seq_entry->linked_buffer;
            seq_entry->linked_buffer = seq_entry->linked_buffer->next_buffer;
            seq_entry->count--;
            
            /*free le buffer*/
            free(buff_tmp->data);
            free(buff_tmp);
            #ifdef DEBUG_MEMORY_SEG
            cont_buffer--;
            #endif
            
            /*set NULL previous on new first buffer*/
            if(seq_entry->linked_buffer != NULL)
            {
                seq_entry->linked_buffer->previous_buffer = NULL;
            }
        }
        
        /*suppression en cas de fin de flux*/
        if( tcp->th_flags&TH_FIN )
        {
            if(seq_entry->linked_buffer == NULL)
            {
                removeEntry(seq_entry);
            }
            else
            {
                seq_entry->flags |= SEG_FLAGS_END;
            }
        }
        else if(seq_entry->flags & SEG_FLAGS_END && seq_entry->linked_buffer == NULL)
        {
            removeEntry(seq_entry);
        }
        
    }
#endif
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
    switch(type_link)
    {
        case DLT_EN10MB : 
            link_info.header_size = 14;
            link_info.frame_max_size = 1500;
            return 14;  /* Ethernet */
        default: return -1;
    }
    return 0;
}
