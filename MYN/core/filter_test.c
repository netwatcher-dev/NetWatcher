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

#include <stdio.h> /*printf, fprintf*/
#include <stdlib.h> /*exit*/

#include <strings.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdint.h>
#include <netinet/ip.h> /*struct ip*/
#include <sys/time.h>

/*TODO faire une verif des sequences TCP*/

/* IP header V6 */
typedef struct 
{
		uint8_t ip_v_tc_fl[4];		/* version (4bits), traffic class (8bits), flow label (20bits) */
		uint16_t ip_len;		/* total length WHITOUT HEADER LENGTH !!!!! */
		uint8_t ip_p;		/* protocol (next header)*/
		uint8_t ip_hl;		/* hop limit */
		struct in6_addr ip_src,ip_dst; /* source and dest address */
} sniff_ip6;

typedef struct 
{
		uint8_t ip_vhl;		/* version << 4 | header length >> 2 */
		uint8_t ip_tos;		/* type of service */
		uint16_t ip_len;		/* total length */
		uint16_t ip_id;		/* identification */
		uint16_t ip_off;		/* fragment offset field */
		uint8_t ip_ttl;		/* time to live */
		uint8_t ip_p;		/* protocol */
		uint16_t ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst; /* source and dest address */
} sniff_ip;

#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */	
#define IP4_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP4_V(ip)		(((ip)->ip_vhl) >> 4)

#define IP_TYPE_TCP 0x06
#define IP_TYPE_UDP 0x11


typedef struct {
		uint16_t th_sport;	/* source port */
		uint16_t th_dport;	/* destination port */
		uint32_t th_seq;		/* sequence number */
		uint32_t th_ack;		/* acknowledgement number */

		uint8_t th_offx2;	/* data offset, rsvd */
	
		uint8_t th_flags;
		uint16_t th_win;		/* window */
		uint16_t th_sum;		/* checksum */
		uint16_t th_urp;		/* urgent pointer */
} sniff_tcp;

	/* UDP header */
typedef struct {
		uint16_t uh_sport;	/* source port */
		uint16_t uh_dport;	/* destination port */
		uint16_t uh_len;	/* source port */
		uint16_t uh_sum;	/* destination port */

} sniff_udp;

#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

#define TAB_SIZE 65535

void printIPV6(struct in6_addr * ip);
void printIpType(uint8_t type);
struct sequence_check * findOrCreateSeqEntry(uint8_t * ip_src, uint8_t * ip_dest,unsigned int ip_addr_size, uint32_t port_src, uint32_t port_dest);

int warning_count;

struct sequence_check
{
    unsigned int ip_ver;
    uint8_t key[40];
    uint32_t seq;
    struct sequence_check * next;
    int fin_count;
};

struct sequence_check * first_seq;

int main(int argc, char *argv[])
{
    uint8_t tab[TAB_SIZE];
    first_seq = NULL;
    
    int client_socket, port, count = 1, init = 1;
    struct sockaddr_in server_address;
    sniff_ip * header_ip;
    sniff_ip6 * header_ip6;
    sniff_tcp * header_tcp;
    sniff_udp * header_udp;
    struct timeval t, t_prec;
    long int diff_result;
    /*int IPV4_enabled = 0, IPV6_enabled = 0, TCP_enabled = 0, UDP_enabled = 0;*/
    unsigned int header_ip_size = 0;
    unsigned int ip_type, ip_addr_size, payload_ip_size;
    struct sequence_check * seq_check_tmp;
    
    warning_count = 0;
    
    if(argc < 3)
    {
        fprintf(stderr,"need at least 3 arg : SERVER_URL SERVER_PORT \n");
        return EXIT_FAILURE;
    }
    
    port = (int)strtol(argv[2],(char **)NULL,10);
    if(port == 0 || port <1 || port > 65532)
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
    
    while(  recv(client_socket,tab, 20*sizeof(uint8_t), MSG_WAITALL) > 0)
    {        
        if(init)
        {
            if(gettimeofday(&t_prec,NULL) != 0)
            {
                perror("failed to init ref time");
                return -1;
            }
            
            init = 0;
        }
        
        if(gettimeofday(&t,NULL) != 0)
        {
            perror("(delayedlib) WARNING failed to get time");
        }
        else
        {
            diff_result = t.tv_sec - t_prec.tv_sec;
            diff_result *= 1000000;
            diff_result += t.tv_usec - t_prec.tv_usec;
            /*printf("%ld.%ld\n",diff_result/1000000,diff_result%1000000);*/
            t_prec = t;
        }
        
        if( (tab[0] >> 4) == 4)
        {
            header_ip = (sniff_ip*)tab;

            printf("%d : ip.size : %d, ip_len : %u, ip.src :  %s", count,IP4_HL(header_ip), ntohs(header_ip->ip_len), inet_ntoa(header_ip->ip_src));
            printf(", ip.dst : %s\n",inet_ntoa(header_ip->ip_dst));
            ip_type = header_ip->ip_p;
            port = ntohs(header_ip->ip_len)-20;/*4*IP4_HL(header_ip);*/ 
            header_ip_size = 4*IP4_HL(header_ip); 
            payload_ip_size = htons(header_ip->ip_len) - 4*IP4_HL(header_ip);
            ip_addr_size = 4;
        }
        else if((tab[0] >> 4) == 6)
        {
            header_ip6 = (sniff_ip6*)tab;
            ip_type = header_ip6->ip_p;
            port = ntohs(header_ip6->ip_len)+20;
            header_ip_size = 40;
            payload_ip_size = htons(header_ip6->ip_len);
            
            ip_addr_size = 16;
        }
        else
        {
            fprintf(stderr,"INVALID IP VERSION : %u\n",(tab[0] >> 4));
            return -1;
        }
        
        if( port > (TAB_SIZE-20))
        {
            fprintf(stderr,"ip4/6 : the buffer is too short : %u vs %u\n",port+20,TAB_SIZE-20);
            return -1;
        }

        if(recv(client_socket,tab+20, port*sizeof(uint8_t), MSG_WAITALL) < 0)
        {
            perror("2eme read : ");
            return -1;
        }
        
        if((tab[0] >> 4) == 6)
        {
            /*print ipv6*/
            printf("%u : ip.size : 10 : ip_len : %d, ip.src : ",count,ntohs(header_ip6->ip_len));
            printIPV6(&header_ip6->ip_src);
            printf(", ip.dst : ");
            printIPV6(&header_ip6->ip_dst);
            printf("\n");
        }
        
        printf("\t");printIpType(ip_type);
        
        if(ip_type == 0x06)/*TCP*/
        {
            header_tcp = (sniff_tcp *)(tab + header_ip_size );
            printf(" : tcp.src : %u, tcp.dst : %u, tcp.seq : %u, tcp.ack %u", ntohs(header_tcp->th_sport), ntohs(header_tcp->th_dport),ntohl(header_tcp->th_seq),ntohl(header_tcp->th_ack));
            printf(", tpc.hsize : %u, payload : %u",TH_OFF(header_tcp), payload_ip_size - TH_OFF(header_tcp)*4);
            printf(", FIN(%d),SYN(%d),RST(%d),PUSH(%d),ACK(%d),URG(%d),ECE(%d),CWR(%d)",(header_tcp->th_flags&TH_FIN)?1:0,(header_tcp->th_flags&TH_SYN)?1:0,(header_tcp->th_flags&TH_RST)?1:0,(header_tcp->th_flags&TH_PUSH)?1:0,(header_tcp->th_flags&TH_ACK)?1:0,(header_tcp->th_flags&TH_URG)?1:0,(header_tcp->th_flags&TH_ECE)?1:0,(header_tcp->th_flags&TH_CWR)?1:0 );
            
            if(header_tcp->th_sum == 0)
            {
                printf(" FORGED");
            }
            printf("\n");
            
            if(ip_addr_size == 4)
            {
                seq_check_tmp = findOrCreateSeqEntry((uint8_t *) &header_ip->ip_src,(uint8_t *) &header_ip->ip_dst,ip_addr_size,header_tcp->th_sport,header_tcp->th_dport);
            }
            else
            {
                seq_check_tmp = findOrCreateSeqEntry(header_ip6->ip_src.s6_addr,header_ip6->ip_dst.s6_addr,ip_addr_size,header_tcp->th_sport,header_tcp->th_dport);
            }
            
            if(seq_check_tmp == NULL)
            {
                perror("findOrCreateSeqEntry failed : ");
                return -1;
            }
            
            if(seq_check_tmp->seq == 0) 
            {
                printf("NEW SEQ\n");
            }
            else
            {
                if(seq_check_tmp->fin_count > 0)
                {
                    printf("CLOSED STREAM\n");
                }
                else if(seq_check_tmp->seq != ntohl(header_tcp->th_seq))
                {
                    printf("WARNING (%d) : BAD SEQ %u(waited) vs %u(received)\n",warning_count++,seq_check_tmp->seq,ntohl(header_tcp->th_seq));
                    return -1;
                }
                else
                {
                    printf("GOOD SEQ\n");
                }
            }
            
            if((header_tcp->th_flags & TH_SYN) /*|| (header_tcp->th_flags & TH_FIN)*/)
            {
                seq_check_tmp->seq = 1 + ntohl(header_tcp->th_seq) + (payload_ip_size - TH_OFF(header_tcp)*4);
                
                /*if((header_tcp->th_flags & TH_FIN))
                {
                    seq_check_tmp->fin_count += 1;
                }*/
            }
            else if((header_tcp->th_flags & TH_FIN))
            {
                seq_check_tmp->fin_count += 1;
            }
            else
            {
                seq_check_tmp->seq = ntohl(header_tcp->th_seq) + (payload_ip_size - TH_OFF(header_tcp)*4);
            }
            
        }
        else if(ip_type == 0x11)
        {
            header_udp = (sniff_udp*)(tab + header_ip_size );
            printf(" : udp.src : %u, udp.dst : %u, udp.length : %u\n", ntohs(header_udp->uh_sport), ntohs(header_udp->uh_dport),ntohs(header_udp->uh_len));
        }
        else
        {
            printf("\n");
        }

        count++;
    }
    perror("1eme read : ");
    return -1;
    
}

void printIpType(uint8_t type)
{
    switch(type)
    {
        case 0x00 : printf("HOPOPT"); break;
        case 0x01 : printf("ICMP"); break;
        case 0x02 : printf("IGMP"); break;
        case 0x03 : printf("GGP"); break;
        case 0x04 : printf("IP"); break;
        case 0x05 : printf("ST"); break;
        case 0x06 : printf("TCP"); break;
        case 0x07 : printf("CBT"); break;
        case 0x08 : printf("EGP"); break;
        case 0x09 : printf("IGP"); break;
        case 0x0A : printf("BBN-RCC-MON"); break;
        case 0x0B : printf("NVP-II"); break;
        case 0x0C : printf("PUP"); break;
        case 0x0D : printf("ARGUS"); break;
        case 0x0E : printf("EMCON"); break;
        case 0x0F : printf("XNET"); break;
        case 0x10 : printf("CHAOS"); break;
        case 0x11 : printf("UDP"); break;
        case 0x12 : printf("MUX"); break;
        case 0x13 : printf("DCN-MEAS"); break;
        case 0x14 : printf("HMP"); break;
        case 0x15 : printf("PRM"); break;
        case 0x16 : printf("XNS-IDP"); break;
        case 0x17 : printf("TRUNK-1"); break;
        case 0x18 : printf("TRUNK-2"); break;
        case 0x19 : printf("LEAF-1"); break;
        case 0x1A : printf("LEAF-2"); break;
        case 0x1B : printf("RDP"); break;
        case 0x1C : printf("IRTP"); break;
        case 0x1D : printf("ISO-TP4"); break;
        case 0x1E : printf("NETBLT"); break;
        case 0x1F : printf("MFE-NSP"); break;
        case 0x20 : printf("MERIT-INP"); break;
        case 0x21 : printf("DCCP"); break;
        case 0x22 : printf("3PC"); break;
        case 0x23 : printf("IDPR"); break;
        case 0x24 : printf("XTP"); break;
        case 0x25 : printf("DDP"); break;
        case 0x26 : printf("IDPR-CMTP"); break;
        case 0x27 : printf("TP++"); break;
        case 0x28 : printf("IL"); break;
        case 0x29 : printf("IPv6"); break;
        case 0x2A : printf("SDRP"); break;
        case 0x2B : printf("IPv6-Route"); break;
        case 0x2C : printf("IPv6-Frag"); break;
        case 0x2D : printf("IDRP"); break;
        case 0x2E : printf("RSVP"); break;
        case 0x2F : printf("GRE"); break;
        case 0x30 : printf("MHRP"); break;
        case 0x31 : printf("BNA"); break;
        case 0x32 : printf("ESP"); break;
        case 0x33 : printf("AH"); break;
        case 0x34 : printf("I-NLSP"); break;
        case 0x35 : printf("SWIPE"); break;
        case 0x36 : printf("NARP"); break;
        case 0x37 : printf("MOBILE"); break;
        case 0x38 : printf("TLSP"); break;
        case 0x39 : printf("SKIP"); break;
        case 0x3A : printf("IPv6-ICMP"); break;
        case 0x3B : printf("IPv6-NoNxt"); break;
        case 0x3C : printf("IPv6-Opts"); break;
        case 0x3D : printf("Any host internal protocol"); break;
        case 0x3E : printf("CFTP"); break;
        case 0x3F : printf("Any local network"); break;
        case 0x40 : printf("SAT-EXPAK"); break;
        case 0x41 : printf("KRYPTOLAN"); break;
        case 0x42 : printf("RVD"); break;
        case 0x43 : printf("IPPC"); break;
        case 0x44 : printf("Any distributed file system"); break;
        case 0x45 : printf("SAT-MON"); break;
        case 0x46 : printf("VISA"); break;
        case 0x47 : printf("IPCV"); break;
        case 0x48 : printf("CPNX"); break;
        case 0x49 : printf("CPHB"); break;
        case 0x4A : printf("WSN"); break;
        case 0x4B : printf("PVP"); break;
        case 0x4C : printf("BR-SAT-MON"); break;
        case 0x4D : printf("SUN-ND"); break;
        case 0x4E : printf("WB-MON"); break;
        case 0x4F : printf("WB-EXPAK"); break;
        case 0x50 : printf("ISO-IP"); break;
        case 0x51 : printf("VMTP"); break;
        case 0x52 : printf("SECURE-VMTP"); break;
        case 0x53 : printf("VINES"); break;
        case 0x54 : printf("TTP or IPTM"); break;
        case 0x55 : printf("NSFNET-IGP"); break;
        case 0x56 : printf("DGP"); break;
        case 0x57 : printf("TCF"); break;
        case 0x58 : printf("EIGRP"); break;
        case 0x59 : printf("OSPF"); break;
        case 0x5A : printf("Sprite-RPC"); break;
        case 0x5B : printf("LARP"); break;
        case 0x5C : printf("MTP"); break;
        case 0x5D : printf("AX.25"); break;
        case 0x5E : printf("IPIP"); break;
        case 0x5F : printf("MICP"); break;
        case 0x60 : printf("SCC-SP"); break;
        case 0x61 : printf("ETHERIP"); break;
        case 0x62 : printf("ENCAP"); break;
        case 0x63 : printf("Any private encryption scheme"); break;
        case 0x64 : printf("GMTP"); break;
        case 0x65 : printf("IFMP"); break;
        case 0x66 : printf("PNNI"); break;
        case 0x67 : printf("PIM"); break;
        case 0x68 : printf("ARIS"); break;
        case 0x69 : printf("SCPS"); break;
        case 0x6A : printf("QNX"); break;
        case 0x6B : printf("A/N"); break;
        case 0x6C : printf("IPComp"); break;
        case 0x6D : printf("SNP"); break;
        case 0x6E : printf("Compaq-Peer"); break;
        case 0x6F : printf("IPX-in-IP"); break;
        case 0x70 : printf("VRRP"); break;
        case 0x71 : printf("PGM"); break;
        case 0x72 : printf("Any 0-hop protocol"); break;
        case 0x73 : printf("L2TP"); break;
        case 0x74 : printf("DDX"); break;
        case 0x75 : printf("IATP"); break;
        case 0x76 : printf("STP"); break;
        case 0x77 : printf("SRP"); break;
        case 0x78 : printf("UTI"); break;
        case 0x79 : printf("SMP"); break;
        case 0x7A : printf("SM"); break;
        case 0x7B : printf("PTP"); break;
        case 0x7C : printf("IS-IS over IPv4"); break;
        case 0x7D : printf("FIRE"); break;
        case 0x7E : printf("CRTP"); break;
        case 0x7F : printf("CRUDP"); break;
        case 0x80 : printf("SSCOPMCE"); break;
        case 0x81 : printf("IPLT"); break;
        case 0x82 : printf("SPS"); break;
        case 0x83 : printf("PIPE"); break;
        case 0x84 : printf("SCTP"); break;
        case 0x85 : printf("FC"); break;
        case 0x86 : printf("RSVP-E2E-IGNORE"); break;
        case 0x87 : printf("Mobility Header"); break;
        case 0x88 : printf("UDP Lite"); break;
        case 0x89 : printf("MPLS-in-IP"); break;
        case 0x8A : printf("manet"); break;
        case 0x8B : printf("HIP"); break;
        case 0x8C : printf("Shim6"); break;
        case 0xFF : printf("Reserved"); break;
        default : 
            if(0x8D <= type && type <= 0xFC)
            {
                printf("unassigned");
            }
            else if(0xFD <= type && type <= 0xFE)
            {
                printf("Use for experimentation and testing");
            }
            else
            {
                printf("unknwon ip protocol");
            }
    }
}

void printIPV6(struct in6_addr * ip)
{
    printf("%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x"
        ,ip->s6_addr[0],ip->s6_addr[1],ip->s6_addr[2],ip->s6_addr[3],ip->s6_addr[4],ip->s6_addr[5],ip->s6_addr[6],ip->s6_addr[7],ip->s6_addr[8],ip->s6_addr[9],ip->s6_addr[10],ip->s6_addr[11],ip->s6_addr[12],ip->s6_addr[13],ip->s6_addr[14],ip->s6_addr[15]);  
}

struct sequence_check * findOrCreateSeqEntry(uint8_t * ip_src, uint8_t * ip_dest,unsigned int ip_addr_size, uint32_t port_src, uint32_t port_dest)
{
    struct sequence_check * tmp;
    //int i;
    tmp = first_seq;
    
    while(tmp != NULL)
    {
        /*printf("%u vs %u, ",tmp->ip_ver,ip_addr_size);
        
        for( i = 0;i<ip_addr_size;i++)
        {
            printf("%.2x",tmp->key[i]);
        }
        
        printf(" vs ");
        
        for( i = 0;i<ip_addr_size;i++)
        {
            printf("%.2x",ip_src[i]);
        }
        
        printf(", ");
        
        for( i = 0;i<ip_addr_size;i++)
        {
            printf("%.2x",tmp->key[16+i]);
        }
        
        printf(" vs ");
        
        for( i = 0;i<ip_addr_size;i++)
        {
            printf("%.2x",ip_dest[i]);
        }
        
        printf(", %u vs %u",*((uint32_t *)&tmp->key[32]),port_src);
        printf(", %u vs %u\n",*((uint32_t *)&tmp->key[36]),port_dest);*/
        
        if(tmp->ip_ver == ip_addr_size
        && bcmp(tmp->key,ip_src,ip_addr_size) == 0 
        && bcmp(&tmp->key[16],ip_dest,ip_addr_size) == 0
        && *((uint32_t *)&tmp->key[32]) == port_src
        && *((uint32_t *)&tmp->key[36]) == port_dest)
        {
            //printf("\n\nFIND\n\n");
            return tmp;
        }
        
        tmp = tmp->next;
    }
    
    if( (tmp = malloc(sizeof(struct sequence_check)) ) == NULL )
    {
        return NULL;
    }
    
    bcopy(ip_src, tmp->key,ip_addr_size);
    bcopy(ip_dest, &tmp->key[16],ip_addr_size) ;
    *((uint32_t *)&tmp->key[32]) = port_src;
    *((uint32_t *)&tmp->key[36]) = port_dest;
    
    tmp->fin_count = 0;
    tmp->ip_ver = ip_addr_size;
    tmp->seq = 0;
    tmp->next = first_seq;
    first_seq = tmp;
    
    return tmp;
}



