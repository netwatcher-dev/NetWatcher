#include <stdio.h> /*printf, fprintf*/
#include <stdlib.h> /*exit*/

#include <strings.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdint.h>
#include <netinet/ip.h> /*struct ip*/

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



#define TAB_SIZE 2000

int main(int argc, char *argv[])
{
    uint8_t tab[TAB_SIZE];
    
    int client_socket, port, count = 1;
    struct sockaddr_in server_address;
    sniff_ip * header_ip;
    sniff_tcp * header_tcp;
    
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
        header_ip = (sniff_ip*)tab;
        
        printf("%d : ip.size : %d, ip_len : %u, ip.src :  %s", count,IP4_HL(header_ip), ntohs(header_ip->ip_len), inet_ntoa(header_ip->ip_src));
        printf(", ip.dst : %s, ",inet_ntoa(header_ip->ip_dst));
        
        port = ntohs(header_ip->ip_len)-20;/*4*IP4_HL(header_ip);*/
        
        if(port > (TAB_SIZE-20))
        {
            fprintf(stderr,"invalid ip header\n");
            return -1;
        }

        if(recv(client_socket,tab+20, port*sizeof(uint8_t), MSG_WAITALL) < 0)
        {
            perror("2eme read : ");
            return -1;
        }
        
        header_tcp = (sniff_tcp *)(tab + 4*IP4_HL(header_ip) );
        
        /*if(header_tcp->th_sum == 0)
        {*/
            printf(", tcp.src : %u, tcp.dst : %u, tcp.seq : %u, tcp.ack %u", ntohs(header_tcp->th_sport), ntohs(header_tcp->th_dport),ntohl(header_tcp->th_seq),ntohl(header_tcp->th_ack));
            printf(", tpc header size (word 32 bits) : %u, payload : %u\n",TH_OFF(header_tcp), htons(header_ip->ip_len) - 4*IP4_HL(header_ip) - TH_OFF(header_tcp)*4);
        /*}*/
        
        count++;
    }
    perror("1eme read : ");
    return -1;
    
}