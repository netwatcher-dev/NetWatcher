#ifndef _STRUCTLIB_H
#define _STRUCTLIB_H

#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h> /*struct ip*/
#include <arpa/inet.h>
#include <strings.h>
#include <string.h>
#include <ifaddrs.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>

#include "../core_type.h"
#include "../segmentlib/segmentlib.h"
/*#include "../capturefilterlib/capturefilterlib.h"*/

#define HL_IP6 40
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

extern datalink_info link_info;

	/* Ethernet header */
typedef struct  
{
		uint8  ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		uint8  ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		uint16 ether_type; /* IP? ARP? RARP? etc */
} sniff_ethernet;

#define ETHERNET_TYPE_IP 0x0800
#define ETHERNET_TYPE_IP6 0x86DD

/* IP header */
typedef struct 
{
		uint8 ip_vhl;		/* version << 4 | header length >> 2 */
		uint8 ip_tos;		/* type of service */
		uint16 ip_len;		/* total length */
		uint16 ip_id;		/* identification */
		uint16 ip_off;		/* fragment offset field */
		uint8 ip_ttl;		/* time to live */
		uint8 ip_p;		/* protocol */
		uint16 ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst; /* source and dest address */
} sniff_ip;

/* IP header V6 */
typedef struct 
{
		uint32 ip_v_tc_fl;		/* version (4bits), traffic class (8bits), flow label (20bits) */
		uint16 ip_len;		/* total length */
		uint8 ip_p;		/* protocol (next header)*/
		uint8 ip_hl;		/* hop limit */
		struct in6_addr ip_src,ip_dst; /* source and dest address */
} sniff_ip6;

typedef struct
{
    uint32 ip_source; /* Adresse ip source */
    uint32 ip_destination; /* Adresse ip destination */
    uint8 mbz; /* Champs à 0 */
    uint8 type; /* Type de protocole (6->TCP et 17->UDP) */
    uint16 length; /* htons( Taille de l'entete Pseudo + Entete TCP ou UDP + Data ) */
} pseudo_entete_ip;

#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */	
#define IP4_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP4_V(ip)		(((ip)->ip_vhl) >> 4)

#define IP_TYPE_TCP 0x06
#define IP_TYPE_UDP 0x11

	/* TCP header */
typedef struct {
		uint16 th_sport;	/* source port */
		uint16 th_dport;	/* destination port */
		uint32 th_seq;		/* sequence number */
		uint32 th_ack;		/* acknowledgement number */

		uint8 th_offx2;	/* data offset, rsvd */
	
		uint8 th_flags;
		uint16 th_win;		/* window */
		uint16 th_sum;		/* checksum */
		uint16 th_urp;		/* urgent pointer */
} sniff_tcp;

	/* UDP header */
typedef struct {
		uint16 uh_sport;	/* source port */
		uint16 uh_dport;	/* destination port */
		uint16 uh_len;	/* source port */
		uint16 uh_sum;	/* destination port */
		
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

int checkETHERNET(sniff_ethernet * header_ethernet, const uint8 * datas, int data_length);
int checkIPV4(sniff_ip * header_ip, const uint8 * datas, int data_length,struct ifaddrs *ifp);
int checkTCP(sniff_tcp * header_tcp, const uint8 * datas, int data_length, sniff_ip * header_ip, int local_source);
int checkUDP(sniff_ip * header_ip, uint16 * packet, int local_source);

uint16 cksum(uint32 sum,uint16 *ip, int len);
uint16 cksum2(uint32 sum, uint8 *bytes, int len);

/*TODO move all check function from dispatch to here*/

#endif