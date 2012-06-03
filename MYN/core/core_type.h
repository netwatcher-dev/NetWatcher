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

#ifndef _CORE_TYPE_H
#define _CORE_TYPE_H

#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h> /*struct ip*/
#include <stdint.h>


/*TODO pour linux*/
#include <time.h>
#include <sys/time.h> 
#include <unistd.h>

#define WAIT_START_PORT 22223
#define WAIT_MAX_PORT 10

extern int act, state;

typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

typedef int8_t sint8;
typedef int16_t sint16;
typedef int32_t sint32;
typedef int64_t int64;

typedef struct /* The order is IMPORTANT ! */
{  
    uint32 epoch_time; /*epoch time on 32 bits*/
    uint8 protocol; /*see ip protocol list*/
    uint8 ver;
    uint16 sport;
    uint16 dport;
    uint8 sip[16];
    uint8 dip[16];
    uint8 status;
    uint8 updated;
    
} collector_entry;

#define MAXBYTES2CAPTURE 65535

typedef struct
{
    unsigned int header_size;
    unsigned int frame_payload_max_size; /**/
    int datalink_type;
    unsigned int footer;
}datalink_info;

#define ACT_STOP          0
#define ACT_START         1
#define ACT_PARSE         2
#define ACT_HANDLE_SIGNAL 4
#define ACT_GOTO          8
#define ACT_READ          16
#define ACT_PAUSE         32
#define ACT_RESUME        64

#define STATE_NOTHING   0
#define STATE_RUNNING   1
#define STATE_RECORDING 2
#define STATE_FILE      4
#define STATE_STREAM    8

#define STATE_PARSING   16
#define STATE_READING   32
#define STATE_PAUSE     64
#define STATE_GOTO      128

#define STATE_PARSED    256
#define STATE_FINISHED  512

#define IS_RUNNING(s)   (s->state & 0x001)
#define IS_RECORDING(s) (s->state & 0x002)
#define IS_FILE(s)      (s->state & 0x004)
#define IS_STREAM(s)    (s->state & 0x008)

#define IS_PARSING(s)   (s->state & 0x010)
#define IS_READING(s)   (s->state & 0x020)
#define IS_PAUSE(s)     (s->state & 0x040)
#define IS_GOTO(s)      (s->state & 0x080)

#define IS_PARSED(s)    (s->state & 0x100)
#define IS_FINISHED(s)  (s->state & 0x200)

struct core_state
{
    uint32 state;
    
    uint32 packet_readed;
    uint32 packet_in_file;

    uint64 file_current_tv_sec, file_current_tv_usec;
    uint64 file_duration_tv_sec, file_duration_tv_usec;
};

#define HL_IP6 40
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

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
		uint16 ip_len;		/* total length WHIT HEADER LENGTH !!!!!*/
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
		uint8 ip_v_tc_fl[4];		/* version (4bits), traffic class (8bits), flow label (20bits) */
		uint16 ip_len;		/* total length WHITOUT HEADER LENGTH !!!!! */
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

#define IP6_V(ip)		(((ip)->ip_v_tc_fl[0]) >> 4)

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

struct ieee80211_radiotap_header 
{
	u_int8_t	it_version;	
	u_int8_t	it_pad;
	u_int16_t       it_len;    
	u_int32_t       it_present;    
};

/*
 * The subtype field of a data frame is, in effect, composed of 4 flag
 * bits - CF-Ack, CF-Poll, Null (means the frame doesn't actually have
 * any data), and QoS.
 */
#define DATA_FRAME_IS_CF_ACK(x)		((x) & 0x01)
#define DATA_FRAME_IS_CF_POLL(x)	((x) & 0x02)
#define DATA_FRAME_IS_NULL(x)		((x) & 0x04)
#define DATA_FRAME_IS_QOS(x)		((x) & 0x08)

/*
 * Bits in the frame control field.
 */
#define	FC_VERSION(fc)		((fc) & 0x3)
#define	FC_TYPE(fc)		(((fc) >> 2) & 0x3)
#define	FC_SUBTYPE(fc)		(((fc) >> 4) & 0xF)
#define	FC_TO_DS(fc)		((fc) & 0x0100)
#define	FC_FROM_DS(fc)		((fc) & 0x0200)
#define	FC_MORE_FLAG(fc)	((fc) & 0x0400)
#define	FC_RETRY(fc)		((fc) & 0x0800)
#define	FC_POWER_MGMT(fc)	((fc) & 0x1000)
#define	FC_MORE_DATA(fc)	((fc) & 0x2000)
#define	FC_WEP(fc)		((fc) & 0x4000)
#define	FC_ORDER(fc)		((fc) & 0x8000)

struct mgmt_header_t {
 	u_int16_t	fc;
 	u_int16_t 	duration;
 	u_int8_t	da[6];
 	u_int8_t	sa[6];
 	u_int8_t	bssid[6];
 	u_int16_t	seq_ctrl;
 }; /*24 bytes*/

struct llc_snap
{
    uint8 dsap;
    uint8 ssap;
    uint8 control_field;
    uint8 organisation_code[3];
    uint16 type;
};

#endif