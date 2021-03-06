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

#ifndef _STRUCTLIB_H
#define _STRUCTLIB_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef __gnu_linux__

#define _BSD_SOURCE
#include <sys/types.h>

#endif

#ifdef HAVE_PCAP_H
#include <pcap.h>
#endif

#ifdef HAVE_PCAP_PCAP_H
#include <pcap/pcap.h>
#endif

#if !(defined(HAVE_PCAP_H) || defined(HAVE_PCAP_PCAP_H))
#include <pcap.h>
#include <pcap/pcap.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h> /*struct ip*/
#include <arpa/inet.h>
#include <strings.h>
#include <string.h>
#include <ifaddrs.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "../core_type.h"
#include "../segmentlib/segmentlib.h"

#define DATALINK_MANAGED 3 /*WARNING, don't forget to increment this variable if you add a new protocol check*/
#define NETWORK_MANAGED 3 /*WARNING, don't forget to increment this variable if you add a new protocol check*/
#define TRANSPORT_MANAGED 3 /*WARNING, don't forget to increment this variable if you add a new protocol check*/

extern datalink_info link_info;

typedef struct
{
    int datalink_type; /*DATALINK type from libpcap, see pcap-linktype manpage*/
    int header_size; /*if the header has a static size, put it here, or set it in the link_info when the check function is executed*/
    int frame_payload_max_size; /*payload of the datalink frame, without header size*/
    int footer; /*if there are a payload, put it here, elswhere set it to zero*/
    int (*check)(const uint8 * datas, int data_length, int * encapslated_protocol); /*the datalink check function pointer*/
} datalink_check;

typedef struct
{
    int protocol_type; /*in our case, we only use the IPV4 or IPV6 header, so the protocol type is the ip payload carried type, here is the list : http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers*/
    int (*check)(const struct pcap_pkthdr *pkthdr, const uint8 * datas, int local_source, collector_entry * entry); 
} transport_check;

typedef struct
{
    int protocol_type; /*protocol type from the datalink header, http://standards.ieee.org/develop/regauth/ethertype/eth.txt*/
    int (*check)(const uint8 * datas, int data_length,struct ifaddrs *ifp,unsigned int * network_size, int * encapslated_protocol, int * local_address, collector_entry * entry); /*the network check function pointer*/
    transport_check transport[TRANSPORT_MANAGED]; /*the list of transport protocol carried on this network protocol*/
} network_check;

/*DATALINK CHECKER*/

    /*
     * 
     * @param datas, a table of byte that contains all the data with header from the datalink layer
     * @param data_length, the lenght of the table datas
     * @param encapslated_protocol, its a pointer to a variable to set, the value to set is the network protocol type
     * @return an integer with the value zero if the packet must be forwarded or a negative value if the packet must be discarded
     *
     */

int checkETHERNET        (const uint8 * datas, int data_length, int * encapslated_protocol);
int checkIEEE80211       (const uint8 * datas, int data_length, int * encapslated_protocol);
int checkDatalinkDefault (const uint8 * datas, int data_length, int * encapslated_protocol);

/*NETWORK CHECKER*/

    /*
     * 
     * @param datas, a table of byte that contains all the data with header from the datalink layer
     * @param data_length, the lenght of the table datas
     * @param ifp, its a list with all the address of the local host
     * @param network_size, it's a variable to set, with the size of the network protocole size, header included
     * @param encapslated_protocol, its a pointer to a variable to set, the value to set is the transport protocol type
     * @param local_address, it's a pointer to a variable to set,if the checked packet is send from the local host, the local_address must be set to 1, otherelse to 0 
     * @param entry, it's a pointer to a collector_entry structure, this structure must be completed with the packet informations
     * @return an integer with the value zero if the packet must be forwarded or a negative value if the packet must be discarded
     *
     */

int checkIPV4               (const uint8 * datas, int data_length,struct ifaddrs *ifp,unsigned int * network_size, int * encapslated_protocol, int * local_address, collector_entry * entry);
int checkIPV6               (const uint8 * datas, int data_length,struct ifaddrs *ifp,unsigned int * network_size, int * encapslated_protocol, int * local_address, collector_entry * entry);
int checkNetworklinkDefault (const uint8 * datas, int data_length,struct ifaddrs *ifp,unsigned int * network_size, int * encapslated_protocol, int * local_address, collector_entry * entry);

/*TRANSPORT CHECKER*/

    /*
     * 
     * @param datas, a table of byte that contains all the data with header from the datalink layer
     * @param data_length, the lenght of the table datas
     * @param local_address, this value come from the network layer check, if the value is 1, the packet is sent from the local host
     * @param entry, it's a pointer to a collector_entry structure, this structure must be completed with the packet informations
     * @return an integer with the value zero if the packet must be forwarded or a negative value if the packet must be discarded
     *
     */

int checkTCP                  (const struct pcap_pkthdr *pkthdr, const uint8 * datas, int local_source, collector_entry * entry);
int checkTCP_ipv6             (const struct pcap_pkthdr *pkthdr, const uint8 * datas, int local_source, collector_entry * entry);
int checkUDP                  (const struct pcap_pkthdr *pkthdr, const uint8 * datas, int local_source, collector_entry * entry);
int checkUDP_ipv6             (const struct pcap_pkthdr *pkthdr, const uint8 * datas, int local_source, collector_entry * entry);
int checkTransportlinkDefault (const struct pcap_pkthdr *pkthdr, const uint8 * datas, int local_source, collector_entry * entry);

/*CHECKSUM CHECKER*/
uint16 cksum(uint32 sum,uint16 *ip, int len);
uint16 cksum2(uint32 sum, uint8 *bytes, int len);

/*DEBUG PRINT FUNCTION*/
void printEthernetType(uint16 type);
void printIpType(uint8 type);
void printIPV6(struct in6_addr * ip);

/*WARNING, if you add a new procotol check, don't forget to add it in the following table in the structlib.c*/

datalink_check datalink_check_function_plop[DATALINK_MANAGED];
network_check network_check_function[NETWORK_MANAGED] ;

#endif