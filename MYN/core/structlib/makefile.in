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
#include <pcap.h>

#include "../core_type.h"
#include "../segmentlib/segmentlib.h"

#define DATALINK_MANAGED 3
#define NETWORK_MANAGED 3
#define TRANSPORT_MANAGED 3

extern datalink_info link_info;

typedef struct
{
    int datalink_type;
    int header_size;
    int frame_payload_max_size;
    int footer;
    int (*check)(const uint8 * datas, int data_length, int * encapslated_protocol);
} datalink_check;

typedef struct
{
    int protocol_type;
    int (*check)(const struct pcap_pkthdr *pkthdr, const uint8 * datas, int local_source, collector_entry * entry);
} transport_check;

typedef struct
{
    int protocol_type;
    int (*check)(const uint8 * datas, int data_length,struct ifaddrs *ifp,unsigned int * network_size, int * encapslated_protocol, int * local_address, collector_entry * entry);
    transport_check transport[TRANSPORT_MANAGED];
} network_check;

/*DATALINK CHECKER*/
int checkETHERNET        (const uint8 * datas, int data_length, int * encapslated_protocol);
int checkIEEE80211       (const uint8 * datas, int data_length, int * encapslated_protocol);
int checkDatalinkDefault (const uint8 * datas, int data_length, int * encapslated_protocol);

/*NETWORK CHECKER*/
int checkIPV4               (const uint8 * datas, int data_length,struct ifaddrs *ifp,unsigned int * network_size, int * encapslated_protocol, int * local_address, collector_entry * entry);
int checkIPV6               (const uint8 * datas, int data_length,struct ifaddrs *ifp,unsigned int * network_size, int * encapslated_protocol, int * local_address, collector_entry * entry);
int checkNetworklinkDefault (const uint8 * datas, int data_length,struct ifaddrs *ifp,unsigned int * network_size, int * encapslated_protocol, int * local_address, collector_entry * entry);

/*TRANSPORT CHECKER*/
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

datalink_check datalink_check_function_plop[DATALINK_MANAGED];
network_check network_check_function[NETWORK_MANAGED] ;

#endif