/*
    TODO SEGMENTLIB : 
        -gerer la taille max du buffer
        -gerer le tour du compteur de la sequence
            c'est embetant pour des comparaisons de sequence
        -gerer le réordonnement des syn/ack, pour l'instant on ne gère que les datas
            -les syn c'est indispensable
            -utilité des ack et autre?
*/

#ifndef _SEGMENTLIB_H
#define _SEGMENTLIB_H

#include "../core_type.h"
#include "../capturefilterlib/capturefilterlib.h"
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#define MAXBUFFSIZE 2048 /*TODO SEGMENTLIB not used*/
#define SEGMAXBUFFBYSOCK 100 /*[1, 255]*/
#define SEGTIMEOUT 20

#define SEG_FLAGS_END 0x01
#define SEG_FLAGS_BROKEN 0x02

extern datalink_info link_info;

typedef struct
{
    uint32 seq;
    uint8 * data;
    int dsize;
    void * next_buffer;
    void * previous_buffer;
} next_buffer;

typedef struct sequence_entry
{
    uint16 port_src;
    uint16 port_dst;
    
    next_buffer * linked_buffer;
    uint32 seq; /*waited sequence*/
    struct timeval mod_time;
    uint8 flags;
    uint8 count;
    
}sequence_entry;

typedef struct sequence_entry_ipv6
{
    uint8 ip_src[16];
    uint8 ip_dest[16];
    
    struct sequence_entry seq;
    
    struct sequence_entry_ipv6 * next;
    struct sequence_entry_ipv6 * previous;
}sequence_entry_ipv6;

typedef struct sequence_entry_ipv4
{
    uint32 ip_src;
    uint32 ip_dest;
    
    struct sequence_entry seq;
    
    struct sequence_entry_ipv4 * next;
    struct sequence_entry_ipv4 * previous;

} sequence_entry_ipv4;

sequence_entry_ipv4 * seq_start_ipv4;
sequence_entry_ipv4 * seq_last_ipv4;

sequence_entry_ipv6 * seq_start_ipv6;
sequence_entry_ipv6 * seq_last_ipv6;

#ifdef DEBUG_MEMORY_SEG
extern int count_entry, cont_buffer;
#endif

sequence_entry_ipv4 * getEntry(uint32 ip_src, uint32 ip_dest, uint16 port_src, uint16 port_dst);
sequence_entry * createEntry(uint32 ip_src, uint32 ip_dest, uint16 port_src, uint16 port_dst, uint32 se);

sequence_entry_ipv6 * getEntry_ipv6(uint8 * ip_src, uint8 * ip_dest, uint16 port_src, uint16 port_dst);
sequence_entry * createEntry_ipv6(uint8 * ip_src, uint8 * ip_dest, uint16 port_src, uint16 port_dst, uint32 se);

int addData(sequence_entry * entry, uint32 sequence_number,const uint8 * datas, int data_length);
next_buffer * createNextBuffer(uint32 sequence_number,const uint8 * datas, int data_length, next_buffer * next, next_buffer * previous);
uint8 * forgeSegment_ipv4(sequence_entry_ipv4 * entry, next_buffer * buffer, int datalink_size);
uint8 * forgeSegment_ipv6(sequence_entry_ipv6 * entry, next_buffer * buffer, int datalink_size);
void flushAllSegment();
void removeEntry_ipv4(sequence_entry_ipv4 * entry);
void removeEntry_ipv6(sequence_entry_ipv6 * entry);
void cleanData(sequence_entry * entry);

int addNewSegment_ipv4(sniff_tcp * header_tcp, sniff_ip * header_ip, const uint8 * datas);
int addNewSegment_ipv6(sniff_tcp * header_tcp, sniff_ip6 * header_ip6, const uint8 * datas);

void sendReadySegment_ipv4(sniff_tcp * tcp, sniff_ip * ip, const struct pcap_pkthdr *pkthdr, const uint8 * datas);
void sendReadySegment_ipv6(sniff_tcp * tcp, sniff_ip6 * ip6, const struct pcap_pkthdr *pkthdr, const uint8 * datas);

#endif