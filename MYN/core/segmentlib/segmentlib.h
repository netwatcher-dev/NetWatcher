/*
    TODO : 
        -gerer la taille max du buffer
        -gerer le tour du compteur de la sequence
            c'est embetant pour des comparaisons de sequence
*/

#ifndef _SEGMENTLIB_H
#define _SEGMENTLIB_H

#include "../core_type.h"
#include "../structlib/structlib.h"
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>

#define MAXBUFFSIZE 2048 /*TODO not used*/
#define SEGMAXBUFFBYSOCK 10 /*[1, 255]*/
#define SEGTIMEOUT 20

#define SEG_FLAGS_END 0x01
#define SEG_FLAGS_BROKEN 0x02

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
    uint32 ip_src;
    uint32 ip_dest;
    uint16 port_src;
    uint16 port_dst;
    
    struct sequence_entry * next;
    struct sequence_entry * previous;
    next_buffer * linked_buffer;
    uint32 seq; /*waited sequence*/
    struct timeval mod_time;
    uint8 flags;
    uint8 count;
    
} sequence_entry;

extern sequence_entry * seq_start;
extern sequence_entry * seq_last;

#ifdef DEBUG_MEMORY_SEG
extern int count_entry, cont_buffer;
#endif

sequence_entry * getEntry(uint32 ip_src, uint32 ip_dest, uint16 port_src, uint16 port_dst);
sequence_entry * createEntry(uint32 ip_src, uint32 ip_dest, uint16 port_src, uint16 port_dst, uint32 se);
int addData(sequence_entry * entry, uint32 sequence_number,const uint8 * datas, int data_length);
next_buffer * createNextBuffer(uint32 sequence_number,const uint8 * datas, int data_length, next_buffer * next, next_buffer * previous);
uint8 * forgeSegment(sequence_entry * entry, next_buffer * buffer, int datalink_size);
void flushAllSegment();
void removeEntry(sequence_entry * entry);
void cleanData(sequence_entry * entry);

#endif