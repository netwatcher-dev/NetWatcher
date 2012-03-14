#ifndef _CORE_TYPE_H
#define _CORE_TYPE_H

#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h> /*struct ip*/

#define WAIT_START_PORT 22223
#define WAIT_MAX_PORT 10

typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;

typedef int8_t sint8;
typedef int16_t sint16;
typedef int32_t sint32;

typedef struct /* The order is IMPORTANT ! */
{  
    uint8 protocol; /*see ip protocol list*/
    uint16 sport;
    uint16 dport;
    uint32 epoch_time; /*epoch time on 32 bits*/
    uint8 sip[16];
    uint8 dip[16];
    uint8 ver;
    uint8 status;
    uint8 updated;
} collector_entry;

#define MAXBYTES2CAPTURE 2048

typedef struct
{
    unsigned int header_size;
    unsigned int frame_max_size;
}datalink_info;

#endif