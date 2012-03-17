#ifndef _DELAYEDLIB_H
#define _DELAYEDLIB_H

#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
#include "../core_type.h"

extern uint8 delay_factor;

#define DELAYED_BUFFER_SIZE 1024

typedef struct temporal_packet
{
    struct timeval T;
    struct temporal_packet * next;
    unsigned int size;
    uint8 * datas;
    
}temporal_packet;

/*
time_t         tv_sec      seconds
suseconds_t    tv_usec     microseconds
*/
struct timeval T, Tprime, ref;
temporal_packet * head_buffered_packet, * queue_buffered_packet;

uint8 buffer[DELAYED_BUFFER_SIZE];

int delay_init(struct timeval * first);
int needToDelay(struct timeval * packet_time_T, struct timeval * reference_time);
int delayPaquet(int pipe, unsigned int size, struct timeval ts);
int sendDelayedPacket(int socket, int dontsend, struct timeval * reference_time);

#endif