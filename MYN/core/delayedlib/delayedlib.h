#ifndef _DELAYEDLIB_H
#define _DELAYEDLIB_H

#include "../core_type.h"

extern uint8 delay_factor;
extern struct timeval ts;

typedef struct temporal_packet
{
    
}temporal_packet;

int availablepacket();
int needToDelay(struct timeval ts);
int delayedPaquet(uint8 * tmp, unsigned int size, struct timeval ts);

#endif