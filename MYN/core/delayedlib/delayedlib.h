#ifndef _DELAYEDLIB_H
#define _DELAYEDLIB_H

#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>
#include <errno.h>
#include "../core_type.h"

#define DELAYED_PACKET_IN_FILE_LIMIT 2000 /*it will be a non sense to set a smallest limit here than the memory limit*/
#define DELAYED_MAX_FILE_COUNT 50
#define DELAYED_MAX_PACKET_IN_MEMORY 500
#define DELAYED_THRESHOLD 10000 /*en microseconde*/

#define DELAYED_FLAG_INIT            1
#define DELAYED_FLAG_PAUSE           2
#define DELAYED_FLAG_ENABLE          4
#define DELAYED_FLAG_DATA_ON_FILE    8
#define DELAYED_FLAG_DONT_DELAY_NEXT 16

typedef struct time_packet
{
    struct timeval T;
    struct time_packet * next; /*next in time*/
    unsigned int size;
    uint8 * datas;
}time_packet;

/*
time_t         tv_sec      seconds
suseconds_t    tv_usec     microseconds 1 seconds = 1.000.000 microseconds
*/

/*DELAY SYSTEM VARS*/
struct timeval T, Tprime, ref_system, ref_packet;
time_packet * head_buffered_packet_input, * queue_buffered_packet_input,* head_buffered_packet_output, * queue_buffered_packet_output;
uint8 delay_factor, delay_flags;

/*DELAY FILE VAR*/
unsigned int file_count, packet_in_last_file, last_file_id,input_buffer_size,packet_read_from_last_file, input_offset;
unsigned int output_offset;
unsigned int output_buffer_size; /*debug vars*/
int input_file_descriptor, output_file_descriptor;

void setDelay(sint8 value);
void delay_init();
int delay_updateTime();
int delay_needToDelay(struct timeval * packet_time_T);
time_packet * delay_allocateTemporalPaquet(unsigned int size,struct timeval * t);
int delay_sendDelayedPacket(int socket, int * send_the_paquet);
void delay_flush();

int bufferToFile(time_packet * from, int limit);
int fileToBuffer();

#endif