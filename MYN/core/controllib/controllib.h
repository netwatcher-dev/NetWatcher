#ifndef _CONTROLLIB_H
#define _CONTROLLIB_H

#ifdef __gnu_linux__

#define _BSD_SOURCE
#define _SVID_SOURCE
#define _POSIX_SOURCE
#include <sys/types.h>

#include <pcap/pcap.h>

#endif

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#include <sys/sem.h>
#include <stdarg.h>
#include <sys/stat.h>
#include "../core_type.h"
#include "../command.h"

#include "../collectorlib/collectorlib.h"
#include "../utillib/utillib.h"
#include "../capturefilterlib/capturefilterlib.h"
#include "../sharedmemorylib/sharedmemorylib.h"

char errbuf[PCAP_ERRBUF_SIZE];

typedef struct
{
    sint32 size;
    char * name;
} entry;

#define ARG_SET 0
#define ARG_GET 1

typedef struct
{
    char type;
    void * values;
    int size;
} my_args;

extern int from_collector, to_collector, dispatch_id;
extern uint32 tokenCount;
extern mymemory * mem;


int sendEntries(int socket);
int getProtocolList(int socket);
int clearProtocolList(int socket);
int setLengthProtocolList(int socket);
int selectCaptureDevice(int socket);
/*int disableCaptureDevice(int socket);*/
int selectCaptureFile(int socket);
int setSpeed(int socket);
/*int parseFile(int socket);*/
/*int startCapture(int socket);*/
int stopCapture(int socket);
/*int stopAllCapture(int socket);*/
int listFiles(int socket);
int startRecord(int socket);
/*int stopRecord(int socket);*/
int setCaptureMode(int mode);

int setFilter(int socket, int command);

int directTransmit(int socket, int command);

int sendCommandToDispatch(int command, int argc_set, int argc_get, ...);


#endif
