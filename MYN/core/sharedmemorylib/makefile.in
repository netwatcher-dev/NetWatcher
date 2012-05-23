/*

improvement :
    -check invalid mem pointer in function
    -check if locked is already done or not
*/

#ifndef _SHAREDMEMORYLIB_H
#define _SHAREDMEMORYLIB_H

#ifdef __gnu_linux__

#define _SVID_SOURCE

#endif

#include <sys/sem.h>
#include <sys/shm.h>
#include <stdlib.h>
#include <stdio.h>
#include "../core_type.h"

#define MEMORYSIZE 2048
#define AREASTART 2

#define get_int(mem, ide) (((int *)mem->mem)[ide])
#define get_byte(mem, ide) (((uint8 *)mem->mem)[ide])

typedef struct
{
    void * mem;
    int areaCount;
    int semDescr;
    int semId;
}mymemory;

mymemory * createMemory(int shmDescr, int areaCount, int semDescr, int semId);
int openMemory(mymemory *  mem);
void cleanAreaMemories(mymemory *  mem);
void setState(mymemory *  mem, int state);
int getState(mymemory *  mem);
void setAction(mymemory *  mem, int action);
int getAction(mymemory *  mem);
int getAreaMemory(mymemory *  mem, int area_id, void ** area, int * size);
void * getNextAvailableAreaMemory(mymemory *  mem, int size);
int closeMemory(mymemory *  mem);
int freeMemory(mymemory *  mem);

int lockSem(int descr, int semid);
int unlockSem(int descr, int semid);


#endif
