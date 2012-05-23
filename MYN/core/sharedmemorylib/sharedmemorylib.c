#include "sharedmemorylib.h"

mymemory * createMemory(int shmDescr, int areaCount, int semDescr, int semId)
{
    mymemory * ret = NULL;
    
    if(  (ret = malloc(sizeof(mymemory ))) == NULL )
    {
        perror("(sharedmemorylib) createMemory, failed to alocate mymemory pointer:");
        return ret;
    }
    
    /*on attache la memoire partagee*/
    if((ret->mem = shmat(shmDescr,NULL,0)) == (void *)-1)
    {
        perror("(sharedmemorylib) createMemory, failed to attach memory");
        free(ret);
        return ret;
    }
    
    ret->areaCount = areaCount;
    ret->semDescr = semDescr;
    ret->semId = semId;
    
    /*init area tab*/
    /*cleanAreaMemories(ret);*/
    
    return ret;
}

int openMemory(mymemory *  mem)
{
    return lockSem(mem->semDescr,mem->semId);
}

void cleanAreaMemories(mymemory *  mem)
{
    int i;
    for(i=0;i< (2*mem->areaCount);i+=2)
    {
        get_int(mem,AREASTART+i) = 0;
        get_int(mem,AREASTART+i+1) = 0;
    }
}

void setState(mymemory *  mem, int state)
{
    get_int(mem,0) = state;
}

int getState(mymemory *  mem)
{
    return get_int(mem,0);
}

void setAction(mymemory *  mem, int action)
{
    get_int(mem,1) = action;
}

int getAction(mymemory *  mem)
{
    return get_int(mem,1);
}

int getAreaMemory(mymemory *  mem, int area_id, void ** area, int * size)
{
    if(area_id < mem->areaCount)
    {
        if( (*size = get_int(mem,AREASTART+2*area_id)) > 0)
        {
            *area = ((uint8 *)mem->mem) + get_int(mem,AREASTART+2*area_id + 1);
        }
        else
        {
            fprintf(stderr,"(sharedmemorylib) createMemory, not initiated area\n");
            return -1;
        }
    }
    else
    {
        fprintf(stderr,"(sharedmemorylib) createMemory, area index out of bound\n");
        return -1;
    }
    
    return 0;
}

void * getNextAvailableAreaMemory(mymemory *  mem, int size)
{
    int i, already_allocated= (AREASTART + 2*mem->areaCount) * sizeof(int);

    /*find first available area*/
    for(i=0;i< (2*mem->areaCount);i+=2)
    {
        already_allocated += get_int(mem,AREASTART+i);
        
        if(get_int(mem,AREASTART+i) == 0)
        {
            /*found an available area*/
            
            if(already_allocated + size > MEMORYSIZE)
            {
                fprintf(stderr,"(sharedmemorylib) getNextAvailableAreaMemory,no enought free space\n");
                return NULL;
            }
            
            get_int(mem,AREASTART+i) = size;
            get_int(mem,AREASTART+i+1) = (AREASTART + 2*mem->areaCount) * sizeof(int) + already_allocated;
            
            return ((uint8 *)mem->mem) + get_int(mem,AREASTART+i+1);
        }
    } 
    
    fprintf(stderr,"no more area available\n");
    return NULL;
}

int closeMemory(mymemory *  mem)
{
    return unlockSem(mem->semDescr, mem->semId);
}

int lockSem(int descr, int semid)
{
    struct sembuf sop;
    
    sop.sem_num = semid; 
    sop.sem_op  = -1; /*decremente*/
    sop.sem_flg = 0; /*allow wait*/
    
    return semop(descr,&sop,1);
}

int unlockSem(int descr, int semid)
{
    struct sembuf sop;
    
    sop.sem_num = semid; 
    sop.sem_op  = 1; /*incremente*/
    sop.sem_flg = 0; /*allow wait*/
    
    return semop(descr,&sop,1);
}

int freeMemory(mymemory *  mem)
{
    void * tmp;
    
    tmp = mem->mem;
    free(mem);
    
    return shmdt(tmp);
}