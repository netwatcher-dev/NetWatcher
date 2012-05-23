#ifdef __gnu_linux__

#define _SVID_SOURCE
#define _POSIX_SOURCE
#include <sys/types.h>

#endif

#include <stdio.h> /*printf, perror, sprintf*/
#include <unistd.h> /*fork, execvp*/
#include <signal.h>
#include <stdlib.h> /*exit*/
#include <errno.h>
#include <sys/shm.h>
#include <sys/sem.h>

#define SHMKEY 25279
#define SEMKEY 97252

/*int control(int write_to_core,int read_from_core);
int core(int write_to_control,int read_from_control, int write_to_collector);
int collector(int read_from_control);*/

int main(int argc, char *argv[])
{
    int /*pipe_control_to_dispatch[2], pipe_dispatch_to_control[2],*/ pipe_dispatch_to_collector[2];
    int pipe_control_to_collector[2], pipe_collector_to_control[2];
    int shmDesc, semDesc;
    char arg1[10], arg2[10], arg3[6], arg4[6], arg5[6];
    pid_t child1, child2;
    key_t key;
    short sarray[2];

    /*create pipe*/ 
    /*if(pipe(pipe_control_to_dispatch) != 0)
    {
        perror("(CORE main) failed to open pipe (1) :");
        return EXIT_FAILURE;
    }
    
    if(pipe(pipe_dispatch_to_control) != 0)
    {
        perror("(CORE main) failed to open pipe (2) :");
        return EXIT_FAILURE;
    }*/
    
    
    if(pipe(pipe_dispatch_to_collector) != 0)
    {
        perror("(CORE main) failed to open pipe (3) :");
        return EXIT_FAILURE;
    }
    
    if(pipe(pipe_control_to_collector) != 0)
    {
        perror("(CORE main) failed to open pipe (3) :");
        return EXIT_FAILURE;
    }
    
    if(pipe(pipe_collector_to_control) != 0)
    {
        perror("(CORE main) failed to open pipe (3) :");
        return EXIT_FAILURE;
    }
     
    printf("PIPE OK\n");
    
    /*creation de la memoire partagee entre le control et le dispatch*/
    key = SHMKEY;
    if( (shmDesc = shmget(key,2048,IPC_CREAT|IPC_EXCL|0660)) < 0) /*tentative de creation*/
    {
        if(errno == EEXIST)
        {
            if( (shmDesc = shmget(key,2048,0660)) < 0) /*tentative de réouverture*/
            {
                perror("(core) shmget(2) :");
                return EXIT_FAILURE;
            }
        }
        else
        {
            perror("(core) shmget(1) :");
            return EXIT_FAILURE;
        }
    }
    printf("SHARED MEMORY %d ok\n",shmDesc);
    
    /*creation du semaphore entre le control et le dispatch*/
    key = SEMKEY;
    if( (semDesc = semget(key,2,IPC_CREAT|IPC_EXCL|0660)) < 0) /*tentative de creation*/
    {
        if(errno == EEXIST)
        {
            if( (semDesc = semget(key,2,0660)) < 0) /*tentative de réouverture*/
            {
                perror("(core) shmget(2) :");
                return EXIT_FAILURE;
            }
        }
        else
        {
            perror("(core) shmget(1) :");
            return EXIT_FAILURE;
        }
    }
    
    sarray[0] = 1;
    sarray[1] = 0;
    if(semctl(semDesc,0,SETALL, sarray) < 0)
    {
        perror("(core) failed to set val to sem :");
        return EXIT_FAILURE;
    }
    
    printf("SEM %d ok\n", semDesc);
        
    /*premier fils*/
    if( (child1 = fork()) < 0)
    {
        perror("(CORE main) failed to fork (1)");
        return EXIT_FAILURE;
    }

    if(child1 == 0)
    {
        /*close(pipe_control_to_dispatch[1]); on ferme le write
        close(pipe_dispatch_to_control[0]); on ferme le read*/
        close(pipe_dispatch_to_collector[0]); /*on ferme le read*/
        
        sprintf(arg1,"%d",shmDesc /*pipe_control_to_dispatch[0]*/);
        sprintf(arg2,"%d",semDesc /*pipe_dispatch_to_control[1]*/);
        sprintf(arg3,"%d",pipe_dispatch_to_collector[1]);
        if( execlp("./dispatch","dispatch", arg1, arg2, arg3, (char *)0) < 0)
        {
            perror("(CORE main) failed to execlp dispatch");
            kill(0,SIGKILL);
            return EXIT_FAILURE;
        }
    }
    
    /*second fils*/
    if( (child2 = fork()) < 0)
    {
        perror("(CORE main) failed to fork (2)");
        kill(0,SIGKILL);
        return EXIT_FAILURE;
    }
    
    if(child2 == 0)
    {
        close(pipe_dispatch_to_collector[1]); /*on ferme le write*/
        close(pipe_control_to_collector[1]);
        close(pipe_collector_to_control[0]);
        
        sprintf(arg1,"%d",pipe_dispatch_to_collector[0]);
        sprintf(arg2,"%d",pipe_control_to_collector[0]);
        sprintf(arg3,"%d",pipe_collector_to_control[1]);
        
        if( execlp("./collector","collector",arg1, arg2, arg3 , (char *)0) < 0)
        {
            perror("(CORE main) failed to execlp dispatch");
            kill(0,SIGKILL);
            return EXIT_FAILURE;
        }
    }
    
    /*close(pipe_control_to_dispatch[0]); on ferme le read
    close(pipe_dispatch_to_control[1]); on ferme le write*/

    close(pipe_control_to_collector[0]);
    close(pipe_collector_to_control[1]);

    sprintf(arg1,"%d",shmDesc /*pipe_control_to_dispatch[1]*/);
    sprintf(arg2,"%d",semDesc /*pipe_dispatch_to_control[0]*/);
    sprintf(arg3,"%d",pipe_control_to_collector[1]);
    sprintf(arg4,"%d",pipe_collector_to_control[0]);
    sprintf(arg5,"%d",child1);

    if( execlp("./control","control", arg1, arg2, arg3, arg4, arg5, (char *)0) < 0)
    {
        perror("(CORE main) failed to execlp dispatch");
        kill(0,SIGKILL);
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;    
}
