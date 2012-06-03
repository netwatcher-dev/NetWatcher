/*
                    GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

                            Preamble

  The GNU General Public License is a free, copyleft license for
software and other kinds of works.

  The licenses for most software and other practical works are designed
to take away your freedom to share and change the works.  By contrast,
the GNU General Public License is intended to guarantee your freedom to
share and change all versions of a program--to make sure it remains free
software for all its users.  We, the Free Software Foundation, use the
GNU General Public License for most of our software; it applies also to
any other work released this way by its authors.  You can apply it to
your programs, too.

  When we speak of free software, we are referring to freedom, not
price.  Our General Public Licenses are designed to make sure that you
have the freedom to distribute copies of free software (and charge for
them if you wish), that you receive source code or can get it if you
want it, that you can change the software or use pieces of it in new
free programs, and that you know you can do these things.

  To protect your rights, we need to prevent others from denying you
these rights or asking you to surrender the rights.  Therefore, you have
certain responsibilities if you distribute copies of the software, or if
you modify it: responsibilities to respect the freedom of others.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
#include <sys/types.h>
#include <sys/stat.h>

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
    char path[2048];
    struct stat st = {0};
    
    /*verification et creation du repertoire captured_files*/

    char *home = getenv ("HOME");
    if (home == NULL) 
    {
        perror("(CORE main) failed to get HOME directory");
        return EXIT_FAILURE;
    }
    
    #ifdef DEV
    snprintf(path, sizeof(path), "./capture_files/");
    #else
    snprintf(path, sizeof(path), "%s/capture_files/", home);
    #endif
    
    printf("%s\n",path);
    
    if (stat(path, &st) == -1) 
    {
        if(mkdir(path, 0700) < 0)
        {
            perror("(CORE main) mkdir");
            return EXIT_FAILURE;
        }
        printf("CREATE CAPTURE DIRECTORY\n");
    }
    
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
        
        #ifdef DEV
        if( execlp("./dispatch","dispatch", arg1, arg2, arg3, (char *)0) < 0)
        #else
        if( execlp("dispatch","dispatch", arg1, arg2, arg3, (char *)0) < 0)
        #endif
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
        #ifdef DEV
        if( execlp("./collector","collector",arg1, arg2, arg3 , (char *)0) < 0)
        #else
        if( execlp("collector","collector",arg1, arg2, arg3 , (char *)0) < 0)
        #endif
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

    #ifdef DEV
    if( execlp("./control","control", arg1, arg2, arg3, arg4, arg5, (char *)0) < 0)
    #else
    if( execlp("control","control", arg1, arg2, arg3, arg4, arg5, (char *)0) < 0)
    #endif
    {
        perror("(CORE main) failed to execlp dispatch");
        kill(0,SIGKILL);
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;    
}
