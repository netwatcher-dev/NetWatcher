#ifndef _UTILLIB_H
#define _UTILLIB_H

#include <sys/socket.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../core_type.h"

int fileExist(const char * path);
char * readString(int socket);
int writeString(int socket, const char * string);
int isDir(char* file);

#endif