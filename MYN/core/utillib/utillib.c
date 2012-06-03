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

#include "utillib.h"

char * readString(int socket)
{
    sint32 size, alreadyRead = 0;
    int readed;
    char * ret = NULL;
    uint8 skip_data;
    /*char buffer[128];*/
    
    /*lecture de la taille*/
    if( (readed = recv(socket, &size, sizeof(size),MSG_WAITALL)) != sizeof(size) )
    {
        perror("(utillib) readString, failed to recv string size");
        return NULL;
    }
    
    size = ntohl(size);
    
    if(size <= 0)
    {
        return NULL;
    }
    
    /*allocation de la memoire*/
    if( (ret = calloc(size+1,sizeof(char))) == NULL)
    {
        perror("(controllib) readString, failed to allocate readed string");
        
        /*consommation du flux reseau*/
        while(size > 0)
        {
            if( (readed = recv(socket, &skip_data, sizeof(skip_data),MSG_WAITALL)) != sizeof(skip_data) )
            {
                perror("(utillib) readString, failed to skip data");
                return NULL;
            }
            size -= 1;
        }
        
        return NULL;
    }
    else
    {
        while( alreadyRead < size)
        {
            if( (readed = recv(socket, &ret[alreadyRead], size, MSG_WAITALL)) <= 0)
            {
                perror("(controllib) readString, failed to receive string");
                free(ret);
                return NULL;
            }
            alreadyRead += readed;
        }
        ret[size] = '\0';
    }
    
    return ret;
}

int writeString(int socket, const char * string)
{
    sint32 size;
    
    size = htonl(strlen(string));
    
    if( send(socket,&size, sizeof(size), 0) != sizeof(size))
    {
        perror("(controllib) writeString, failed to send size");
        return -1;
    }
    
    if(size > 0)
    {
        if( send(socket,string,strlen(string),0) != strlen(string))
        {
            perror("(controllib) writeString, failed to send string");
            return -1;
        }
    }
    
    /*printf("sended string : %s (%ld)\n",string,strlen(string));*/
    
    return 0;
    
}

int fileExist(const char * path)
{
	FILE * file;

    if( (file = fopen(path,"r") ) != NULL)
    {
		fclose(file);
		return 1;
    }
	return 0;
}

int isDir(char* file)
{
    struct stat b;
    stat(file, &b);
    if (S_ISDIR(b.st_mode))
        return 1;
    else
        return 0;
}

/*result = A - B*/
void timevalSubstraction(struct timeval * result, struct timeval * A, struct timeval * B)
{
    if(A->tv_usec < B->tv_usec)
    {
        result->tv_usec = 1000000 - (B->tv_usec - A->tv_usec);
        result->tv_sec = (A->tv_sec - 1) - B->tv_sec;
    }
    else
    {
        result->tv_usec = A->tv_usec - B->tv_usec;
        result->tv_sec = A->tv_sec - B->tv_sec;
    }
}

/*TO BIGENDIAN*/
uint64 htonll(uint64 value)
{
    uint64 ret;
    int num = 42;
    if (*(char *)&num == 42)
    {
        /*le system n'est pas en bigendian*/
        ((char *)&ret)[0] = ((char *)&value)[7];
        ((char *)&ret)[1] = ((char *)&value)[6];
        ((char *)&ret)[2] = ((char *)&value)[5];
        ((char *)&ret)[3] = ((char *)&value)[4];
        
        ((char *)&ret)[4] = ((char *)&value)[3];
        ((char *)&ret)[5] = ((char *)&value)[2];
        ((char *)&ret)[6] = ((char *)&value)[1];
        ((char *)&ret)[7] = ((char *)&value)[0];
        
        return ret;
    }
    else
    {
        /*le system est deja en bigendian*/
        return value;
    }
}

/*FROM BIGENDIAN*/
uint64 ntohll(uint64 value)
{
    return htonll(value);
}