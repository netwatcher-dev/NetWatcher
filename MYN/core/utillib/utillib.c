#include "utillib.h"

char * readString(int socket)
{
    sint32 size, alreadyRead = 0;
    int readed;
    char * ret = NULL;
    /*char buffer[128];*/
    
    /*lecture de la taille*/
    if( (readed = recv(socket, &size, sizeof(size),MSG_WAITALL)) != sizeof(size) )
    {
        fprintf(stderr,"readString size : %d\n", readed);
        return ret;
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
        
        /*TODO consommation du flux reseau*/
        
        return ret;
    }
    else
    {
        while( alreadyRead < size)
        {
            if( (readed = recv(socket, &ret[alreadyRead], size, 0)) <= 0)
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
    
    if( send(socket,string,strlen(string),0) != strlen(string))
    {
        perror("(controllib) writeString, failed to send string");
        return -1;
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