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

#include "delayedlib.h"

void setDelay(sint8 value)
{
    delay_factor = value;
}

/*
 * this function create a reference system time and a reference packet time
 * the reference packet time start with the first timestamp packet
 * then the value packet is updated in symetric way with the system time
 *
 */
void delay_init()
{
    delay_flags = DELAYED_FLAG_ENABLE;
    delay_factor = 0x80;
    head_buffered_packet_input = queue_buffered_packet_input = head_buffered_packet_output = queue_buffered_packet_output = NULL;
    output_buffer_size = input_offset = output_offset = packet_read_from_last_file = file_count = packet_in_last_file = last_file_id = input_buffer_size = 0;
    output_file_descriptor = input_file_descriptor = -1;
}

int delay_updateTime()
{
    struct timeval ref_system_tmp;
        
    if(!(delay_flags & DELAYED_FLAG_INIT))
        return 0;
        
    /*on met a jour ref*/
    if(gettimeofday(&ref_system_tmp,NULL) != 0)
    {
        perror("(delayedlib) WARNING failed to get ref time : ");
        return -1;
    }    
    
    /*update packet ref*/
    if(!(delay_flags & DELAYED_FLAG_PAUSE))
    {
        ref_packet.tv_sec += (ref_system_tmp.tv_sec - ref_system.tv_sec);
        ref_packet.tv_usec += (ref_system_tmp.tv_usec - ref_system.tv_usec);

        /*if there is a microseconds overflow*/
        while(ref_packet.tv_usec > 1000000)
        {
            ref_packet.tv_sec += 1;
            ref_packet.tv_usec -= 1000000;
        }
    }
    
    /*update system ref*/
    ref_system = ref_system_tmp;
    
    return 0;
}

/*
    T'(x+1) = ( T(x+1) - T(x) ) * Y + T'(x)
*/
void delay_getTprimeXPlusOne(struct timeval * TXPlusOne, struct timeval * TprimeXPlusOne)
{   
    long int factor = 100 + lround(sqrt(pow((delay_factor&0x7F),3)));
    if(delay_factor&0x80)
    {
        if(TXPlusOne->tv_usec > T.tv_usec)
        {
            /*TprimeXPlusOne->tv_usec = ((TXPlusOne->tv_usec - T.tv_usec) * (delay_factor&0x7F))+ Tprime.tv_usec;
            TprimeXPlusOne->tv_sec = ((TXPlusOne->tv_sec - T.tv_sec) * (delay_factor&0x7F)) + Tprime.tv_sec;*/
            TprimeXPlusOne->tv_usec = ( ((TXPlusOne->tv_usec - T.tv_usec) * factor) / 100)+ Tprime.tv_usec;
            TprimeXPlusOne->tv_sec = ( ((TXPlusOne->tv_sec - T.tv_sec) * factor) /100) + Tprime.tv_sec;            
        }
        else
        {
            /*TprimeXPlusOne->tv_usec = ((1000000 - (T.tv_usec - TXPlusOne->tv_usec)) * (delay_factor&0x7F))+ Tprime.tv_usec;
            TprimeXPlusOne->tv_sec = ((TXPlusOne->tv_sec - T.tv_sec -1) * (delay_factor&0x7F)) + Tprime.tv_sec;*/
            TprimeXPlusOne->tv_usec = (((1000000 - (T.tv_usec - TXPlusOne->tv_usec)) * factor) /100)+ Tprime.tv_usec;
            TprimeXPlusOne->tv_sec = (((TXPlusOne->tv_sec - T.tv_sec -1) * factor) /100) + Tprime.tv_sec;
        }
    }
    else
    {
        if(TXPlusOne->tv_usec > T.tv_usec)
        {
            /*TprimeXPlusOne->tv_usec = ((TXPlusOne->tv_usec - T.tv_usec) / (delay_factor&0x7F))+ Tprime.tv_usec;
            TprimeXPlusOne->tv_sec = ((TXPlusOne->tv_sec - T.tv_sec) / (delay_factor&0x7F)) + Tprime.tv_sec;*/
            TprimeXPlusOne->tv_usec = (((TXPlusOne->tv_usec - T.tv_usec) * 100) / factor)+ Tprime.tv_usec;
            TprimeXPlusOne->tv_sec = (((TXPlusOne->tv_sec - T.tv_sec) * 100) / factor) + Tprime.tv_sec;
        }
        else
        {
            /*TprimeXPlusOne->tv_usec = ((1000000 - (T.tv_usec - TXPlusOne->tv_usec)) / (delay_factor&0x7F))+ Tprime.tv_usec;
            TprimeXPlusOne->tv_sec = ((TXPlusOne->tv_sec - T.tv_sec -1) / (delay_factor&0x7F)) + Tprime.tv_sec;*/
            TprimeXPlusOne->tv_usec = (((1000000 - (T.tv_usec - TXPlusOne->tv_usec))  * 100) / factor)+ Tprime.tv_usec;
            TprimeXPlusOne->tv_sec = (((TXPlusOne->tv_sec - T.tv_sec -1)  * 100) / factor) + Tprime.tv_sec;
        }
    }
    
    while(TprimeXPlusOne->tv_usec > 1000000)
    {
        TprimeXPlusOne->tv_usec -= 1000000;
        TprimeXPlusOne->tv_sec += 1;
    }
}

int delay_needToDelay(struct timeval * packet_time_T)
{
    struct timeval packet_time_Tprime;
    
    if(!(delay_flags & DELAYED_FLAG_INIT))
    {
        /*init du temps system*/
        if(gettimeofday(&ref_system,NULL) != 0)
        {
            perror("(delayedlib) WARNING failed to set ref time");
            return 0;
        }
    
        ref_packet.tv_sec = T.tv_sec = Tprime.tv_sec = packet_time_T->tv_sec;
        ref_packet.tv_usec = T.tv_usec = Tprime.tv_usec = packet_time_T->tv_usec;
        
        delay_flags |= DELAYED_FLAG_INIT;
        return 0; /*false, don't delayed the first packet*/
    }
    
    if(head_buffered_packet_input != NULL /*il y a des paquet dans le buffer d'entree, pas besoin de faire la verif, il doit aller en queue*/
       || head_buffered_packet_output != NULL /*meme chose si packet en bufer de sortie*/
       || file_count > 1 || (file_count==1 && packet_in_last_file > 0)/*s'il y a des paquets sur fichier, */
       || ((delay_flags & DELAYED_FLAG_PAUSE) && (delay_flags & DELAYED_FLAG_ENABLE)) /*pause si le buffer est activé et en pause*/
        ) 
    {                                                                 
        return 1; /*true*/
    }
    
    if(delay_flags & DELAYED_FLAG_ENABLE)/*si la bufferisation est activée, on regarde si on doit différé le packet*/
    {
        /*on calcul le temps différé en fonction du precedent paquet */
        delay_getTprimeXPlusOne(packet_time_T, &packet_time_Tprime);

        /*printf("%lu.%u vs %lu.%u\n",packet_time_Tprime.tv_sec, packet_time_Tprime.tv_usec, ref_packet.tv_sec, ref_packet.tv_usec);*/
        if( packet_time_Tprime.tv_sec > ref_packet.tv_sec 
        || (packet_time_Tprime.tv_sec == ref_packet.tv_sec && packet_time_Tprime.tv_usec > ref_packet.tv_usec) )
        {
            return 1; /*true*/
        }
    }
    
    return 0; /*false*/
}

int setFilePacketCount(int descriptor, unsigned int value)
{
    if( lseek(input_file_descriptor,0,SEEK_SET) != 0)
    {
        perror("(delayedlib) setFilePacketCount, failed to seek at the beginning of the file");
        return -1;
    }
    
    if(write(input_file_descriptor,&value,sizeof(unsigned int)) != sizeof(unsigned int))
    {
        perror("(delayedlib) setFilePacketCount, failed to write file size");
        return -1;
    }
    
    return 0;
}

time_packet * delay_allocateTemporalPaquet(unsigned int size,struct timeval * t)
{
    time_packet * tmp = NULL, * tmp2;
    char filename[256];
    unsigned int i;
    
    /*allocation en memoire du paquet*/
    if( (tmp = malloc(sizeof(struct time_packet))) == NULL )
    {
        perror("(delayedlib) delayPaquet, failed to malloc temporal_packet");
        return NULL;
    }
    /*allocation du paquet*/
    
    if(size > 0)
    {
        if( (tmp->datas = malloc(size)) == NULL )
        {
            perror("(delayedlib) delayPaquet, failed to malloc temporal_packet");
            free(tmp);
            return NULL;
        }        
    }
    
    tmp->size = size;
    tmp->next = NULL;
    tmp->T.tv_sec = t->tv_sec;
    tmp->T.tv_usec = t->tv_usec;
    
/*gestion de la bufferisation sur disque*/
    if(input_buffer_size == DELAYED_MAX_PACKET_IN_MEMORY 
    || ((delay_flags & DELAYED_FLAG_DATA_ON_FILE) && input_buffer_size == (DELAYED_MAX_PACKET_IN_MEMORY/2))
    )/*LE BUFFER INPUT EST PLEIN ?*/
    {
        /*open and create file if needed*/
        if(input_file_descriptor == -1)
        {
            /*max file count ?*/
            if(file_count == DELAYED_MAX_FILE_COUNT) 
            {
                fprintf(stderr,"(delayedlib) delay_allocateTemporalPaquet, buffer is full, packet drop\n");
                free(tmp->datas);free(tmp);
                return NULL;
            }
            
            sprintf(filename,"/tmp/myndelay_tempfile.%d.%d",getpid(),(last_file_id+1)%DELAYED_MAX_FILE_COUNT);
            if( (input_file_descriptor = open(filename,O_WRONLY|O_CREAT|O_TRUNC,0644)) < 0)
            {
                perror("(delayedlib) delay_allocateTemporalPaquet, failed to open first file");
                free(tmp->datas);free(tmp);
                return NULL;
            }
            
            /*modification des variables d'etats*/
            last_file_id += 1;
            packet_in_last_file = 0;
            input_offset = 0;
            file_count += 1;
            
            /*si c'est l'ouverture du premier fichier, on doit splitter le buffer*/
            if( !(delay_flags & DELAYED_FLAG_DATA_ON_FILE))
            {
                /*on split les buffer*/
                tmp2 = head_buffered_packet_input;
                output_buffer_size = 0;
                for(i=0;i<((DELAYED_MAX_PACKET_IN_MEMORY/2)-1);i+=1,input_buffer_size -= 1, output_buffer_size +=1)
                {
                    tmp2 = tmp2->next;
                }
                input_buffer_size -= 1;
                output_buffer_size += 1;
                head_buffered_packet_input = tmp2->next;
                queue_buffered_packet_output = tmp2;
                tmp2->next = NULL;

                delay_flags |= DELAYED_FLAG_DATA_ON_FILE;
            }
        }
                
        /*write input buffer in file */
        for(i = 0;head_buffered_packet_input != NULL && packet_in_last_file < DELAYED_PACKET_IN_FILE_LIMIT;packet_in_last_file += 1,input_buffer_size -= 1, i++)
        {
            /*faire un fseek avec un offset global*/            
            if(lseek(input_file_descriptor,input_offset,SEEK_SET) != input_offset
             ||write(input_file_descriptor,&head_buffered_packet_input->T,sizeof(struct timeval))              < sizeof(struct timeval)
             ||write(input_file_descriptor,&head_buffered_packet_input->size,sizeof(unsigned int))             < sizeof(unsigned int)
             ||write(input_file_descriptor,head_buffered_packet_input->datas,head_buffered_packet_input->size) < head_buffered_packet_input->size)
            {
                perror("(delaylib) sendDelayedPacket, failed to write or lseek next packet");
                free(tmp->datas);free(tmp);

                close(input_file_descriptor);
                input_file_descriptor = -1;
                
                /*si fichier vide, le supprimer*/
                if(packet_in_last_file == 0)
                {
                    sprintf(filename,"/tmp/myndelay_tempfile.%d.%d",getpid(),last_file_id % DELAYED_MAX_FILE_COUNT);
                    unlink(filename);
                }
                
                return NULL;
            }
            
            /*update offset*/
            input_offset += sizeof(struct timeval)+sizeof(unsigned int)+head_buffered_packet_input->size;
            
            tmp2 = head_buffered_packet_input;
            head_buffered_packet_input = head_buffered_packet_input->next;
            
            free(tmp2->datas);
            free(tmp2);
        }
                
        /*fermeture du fichier*/
        if(packet_in_last_file == DELAYED_PACKET_IN_FILE_LIMIT)
        {   
            close(input_file_descriptor);
            input_file_descriptor = -1;
        }
    }
    
/*append new packet at the queue of the input buffer*/
    
    if(head_buffered_packet_input == NULL)/*le buffer est vide*/
    {
        head_buffered_packet_input = queue_buffered_packet_input = tmp;
    }
    else /*le buffer n'est pas vide mais n'est pas plein*/
    {
        queue_buffered_packet_input->next = tmp;
        queue_buffered_packet_input = tmp;
    }
    
    input_buffer_size += 1;
    
    /*si pas de fichier, les deux bufers ne font qu'un*/
    if( !(delay_flags & DELAYED_FLAG_DATA_ON_FILE))
    {
        head_buffered_packet_output = head_buffered_packet_input;
        queue_buffered_packet_output = queue_buffered_packet_input;
        output_buffer_size += 1;
    }
    
    return tmp;
}

int delay_sendDelayedPacket(int socket, int * send_the_paquet)
{
    struct timeval packet_time_Tprime;
    time_packet * tmp;
    int error = 0;
    unsigned int limite_to_read, i;
    char filename[256];
    
    /*BOUCLE PRINCIPALE DE VIDAGE DU BUFFER*/
    while(head_buffered_packet_output != NULL)
    {
        delay_getTprimeXPlusOne(&head_buffered_packet_output->T, &packet_time_Tprime);
        
        /*printf("%lu,%u vs %lu,%u\n", 
        head_buffered_packet_output->T.tv_sec - T.tv_sec,
        head_buffered_packet_output->T.tv_usec - T.tv_usec,
        packet_time_Tprime.tv_sec - Tprime.tv_sec,
        packet_time_Tprime.tv_usec - Tprime.tv_usec);
        
        printf("T : %lu,%u T' %lu,%u",T.tv_sec,T.tv_usec,Tprime.tv_sec,Tprime.tv_usec);
        printf(" T+1 : %lu,%u T+1' %lu,%u\n",head_buffered_packet_output->T.tv_sec,head_buffered_packet_output->T.tv_usec,packet_time_Tprime.tv_sec,packet_time_Tprime.tv_usec);
        */
        
        /*est ce que le paquet de tête peu être envoyé?*/
        if( (delay_flags & DELAYED_FLAG_DONT_DELAY_NEXT) || packet_time_Tprime.tv_sec < ref_packet.tv_sec 
        || (packet_time_Tprime.tv_sec == ref_packet.tv_sec && packet_time_Tprime.tv_usec <= (ref_packet.tv_usec + DELAYED_THRESHOLD )) )
        {
            if(*send_the_paquet)/*on a un client au bout?*/
            {
                if(send(socket, head_buffered_packet_output->datas, head_buffered_packet_output->size,0) < 0)
                {
                    perror("(delaylib) sendDelayedPacket, failed to send packet");
                    /*WARNING, don't return or break or exit this statement, the buffer must be read*/
                    error = -1;
                }
            }
            
            /*mettre T et Tprime a jour*/
            if(delay_flags & DELAYED_FLAG_DONT_DELAY_NEXT)
            {
                ref_packet.tv_sec = T.tv_sec = Tprime.tv_sec = head_buffered_packet_output->T.tv_sec;
                ref_packet.tv_usec = T.tv_usec = Tprime.tv_usec = head_buffered_packet_output->T.tv_usec;
                delay_flags ^= DELAYED_FLAG_DONT_DELAY_NEXT;
            }
            else
            {
                T = head_buffered_packet_output->T;
                Tprime = packet_time_Tprime;
            }

            /*liberer la memoire*/
            tmp = head_buffered_packet_output;
            head_buffered_packet_output = head_buffered_packet_output->next;
            free(tmp->datas);
            free(tmp);
            
            if( !(delay_flags & DELAYED_FLAG_DATA_ON_FILE) )
            {
                input_buffer_size -= 1;
                head_buffered_packet_input = head_buffered_packet_output;
            }
            output_buffer_size -=1;
                        
            continue;
        }
        /*else on doit attendre, dc packet_time_Tprime > ref_packet
        {
            if(packet_time_Tprime.tv_usec < ref_packet.tv_usec )
            {
                printf("    (1) time to wait before to send : %lu, %u\n",packet_time_Tprime.tv_sec - ref_packet.tv_sec -1,1000000 - (ref_packet.tv_usec - packet_time_Tprime.tv_usec));
            }
            else
            {
                printf("    (2) time to wait before to send : %lu, %u\n",packet_time_Tprime.tv_sec - ref_packet.tv_sec,packet_time_Tprime.tv_usec - ref_packet.tv_usec);            
            }
            printf("    %lu, %u vs %lu, %u\n", ref_packet.tv_sec,ref_packet.tv_usec,packet_time_Tprime.tv_sec,packet_time_Tprime.tv_usec);
            
        }*/
        /*si le packet de tête ne peut pas être envoyé, il n'y a aucun autre traitement à faire, il faut attendre*/
        return error;
    }
    
    /*SI ON ARRIVE ICI, LE BUFFER OUTPUT EST VIDE*/
    
    queue_buffered_packet_output = NULL;
    
    if( delay_flags & DELAYED_FLAG_DATA_ON_FILE )
    {     
        /*cas de base (1) : plus de fichier*/   
        if(file_count == 0)
        {
            /*merge input and output buffer*/
            head_buffered_packet_output = head_buffered_packet_input;
            queue_buffered_packet_output = queue_buffered_packet_input;
            delay_flags ^= DELAYED_FLAG_DATA_ON_FILE;
            output_buffer_size = input_buffer_size;
            
            return error;
        }
        
        /*cas de base (2) : 1 seul fichier et le writer ecrit tjs dedans*/
        if(file_count == 1 && input_file_descriptor > -1)
        {   
            if(packet_read_from_last_file == packet_in_last_file)/*le reader a rattrapé le writer?*/
            {                                                    /*empeche d'ouvrir des fichiers vide*/
                /*close the files*/
                close(output_file_descriptor);
                close(input_file_descriptor);
                
                /*destroy the file*/
                sprintf(filename,"/tmp/myndelay_tempfile.%d.%d",getpid(),( last_file_id - (file_count-1) ) % DELAYED_MAX_FILE_COUNT);
                unlink(filename);
                
                /*reset vars*/
                input_file_descriptor = output_file_descriptor = -1;
                file_count = 0;
                
                /*merge buffer*/
                head_buffered_packet_output = head_buffered_packet_input;
                queue_buffered_packet_output = queue_buffered_packet_input;
                delay_flags ^= DELAYED_FLAG_DATA_ON_FILE;
                output_buffer_size = input_buffer_size;
                
                return error;
            }
            
            limite_to_read = packet_in_last_file;
        }
        else
        {
            limite_to_read = DELAYED_PACKET_IN_FILE_LIMIT;
        }

        /*ouverture de fichier*/
        if(output_file_descriptor == -1)/*y a t'il deja un fichier d'ouvert?*/
        {
            /*open the file*/
            sprintf(filename,"/tmp/myndelay_tempfile.%d.%d",getpid(),( last_file_id - (file_count-1) ) % DELAYED_MAX_FILE_COUNT);
            if(  (output_file_descriptor = open(filename,O_RDONLY,0644)) < 0 )
            {
                perror("(delaylib) sendDelayedPacket, failed to open buffer file");
                return -1;
            }
            
            output_offset = 0;
            packet_read_from_last_file = 0;
            
            delay_flags |= DELAYED_FLAG_DONT_DELAY_NEXT;
        }
        
        /*read from file*/
        for(i=0;packet_read_from_last_file < limite_to_read && i < (DELAYED_MAX_PACKET_IN_MEMORY/2);i+=1,packet_read_from_last_file += 1,output_buffer_size +=1)
        {   
            /*positionnement au bon endroit dans le fichier*/
            if(lseek(output_file_descriptor,output_offset,SEEK_SET) != output_offset)
            {
                perror("(delaylib) sendDelayedPacket, failed to seek to next packet (2)");
                goto endof;
            }

            if( (tmp = malloc(sizeof(struct time_packet))) == NULL)
            {
                perror("(delaylib) sendDelayedPacket, failed to allocate new time packet");
                return -1;
            }
            tmp->next = NULL;

            if(read(output_file_descriptor,&tmp->T,sizeof(struct timeval)) != sizeof(struct timeval)
             ||read(output_file_descriptor,&tmp->size,sizeof(unsigned int)) != sizeof(unsigned int))
            {
                perror("(delaylib) sendDelayedPacket, failed to read next timeval or size");
                free(tmp);
                goto endof;
            }

            if( (tmp->datas = malloc(tmp->size)) == NULL)
            {
                perror("(delaylib) sendDelayedPacket, failed to allocate new time packet datas");
                free(tmp);
                return -1;
            }

            if(read(output_file_descriptor,tmp->datas,tmp->size) != tmp->size)
            {
                perror("(delaylib) sendDelayedPacket, failed to allocate new time packet datas");
                free(tmp->datas);free(tmp);
                goto endof;
            }
            
            /*update offset*/
            output_offset += sizeof(struct timeval) + sizeof(unsigned int) + tmp->size;
            
            /*append the new packet at the queue of the buffer*/
            if(head_buffered_packet_output == NULL)
            {
                queue_buffered_packet_output = head_buffered_packet_output = tmp;
            }
            else
            {
                queue_buffered_packet_output->next = tmp;
                queue_buffered_packet_output = tmp;
            }
        }
                
        /*end of file? */
        if(packet_read_from_last_file == DELAYED_PACKET_IN_FILE_LIMIT)
        {
            endof:
            
            close(output_file_descriptor);
            
            if(input_file_descriptor > -1 && file_count == 1)
            {
                close(input_file_descriptor);
                input_file_descriptor = -1;
                file_count = 0;
            }
            
            /*destroy the file*/
            sprintf(filename,"/tmp/myndelay_tempfile.%d.%d",getpid(),( last_file_id - (file_count-1) ) % DELAYED_MAX_FILE_COUNT);
            unlink(filename);
            
            output_file_descriptor = -1;
            file_count -= 1;
        }
    }
    else
    {
        queue_buffered_packet_input = queue_buffered_packet_output;
    }    
    
    return error;
}

void delay_flush()
{
    time_packet * tmp;
    char filename[256];
    
    while(head_buffered_packet_input != NULL)
    {
        tmp = head_buffered_packet_input;
        head_buffered_packet_input = head_buffered_packet_input->next;
        
        free(tmp->datas);
        free(tmp);
    }
    
    /*free output buff*/
    if(delay_flags & DELAYED_FLAG_DATA_ON_FILE )
    {
        while(head_buffered_packet_output != NULL)
        {
            tmp = head_buffered_packet_output;
            head_buffered_packet_output = head_buffered_packet_output->next;

            free(tmp->datas);
            free(tmp);
        }
        delay_flags ^= DELAYED_FLAG_DATA_ON_FILE;
    }
    
    /*remove files*/
    close(input_file_descriptor);
    close(output_file_descriptor);
    
    input_file_descriptor = output_file_descriptor = -1;
    head_buffered_packet_input = queue_buffered_packet_input = head_buffered_packet_output = queue_buffered_packet_output = NULL;
    output_buffer_size = input_offset = output_offset = packet_read_from_last_file = file_count = packet_in_last_file = last_file_id = input_buffer_size = 0;
    
    for(;file_count> 0;file_count-=1)
    {
        sprintf(filename,"/tmp/myndelay_tempfile.%d.%d",getpid(),( last_file_id - (file_count-1) ) % DELAYED_MAX_FILE_COUNT);
        unlink(filename);
    }
    
    if(delay_flags & DELAYED_FLAG_INIT)
    {
        delay_flags ^= DELAYED_FLAG_INIT;/*de-init*/
    }
}
