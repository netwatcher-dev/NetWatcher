#include "delayedlib.h"

int delay_init(struct timeval * first)
{
    T.tv_sec = Tprime.tv_sec = first->tv_sec;
    T.tv_usec = Tprime.tv_usec = first->tv_usec;
    
    if(gettimeofday(&ref,NULL) != 0)
    {
        perror("(delayedlib) init, failed to init ref time : ");
        return -1;
    }
    return 0;
}

/*
    T'(x+1) = ( T(x+1) - T(x) ) * Y + T'(x)
*/
void getTprimeXPlusOne(struct timeval * TXPlusOne, struct timeval * TprimeXPlusOne)
{    
    TprimeXPlusOne->tv_sec = ((TXPlusOne->tv_sec - T.tv_sec) * delay_factor) + Tprime.tv_sec;
    TprimeXPlusOne->tv_usec = (((TXPlusOne->tv_sec > T.tv_sec)?TXPlusOne->tv_sec - T.tv_sec:1000000-T.tv_sec+TXPlusOne->tv_sec) * delay_factor) + Tprime.tv_usec;
    
    while(TprimeXPlusOne->tv_usec > 1000000)
    {
        TprimeXPlusOne->tv_usec -= 1000000;
        TprimeXPlusOne->tv_sec -= 1;
    }    
}


int needToDelay(struct timeval * packet_time_T, struct timeval * reference_time)
{
    struct timeval packet_time_Tprime;
    
    if(head_buffered_packet != NULL)/*il y a des paquet en memoire, pas besoin de faire la verif, il doit aller en queue*/
    {
        return 1; /*true*/
    }
    
    /*on calcul le temps différé en fonction du precedent paquet */
    getTprimeXPlusOne(packet_time_T, &packet_time_Tprime);
    
    if( packet_time_Tprime.tv_sec < reference_time->tv_sec 
    || (packet_time_Tprime.tv_sec == reference_time->tv_sec && packet_time_Tprime.tv_usec < reference_time->tv_usec) )
    {
        return 1; /*true*/
    }
    
    return 0; /*false*/
}

int delayPaquet(int pipe, unsigned int size, struct timeval ts)
{
    /*TODO faire une fonction hybride qui peut soit vider le flux, soit forwarder le paquet, soit le bufferisé*/
    
    temporal_packet * tmp;
    int error = 0;
    
    
    /*allocation en memoire du paquet*/
    if( (tmp = malloc(sizeof(temporal_packet))) == NULL )
    {
        perror("(delayedlib) delayPaquet, failed to malloc temporal_packet");
        error = -1;
    }
    
    /*allocation du paquet*/
    if( (tmp->datas = malloc(size)) == NULL )
    {
        perror("(delayedlib) delayPaquet, failed to malloc temporal_packet");
        free(tmp);
        error = -1;
    }
    
    /*TODO lire le paquet sur le pipe*/
    
        /*TODO remplir le buffer si pas d'erreur*/
        
        /*TODO juste lire le pipe si erreur d'allocation*/
    
    /*TODO on ajoute le paquet dans la file*/
    
    return error;
}

int sendDelayedPacket(int socket, int send_the_paquet, struct timeval * reference_time)
{
    struct timeval packet_time_Tprime;
    temporal_packet * tmp;
    int error = 0;
    
    while(head_buffered_packet != NULL)
    {
        getTprimeXPlusOne(&head_buffered_packet->T, &packet_time_Tprime);
        
        /*est ce que le paquet de tête peu être envoyé?*/
        if( packet_time_Tprime.tv_sec < reference_time->tv_sec 
        || (packet_time_Tprime.tv_sec == reference_time->tv_sec && packet_time_Tprime.tv_usec < reference_time->tv_usec) )
        {
            /*envoyer le paquet*/
            if(send_the_paquet)/*on a un client au bout?*/
            {
                if(send(socket, head_buffered_packet->datas, head_buffered_packet->size,0) < 0)
                {
                    perror("(delaylib) sendDelayedPacket, failed to send packet");
                    /*WARNING, don't return or break or exit this statement, the buffer must be read*/
                    error = -1;
                }
            }
            
            /*mettre T et Tprime a jour*/
            T = head_buffered_packet->T;
            Tprime.tv_sec = packet_time_Tprime.tv_sec;
            Tprime.tv_usec = packet_time_Tprime.tv_usec;

            /*liberer la memoire*/
            tmp = head_buffered_packet;
            head_buffered_packet = head_buffered_packet->next;
            free(tmp->datas);
            free(tmp);
            
            continue;
        }
        return error;
    }
    
    return error;
}





