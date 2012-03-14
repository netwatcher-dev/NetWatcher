#include "segmentlib.h"

sequence_entry * getEntry(uint32 ip_src, uint32 ip_dest, uint16 port_src, uint16 port_dst)
{
    sequence_entry * ret = seq_start, * tmp;
    struct timeval current;
    
    if(gettimeofday(&current,NULL) != 0)
    {
        perror("(segmentlib) getEntry, failed to get mod_time");
    }
    
    /*recherche dans les existants*/
    while(ret != NULL)
    {
        if(ret->ip_src == ip_src && ret->ip_dest == ip_dest && ret->port_src == port_src && ret->port_dst == port_dst)
        {
            if(gettimeofday(&ret->mod_time,NULL) != 0)
            {
                perror("(segmentlib) getEntry, failed to update mod_time");
            }
            
            return ret;
        }
        tmp = ret;
        ret = ret->next;
        
        /* faire sauter les périmés*/
        if(tmp->mod_time.tv_sec+SEGTIMEOUT < current.tv_sec)
        {
            removeEntry(tmp);
        }
    }
    
    /*not found*/
    return NULL;
}

sequence_entry * createEntry(uint32 ip_src, uint32 ip_dest, uint16 port_src, uint16 port_dst, uint32 se)
{
    /*creation si n'existe pas*/
    sequence_entry * ret = calloc(1,sizeof(sequence_entry));
    if(ret == NULL)
    {
        perror("(segmentlib) createEntry, failed to allocate memory");
        return NULL;
    }
    
    ret->ip_src = ip_src;
    ret->ip_dest = ip_dest;
    ret->port_src = port_src;
    ret->port_dst = port_dst;
    ret->flags = 0;
    ret->count = 0;
    
    ret->next = NULL;
    ret->previous = NULL;
    ret->linked_buffer = NULL;
    ret->seq = se;
    
    if(gettimeofday(&ret->mod_time,NULL) != 0)
    {
        perror("(segmentlib) createEntry, failed to init mod_time : ");
        free(ret);
        return NULL;
    }
    #ifdef DEBUG_MEMORY_SEG
    count_entry++;
    #endif
    
    /*ajout dans la chaine*/
    if(seq_last == NULL)
    {
        seq_start = seq_last = ret;
    }
    else
    {
        seq_last->next = ret;
        ret->previous = seq_last;
        seq_last = ret;
    }
    
    return ret;
}

/**
 * @param entry, l'entree corresponsant a la session tcp (ip.src, ip.dst, tcp.psrc, tcp.pdst)
 * @param sequence_number, le numero de sequence du premier byte de data
 * @param datas, les données reçues
 * @param data_length, nombre de bytes reçu
 *
 */
int addData(sequence_entry * entry, uint32 sequence_number, const uint8 * datas, int data_length)
{
    uint32 last_byte_seq = sequence_number + data_length -1;
    next_buffer * next = NULL, * last = NULL, *newbuff;
    int itmp, jtmp;
    
    /*on est bien en presence d'une sequence trop grande*/
    if(entry->seq < sequence_number)
    {
        if(entry->linked_buffer == NULL)
        {
            /*CAS 1 pas encore de buffer disponible, on ajoute juste l'entree*/
            #ifdef PRINT_TCP
            printf("CAS 1\n");
            #endif
            if( (newbuff = createNextBuffer(sequence_number, datas, data_length, NULL, NULL)) == NULL)
            {
                fprintf(stderr,"(segmentlib) addData, failed to create new next_buffer\n");
                return -1;
            }
            entry->linked_buffer = newbuff;
            entry->count++;
        }
        else
        {
            /*on trouve ou inserer les données*/
            next = entry->linked_buffer;
            while(next != NULL)
            {
                if(last_byte_seq+1 <= next->seq) /*on a trouvé une borne supérieur*/
                {
                    break;
                }
                last = next;
                next = next->next_buffer;
            }
        
            if(next == NULL)
            {
                /*CAS 2 : on insere en fin de buffer*/
                #ifdef PRINT_TCP
                printf("CAS 2\n");
                #endif
                itmp = last->seq + last->dsize - sequence_number; /*byte en commun entre last et new*/
                
                if( itmp <= 0)/*verifier qu'on overlape pas le buffer precedent last*/
                {
                    newbuff = createNextBuffer(sequence_number, datas, data_length, NULL, last); /*new_buff est après last*/
                }
                else if(itmp == data_length)
                {
                    /*on overlap entierement le segment precedent, drop*/
                    return 0;
                }
                else
                {
                    newbuff = createNextBuffer(sequence_number + itmp, &datas[itmp], data_length - itmp, NULL, last); /*on est face a un overlap*/
                }
                
                if( newbuff == NULL)
                {
                    fprintf(stderr,"(segmentlib) addData, failed to create new next_buffer\n");
                    return -1;
                }
                
                last->next_buffer = newbuff;
                entry->count++;
            }
            else
            {
                if(last == NULL)
                {
                    /*CAS 3 on insere en tête de buffer, avant next*/
                        /*pas d'overlap possible ici, puisque les conditions precedantes nous indique qu'on se trouve avant le premier element du buffer*/
                    #ifdef PRINT_TCP
                    printf("CAS 3\n");
                    #endif
                    if( (newbuff = createNextBuffer(sequence_number, datas, data_length, next, NULL)) == NULL)
                    {
                        fprintf(stderr,"(segmentlib) addData, failed to create new next_buffer\n");
                        return -1;
                    }
                    
                    entry->linked_buffer = newbuff;
                    entry->count++;
                }
                else
                {
                    /*CAS 4 on insere au millieu du buffer, entre next et last*/
                        /*verifier qu'on overlape pas le buffer suivant next*/
                        /*verifier qu'on overlape pas le buffer precedent last*/
                    #ifdef PRINT_TCP
                    printf("CAS 4\n");
                    #endif
                    itmp = last->seq + last->dsize - sequence_number;
                    jtmp = sequence_number + data_length - next->seq;
                    
                    if(itmp <= 0 && jtmp <= 0)
                    {
                        newbuff = createNextBuffer(sequence_number, datas, data_length, next, last);
                    }
                    else if(itmp > 0 && jtmp > 0)
                    {
                        if(itmp + jtmp >= data_length)
                        {
                            return 0; /*overlap de tout le segment*/
                        }
                        
                        newbuff = createNextBuffer(sequence_number + itmp, &datas[itmp], data_length - (itmp + jtmp), next, last);
                    }
                    else if(jtmp > 0) /*&& itmp <= 0*/
                    {
                        if(jtmp >= data_length)
                        {
                            return 0; /*overlap de tout le segment*/
                        }
                        
                        newbuff = createNextBuffer(sequence_number, datas, data_length-jtmp, next, last);
                    }
                    else /*if (itmp > 0 && jtmp <= 0) */
                    {
                        if(itmp >= data_length)
                        {
                            return 0; /*overlap de tout le segment*/
                        }
                        
                        newbuff = createNextBuffer(sequence_number + itmp, &datas[itmp], data_length - itmp, next, last);
                    }
                    
                    if( newbuff == NULL)
                    {
                        fprintf(stderr,"(segmentlib) addData, failed to create new next_buffer\n");
                        return -1;
                    }
                    
                    last->next_buffer = newbuff;
                    next->previous_buffer = newbuff;
                    entry->count++;
                }
            }
        }
    }
    
    return 0;
}

next_buffer * createNextBuffer(uint32 sequence_number,const uint8 * datas, int data_length, next_buffer * next, next_buffer * previous)
{
    next_buffer * newbuff;
        
    if( (newbuff = calloc(1, sizeof(next_buffer)))  == NULL)
    {
        perror("(segmentlib) createNextBuffer, failed to create new next_buffer : ");
        return NULL;
    }
    
    if( (newbuff->data = malloc(data_length)) == NULL)
    {
        perror("(segmentlib) createNextBuffer, failed to create new next_buffer data : ");
        free(newbuff);
        return NULL;
    }
    #ifdef DEBUG_MEMORY_SEG
    cont_buffer++;
    #endif
    memcpy(newbuff->data, datas, data_length);
    
    newbuff->seq = sequence_number;
    newbuff->dsize = data_length;
    newbuff->next_buffer = next;
    newbuff->previous_buffer = previous;
        
    return newbuff;
}

uint8 * forgeSegment(sequence_entry * entry, next_buffer * buffer, int datalink_size)
{   
    uint8 * ret = NULL;
    sniff_ethernet *ether;
    sniff_tcp *tcp; 
    sniff_ip *ip;
    uint32 diff_seq = entry->seq - buffer->seq;
    
    if((ret = calloc(datalink_size + 20 + 20 + buffer->dsize - diff_seq,1)) == NULL)
    {
        perror("(segmentlib) forgeSegment, failed to allocate memory to new segment : ");
        return NULL;
    }
    
    /*TODO manage other datalink types*/
    ether = (sniff_ethernet *)ret;
    ether->ether_type = htons(ETHERNET_TYPE_IP);
    
    /*ip*/
    ip = (sniff_ip*)(ret + datalink_size);
    ip->ip_vhl = 0x45;
    /*ip->ip_tos = 0;*/
    ip->ip_len = htons(20 + 20 + buffer->dsize);
    /*ip->ip_id = 0;*/
    /*ip->ip_off = 0x4000; don't fragment*/
    ip->ip_ttl = 254;
    ip->ip_p = IP_TYPE_TCP;
    /*ip->ip_sum = 0; */ /*TODO TO compute*/
    ip->ip_src.s_addr = entry->ip_src;
    ip->ip_dst.s_addr = entry->ip_dest;
    
    /*tcp*/
    tcp = (sniff_tcp*)(ret + datalink_size + 20);
    tcp->th_sport = htons(entry->port_src);
    tcp->th_dport = htons(entry->port_dst);
    tcp->th_seq = htonl(entry->seq);
    /*tcp->th_ack = 0;*/
    tcp->th_offx2 = 0x50;
    /*tcp->th_flags = 0;*/ /*no flag*/
    /*tcp->th_win = 0;*/ /*TODO ???*/
    tcp->th_sum =  0; /*TODO TO compute*/
    /*tcp->th_urp = 0;*/
    
    /*data
    printf("DIFF SEQ : %d\n",diff_seq);*/
    memcpy(&ret[datalink_size+20+20],&buffer->data[diff_seq], buffer->dsize-diff_seq);
    
    return ret;
}

void flushAllSegment()
{
    sequence_entry * tmp;
    next_buffer * nb_tmp1, * nb_tmp2;
    
    /*recherche dans les existants*/
    while(seq_start != NULL)
    {
        tmp = seq_start;
        seq_start = seq_start->next;
        
        nb_tmp1 = tmp->linked_buffer;
        while(nb_tmp1 != NULL)
        {
            nb_tmp2 = nb_tmp1;
            nb_tmp1 = nb_tmp1->next_buffer;
            free(nb_tmp2);
            #ifdef DEBUG_MEMORY_SEG
            cont_buffer--;
            #endif
        }
        #ifdef DEBUG_MEMORY_SEG
        count_entry--;
        #endif
        free(tmp);
    }
    seq_start = seq_last = NULL;
}

void removeEntry(sequence_entry * entry)
{
    next_buffer * nb_tmp1, * nb_tmp2;
    
    if(entry->previous == NULL)
    {
        seq_start = entry->next;
        
        if(entry->next != NULL)
        {
            entry->next->previous = NULL;
        }
    }
    else
    {
        entry->previous->next = entry->next;
        
        if(entry->next != NULL)
        {
            entry->next->previous = entry->previous;
        }
    }
    
    if(entry->next == NULL)
    {
        seq_last = entry->previous;
        
        if(entry->previous != NULL)
        {
            entry->previous->next = NULL;
        }
    }
    else
    {
        entry->next->previous = entry->previous;
        
        if(entry->previous != NULL)
        {
            entry->previous->next = entry->next;
        }
    }
    
    nb_tmp1 = entry->linked_buffer;
    while(nb_tmp1 != NULL)
    {
        nb_tmp2 = nb_tmp1;
        nb_tmp1 = nb_tmp1->next_buffer;
        free(nb_tmp2->data);
        free(nb_tmp2);
        #ifdef DEBUG_MEMORY_SEG
        cont_buffer--;
        #endif
    }
    #ifdef DEBUG_MEMORY_SEG
    count_entry--;
    #endif
    free(entry);
}

void cleanData(sequence_entry * entry)
{
    next_buffer * nb_tmp1, * nb_tmp2;
    
    nb_tmp1 = entry->linked_buffer;
    while(nb_tmp1 != NULL)
    {
        nb_tmp2 = nb_tmp1;
        nb_tmp1 = nb_tmp1->next_buffer;
        free(nb_tmp2->data);
        free(nb_tmp2);
        #ifdef DEBUG_MEMORY_SEG
        cont_buffer--;
        #endif
    }
    
    entry->linked_buffer = NULL;
}

