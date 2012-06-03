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

#include "segmentlib.h"

sequence_entry_ipv4 * getEntry(uint32 ip_src, uint32 ip_dest, uint16 port_src, uint16 port_dst)
{
    sequence_entry_ipv4 * ret = seq_start_ipv4, * tmp;
    struct timeval current;
    
    last_header_ip = NULL;last_header_tcp = NULL;last_header_ip6 = NULL;
    
    if(gettimeofday(&current,NULL) != 0)
    {
        perror("(segmentlib) getEntry, failed to get mod_time");
    }
    
    /*recherche dans les existants*/
    while(ret != NULL)
    {
        if(ret->ip_src == ip_src && ret->ip_dest == ip_dest && ret->seq.port_src == port_src && ret->seq.port_dst == port_dst)
        {
            if(gettimeofday(&ret->seq.mod_time,NULL) != 0)
            {
                perror("(segmentlib) getEntry, failed to update mod_time");
            }
            
            return ret;
        }
        tmp = ret;
        ret = ret->next;
        
        /* faire sauter les périmés*/
        if(tmp->seq.mod_time.tv_sec+SEGTIMEOUT < current.tv_sec)
        {
            removeEntry_ipv4(tmp);
        }
    }
    
    /*not found*/
    return NULL;
}

sequence_entry * createEntry(uint32 ip_src, uint32 ip_dest, uint16 port_src, uint16 port_dst, uint32 se)
{
    /*creation si n'existe pas*/
    sequence_entry_ipv4 * ret = calloc(1,sizeof(sequence_entry_ipv4));
    
    last_header_ip = NULL;last_header_tcp = NULL;last_header_ip6 = NULL;
    
    if(ret == NULL)
    {
        perror("(segmentlib) createEntry, failed to allocate memory");
        return NULL;
    }
    
    ret->ip_src = ip_src;
    ret->ip_dest = ip_dest;
    ret->seq.port_src = port_src;
    ret->seq.port_dst = port_dst;
    ret->seq.flags = 0;
    ret->seq.count = 0;
    
    ret->next = NULL;
    ret->previous = NULL;
    ret->seq.linked_buffer = NULL;
    ret->seq.seq = se;
    
    if(gettimeofday(&ret->seq.mod_time,NULL) != 0)
    {
        perror("(segmentlib) createEntry, failed to init mod_time : ");
        free(ret);
        return NULL;
    }
    #ifdef DEBUG_MEMORY_SEG
    count_entry++;
    #endif
    
    /*ajout dans la chaine*/
    if(seq_last_ipv4 == NULL)
    {
        seq_start_ipv4 = seq_last_ipv4 = ret;
    }
    else
    {
        seq_last_ipv4->next = ret;
        ret->previous = seq_last_ipv4;
        seq_last_ipv4 = ret;
    }
    
    return &ret->seq;
}

sequence_entry_ipv6 * getEntry_ipv6(uint8 * ip_src, uint8 * ip_dest, uint16 port_src, uint16 port_dst)
{
    sequence_entry_ipv6 * ret = seq_start_ipv6, * tmp;
    struct timeval current;
    
    last_header_ip = NULL;last_header_tcp = NULL;last_header_ip6 = NULL;
    
    /*printf("(getEntry_ipv6) IP_SRC : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",ip_src[0],ip_src[1],ip_src[2],ip_src[3],ip_src[4],ip_src[5],ip_src[6],ip_src[7],ip_src[8],ip_src[9],ip_src[10],ip_src[11],ip_src[12],ip_src[13],ip_src[14],ip_src[15]);
    printf(", IP_DEST : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",ip_dest[0],ip_dest[1],ip_dest[2],ip_dest[3],ip_dest[4],ip_dest[5],ip_dest[6],ip_dest[7],ip_dest[8],ip_dest[9],ip_dest[10],ip_dest[11],ip_dest[12],ip_dest[13],ip_dest[14],ip_dest[15]);
    printf(", port_src : %u, port_dest : %u\n",port_src, port_dst);*/
    
    if(gettimeofday(&current,NULL) != 0)
    {
        perror("(segmentlib) getEntry, failed to get mod_time");
    }
    
    /*recherche dans les existants*/
    while(ret != NULL)
    {
        if(bcmp(ret->ip_src,ip_src,16) == 0 && bcmp(ret->ip_dest,ip_dest,16) == 0
        && ret->seq.port_src == port_src && ret->seq.port_dst == port_dst)
        {
            if(gettimeofday(&ret->seq.mod_time,NULL) != 0)
            {
                perror("(segmentlib) getEntry, failed to update mod_time");
            }
            
            return ret;
        }
        tmp = ret;
        ret = ret->next;
        
        /* faire sauter les périmés*/
        if(tmp->seq.mod_time.tv_sec+SEGTIMEOUT < current.tv_sec)
        {
            removeEntry_ipv6(tmp);
        }
    }
    
    /*not found*/
    return NULL;
}

sequence_entry * createEntry_ipv6(uint8 * ip_src, uint8 * ip_dest, uint16 port_src, uint16 port_dst, uint32 se)
{
    /*creation si n'existe pas*/
    sequence_entry_ipv6 * ret = calloc(1,sizeof(sequence_entry_ipv6));
    
    last_header_ip = NULL;last_header_tcp = NULL;last_header_ip6 = NULL;
    
    if(ret == NULL)
    {
        perror("(segmentlib) createEntry, failed to allocate memory");
        return NULL;
    }
    
    /*printf("(createEntry_ipv6) IP_SRC : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",ip_src[0],ip_src[1],ip_src[2],ip_src[3],ip_src[4],ip_src[5],ip_src[6],ip_src[7],ip_src[8],ip_src[9],ip_src[10],ip_src[11],ip_src[12],ip_src[13],ip_src[14],ip_src[15]);
    printf(", IP_DEST : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",ip_dest[0],ip_dest[1],ip_dest[2],ip_dest[3],ip_dest[4],ip_dest[5],ip_dest[6],ip_dest[7],ip_dest[8],ip_dest[9],ip_dest[10],ip_dest[11],ip_dest[12],ip_dest[13],ip_dest[14],ip_dest[15]);
    printf(", port_src : %u, port_dest : %u\n",port_src, port_dst);*/
    
    memcpy(ret->ip_src, ip_src, 16);
    memcpy(ret->ip_dest, ip_dest, 16);
    ret->seq.port_src = port_src;
    ret->seq.port_dst = port_dst;
    ret->seq.flags = 0;
    ret->seq.count = 0;
    
    ret->next = NULL;
    ret->previous = NULL;
    ret->seq.linked_buffer = NULL;
    ret->seq.seq = se;
    
    if(gettimeofday(&ret->seq.mod_time,NULL) != 0)
    {
        perror("(segmentlib) createEntry, failed to init mod_time : ");
        free(ret);
        return NULL;
    }
    #ifdef DEBUG_MEMORY_SEG
    count_entry++;
    #endif
    
    /*ajout dans la chaine*/
    if(seq_last_ipv6 == NULL)
    {
        seq_start_ipv6 = seq_last_ipv6 = ret;
    }
    else
    {
        seq_last_ipv6->next = ret;
        ret->previous = seq_last_ipv6;
        seq_last_ipv6 = ret;
    }
    
    return &ret->seq;
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

uint8 * forgeSegment_ipv4(sequence_entry_ipv4 * entry, next_buffer * buffer, int datalink_size)
{   
    uint8 * ret = NULL;
    sniff_ethernet *ether;
    sniff_tcp *tcp; 
    sniff_ip *ip;
    uint32 diff_seq = entry->seq.seq - buffer->seq;
    
    struct ieee80211_radiotap_header * radio;
    struct mgmt_header_t * wlan;
    struct llc_snap * llc;
            
    if(link_info.datalink_type == DLT_EN10MB)
    {
        if((ret = calloc(datalink_size + 20 + 20 + buffer->dsize - diff_seq,1)) == NULL)
        {
            perror("(segmentlib) forgeSegment, failed to allocate memory to new segment : ");
            return NULL;
        }
        
        ether = (sniff_ethernet *)ret;
        ether->ether_type = htons(ETHERNET_TYPE_IP);
    }
    else if(link_info.datalink_type == DLT_IEEE802_11_RADIO)
    {
        /*radiotap(8) + ieee802.11(24) + llc(8) + ip(20) + tcp(20)*/
        if((ret = calloc(8 + 24 + 8 + 20 + 20 + buffer->dsize - diff_seq,1)) == NULL)
        {
            perror("(segmentlib) forgeSegment, failed to allocate memory to new segment : ");
            return NULL;
        }
        
        radio = (struct ieee80211_radiotap_header *)ret;
        radio->it_version = 0;
        radio->it_pad = 0;
        radio->it_len = 8;
        radio->it_present = 0;
        
        wlan = (struct mgmt_header_t *)(ret+8);
        wlan->fc =  0x8;  /*flags(8) = 0, subtype(4) = 0, type(2) = 2 (data), version(2) = 0*/
        
     	wlan->duration = 0;
     	bzero(wlan->da,6);
     	bzero(wlan->sa,6);
        bzero(wlan->bssid,6);
     	wlan->seq_ctrl = 0;
     	
        llc = (struct llc_snap *)(ret+8+24);
        llc->dsap = 0xAA;/*indique des données*/
        llc->ssap = 0xAA;/*indique des données*/
        llc->control_field = 0x03;/*comme ça dans tous les paquets*/
        bzero(llc->organisation_code,3); /*a zero dans tous les paquets*/
        llc->type = htons(ETHERNET_TYPE_IP);
        
        link_info.header_size = datalink_size = 8+24+8;
    }
    else
    {
        fprintf(stderr,"(segmentlib) forgeSegment, link layer not managed ");
        return NULL;
    }
    
    /*ip*/
    ip = (sniff_ip*)(ret + datalink_size);
    ip->ip_vhl = 0x45;
    /*ip->ip_tos = 0;*/
    ip->ip_len = htons(20 + 20 + buffer->dsize);
    /*ip->ip_id = 0;*/
    /*ip->ip_off = 0x4000; don't fragment*/
    ip->ip_ttl = 254;
    ip->ip_p = IP_TYPE_TCP;
    /*ip->ip_sum = 0; */ /*TODO CHECKSUM to compute*/
    ip->ip_src.s_addr = entry->ip_src;
    ip->ip_dst.s_addr = entry->ip_dest;
    
    /*tcp*/
    tcp = (sniff_tcp*)(ret + datalink_size + 20);
    tcp->th_sport = htons(entry->seq.port_src);
    tcp->th_dport = htons(entry->seq.port_dst);
    tcp->th_seq = htonl(entry->seq.seq);
    /*tcp->th_ack = 0;*/
    tcp->th_offx2 = 0x50;
    /*tcp->th_flags = 0;*/ /*no flag*/
    /*tcp->th_win = 0;*/ 
    tcp->th_sum =  0; /*TODO CHECKSUM to compute*/
    /*tcp->th_urp = 0;*/
    
    /*data
    printf("DIFF SEQ : %d\n",diff_seq);*/
    memcpy(&ret[datalink_size+20+20],&buffer->data[diff_seq], buffer->dsize-diff_seq);
    
    /*printf("uin8t_t data[%u] = {",datalink_size + 40 + 20 + buffer->dsize - diff_seq);
    for(i = 0;i<(datalink_size + 40 + 20 + buffer->dsize - diff_seq);i++)
    {
        printf("0x%.2x, ",ret[i]);
    }
    printf("};\n");*/
    
    return ret;
}

uint8 * forgeSegment_ipv6(sequence_entry_ipv6 * entry, next_buffer * buffer, int datalink_size)
{
    uint8 * ret = NULL;
    sniff_ethernet *ether;
    sniff_tcp *tcp; 
    sniff_ip6 *ip6;
    uint32 diff_seq = entry->seq.seq - buffer->seq;
    
    struct ieee80211_radiotap_header * radio;
    struct mgmt_header_t * wlan;
    struct llc_snap * llc;
        
    if(link_info.datalink_type == DLT_EN10MB)
    {
        if((ret = calloc(datalink_size + 40 + 20 + buffer->dsize - diff_seq,1)) == NULL)
        {
            perror("(segmentlib) forgeSegment, failed to allocate memory to new segment : ");
            return NULL;
        }
        
        ether = (sniff_ethernet *)ret;
        ether->ether_type = htons(ETHERNET_TYPE_IP6);
    }
    else if(link_info.datalink_type == DLT_IEEE802_11_RADIO)
    {
        /*radiotap(8) + ieee802.11(24) + llc(8) + ip(40) + tcp(20)*/
        if((ret = calloc(8 + 24 + 8 + 40 + 20 + buffer->dsize - diff_seq,1)) == NULL)
        {
            perror("(segmentlib) forgeSegment, failed to allocate memory to new segment : ");
            return NULL;
        }
        
        radio = (struct ieee80211_radiotap_header *)ret;
        radio->it_version = 0;
        radio->it_pad = 0;
        radio->it_len = 8;
        radio->it_present = 0;
        
        wlan = (struct mgmt_header_t *)(ret+8);
        wlan->fc =  0x8;  /*flags(8) = 0, subtype(4) = 0, type(2) = 2 (data), version(2) = 0*/
     	wlan->duration = 0;
     	bzero(wlan->da,6);
     	bzero(wlan->sa,6);
        bzero(wlan->bssid,6);
     	wlan->seq_ctrl = 0;
     	
        llc = (struct llc_snap *)(ret+8+24);
        llc->dsap = 0xAA;/*indique des données*/
        llc->ssap = 0xAA;/*indique des données*/
        llc->control_field = 0x03;/*comme ça dans tous les paquets*/
        bzero(llc->organisation_code,3); /*a zero dans tous les paquets*/
        llc->type = htons(ETHERNET_TYPE_IP6);
        
        link_info.header_size = datalink_size = 8+24+8;
    }
    else
    {
        fprintf(stderr,"(segmentlib) forgeSegment, link layer not managed ");
        return NULL;
    }
    
    /*IPV6*/
    ip6 = (sniff_ip6*)(ret + datalink_size);
    ip6->ip_v_tc_fl[0] = 0x60;
    ip6->ip_v_tc_fl[1] = 0;
    ip6->ip_v_tc_fl[2] = 0;
    ip6->ip_v_tc_fl[3] = 0;
    ip6->ip_len = htons(20 + buffer->dsize - diff_seq); /*tcp + payload length*/
    ip6->ip_p = IP_TYPE_TCP; /*next protocol type*/
    ip6->ip_hl = 254; /*TTL*/
    memcpy(ip6->ip_src.s6_addr,entry->ip_src,16);
    memcpy(ip6->ip_dst.s6_addr,entry->ip_dest,16);
    
    /*TCP*/
    tcp = (sniff_tcp*)(ret + datalink_size + 40);
    tcp->th_sport = htons(entry->seq.port_src);
    tcp->th_dport = htons(entry->seq.port_dst);
    tcp->th_seq = htonl(entry->seq.seq);
    /*tcp->th_ack = 0;*/
    tcp->th_offx2 = 0x50;
    /*tcp->th_flags = 0;*/ /*no flag*/
    /*tcp->th_win = 0;*/ 
    tcp->th_sum =  0; /*TODO CHECKSUM to compute*/
    /*tcp->th_urp = 0;*/
    
    /*DATA*/
    memcpy(&ret[datalink_size+40+20],&buffer->data[diff_seq], buffer->dsize-diff_seq);    
    return ret;
}

void flushAllSegment()
{
    sequence_entry_ipv4 * tmp_ipv4;
    sequence_entry_ipv6 * tmp_ipv6;
    next_buffer * nb_tmp1, * nb_tmp2;
    
    /*recherche dans les existants*/
    while(seq_start_ipv4 != NULL)
    {
        tmp_ipv4 = seq_start_ipv4;
        seq_start_ipv4 = seq_start_ipv4->next;
        
        nb_tmp1 = tmp_ipv4->seq.linked_buffer;
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
        free(tmp_ipv4);
    }
    seq_start_ipv4 = seq_last_ipv4 = NULL;
    
    /*recherche dans les existants*/
    while(seq_start_ipv6 != NULL)
    {
        tmp_ipv6 = seq_start_ipv6;
        seq_start_ipv6 = seq_start_ipv6->next;
        
        nb_tmp1 = tmp_ipv6->seq.linked_buffer;
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
        free(tmp_ipv6);
    }
    seq_start_ipv6 = seq_last_ipv6 = NULL;
}

void removeEntry_ipv4(sequence_entry_ipv4 * entry)
{
    next_buffer * nb_tmp1, * nb_tmp2;
    
    if(entry->previous == NULL)
    {
        seq_start_ipv4 = entry->next;
        
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
        seq_last_ipv4 = entry->previous;
        
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
    
    nb_tmp1 = entry->seq.linked_buffer;
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

void removeEntry_ipv6(sequence_entry_ipv6 * entry)
{
    next_buffer * nb_tmp1, * nb_tmp2;
    
    if(entry->previous == NULL)
    {
        seq_start_ipv6 = entry->next;
        
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
        seq_last_ipv6 = entry->previous;
        
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
    
    nb_tmp1 = entry->seq.linked_buffer;
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

int addNewSegment_ipv4(sniff_tcp * header_tcp, sniff_ip * header_ip, const uint8 * datas)
{
    uint32 new_seq;
    sequence_entry_ipv4 * seq_entry_ipv4;
    sequence_entry * seq_entry;
    unsigned int header_ip_size = IP4_HL(header_ip)*4; /*TODO deja calculé dans la fonction appelante*/
    unsigned int segment_size = ntohs(header_ip->ip_len)-header_ip_size; /*TODO deja calculé dans la fonction appelante*/
    
    if( (header_tcp->th_flags & TH_SYN) ||  (header_tcp->th_flags & TH_FIN))
    {
        new_seq = 1 + ntohl(header_tcp->th_seq) + ntohs(header_ip->ip_len) - header_ip_size - TH_OFF(header_tcp)*4;
    }
    else
    {
        new_seq = ntohl(header_tcp->th_seq) + ntohs(header_ip->ip_len) - header_ip_size - TH_OFF(header_tcp)*4;
    }

    /*verification de sequence*/
    if((seq_entry_ipv4 = getEntry(header_ip->ip_src.s_addr,header_ip->ip_dst.s_addr,ntohs(header_tcp->th_sport),ntohs(header_tcp->th_dport))) == NULL)
    {     
        #ifdef PRINT_TCP   
        printf("(structlib) checkTCP, new seq : %u\n",ntohl(header_tcp->th_seq));
        #endif

        if((seq_entry = createEntry(header_ip->ip_src.s_addr,header_ip->ip_dst.s_addr,ntohs(header_tcp->th_sport),ntohs(header_tcp->th_dport),new_seq)) == NULL)
        {
            fprintf(stderr,"(structlib) checkTCP, failed to create a new tcp entry\n");
            return -1;
        }
        else
        {
            /*printf("set new seq %u (1)\n",new_seq);*/
            /*if(paquet_size - TH_OFF(header_tcp)*4 <= 0) pas de traitement supplementaire si le paquet est vide
            {
                printf("tcp drop empty segment\n");
                return 1;
            }*/
            /*nouveau flux, on forward*/
            #ifdef PRINT_TCP
            printf("(structlib) checkTCP, tcp forward\n");
            #endif
            return 0;
        }
    }
    else
    {
        seq_entry = &seq_entry_ipv4->seq;
        
        #ifdef PRINT_TCP
            printf("(structlib) checkTCP, waited seq : %u, receive seq %u\n",seq_entry->seq,ntohl(header_tcp->th_seq));
        #endif
        
        /*flux tcp brisé, on drop*/
        if(seq_entry->flags & SEG_FLAGS_BROKEN)
        {
            #if defined(PRINT_DROP)
            printf("(structlib) checkTCP, tcp broken\n");
            #endif
            
            return -1;
        }
    }
    

    /*if(paquet_size - TH_OFF(header_tcp)*4 <= 0) pas de traitement supplementaire si le paquet est vide
    {
        printf("tcp drop empty segment\n");
        return 1;
    }*/
    
    if(ntohl(header_tcp->th_seq) == seq_entry->seq)
    {/*un segment qui suit, on forwarde*/
        #ifdef PRINT_TCP
        printf("(structlib) checkTCP, tcp forward\n");
        #endif
        /*printf("set new seq %u (2), old seq : %u\n",new_seq,ntohl(header_tcp->th_seq));*/
        seq_entry->seq = new_seq;
        return 0;
    }
    else if (ntohl(header_tcp->th_seq) > seq_entry->seq)
    {/*le segment est trop loin, inversion probable, on bufferise*/
        
        #if defined(PRINT_TCP) || defined(PRINT_DROP)
        printf("(ipv4) waited seq : %u, receive seq %u\n",seq_entry->seq,ntohl(header_tcp->th_seq));
        printf("(structlib) checkTCP, tcp bufferise\n");
        #endif
        /*le flux tcp est probablement brisé*/
        if(seq_entry->count >= SEGMAXBUFFBYSOCK)
        {
            /*printf("maybe tcp broken : %lx\n",(unsigned long)seq_entry);*/
            seq_entry->flags |= SEG_FLAGS_BROKEN;
            cleanData(seq_entry);
            return -1;
        }
        addData(seq_entry,ntohl(header_tcp->th_seq),&datas[link_info.header_size + header_ip_size + TH_OFF(header_tcp)*4],segment_size-TH_OFF(header_tcp)*4);
        return -1;
    }
    /*data duplicate*/
    else /* if(ntohl(header_tcp->th_seq) <  seq_entry->seq)*/
    {
        #if defined(PRINT_TCP) || defined(PRINT_DROP)
        printf("(structlib) checkTCP, tcp duplicate data, drop\n");
        #endif
        
        /*TODO*/
        
        if(new_seq >  seq_entry->seq)
        {
            printf("!!!!! WARNING OVERLAP WITH LOSE !!!!!, waited seq : %u, received seq : %u, new received seq : %u\n",seq_entry->seq,ntohl(header_tcp->th_seq),new_seq);
        }
        
        return -1;
    }
}

int addNewSegment_ipv6(sniff_tcp * header_tcp, sniff_ip6 * header_ip6, const uint8 * datas)
{
    uint32 new_seq;
    sequence_entry_ipv6 * seq_entry_ipv6;
    sequence_entry * seq_entry;
    
    unsigned int segment_size = ntohs(header_ip6->ip_len); /*TODO deja calculé dans la fonction appelante*/
    
    if( (header_tcp->th_flags & TH_SYN) ||  (header_tcp->th_flags & TH_FIN))
    {
        new_seq = 1 + ntohl(header_tcp->th_seq) + ntohs(header_ip6->ip_len) - TH_OFF(header_tcp)*4;
    }
    else
    {
        new_seq = ntohl(header_tcp->th_seq) + ntohs(header_ip6->ip_len) - TH_OFF(header_tcp)*4;
    }

    /*verification de sequence*/
    if((seq_entry_ipv6 = getEntry_ipv6(header_ip6->ip_src.s6_addr,header_ip6->ip_dst.s6_addr,ntohs(header_tcp->th_sport),ntohs(header_tcp->th_dport))) == NULL)
    {     
        #ifdef PRINT_TCP   
        printf("(structlib) checkTCP_ipv6, new seq : %u\n",ntohl(header_tcp->th_seq));
        #endif

        if((seq_entry = createEntry_ipv6(header_ip6->ip_src.s6_addr,header_ip6->ip_dst.s6_addr,ntohs(header_tcp->th_sport),ntohs(header_tcp->th_dport),new_seq)) == NULL)
        {
            fprintf(stderr,"(structlib) checkTCP_ipv6, failed to create a new tcp entry\n");
            return -1;
        }
        else
        {
            /*if(paquet_size - TH_OFF(header_tcp)*4 <= 0) pas de traitement supplementaire si le paquet est vide
            {
                printf("tcp drop empty segment\n");
                return 1;
            }*/
            /*nouveau flux, on forward*/
            #ifdef PRINT_TCP
            printf("(structlib) checkTCP_ipv6, tcp forward\n");
            #endif
            return 0;
        }
    }
    else
    {
        seq_entry = &seq_entry_ipv6->seq;

        #ifdef PRINT_TCP
            printf("(structlib) checkTCP_ipv6, waited seq : %u, receive seq %u\n",seq_entry->seq,ntohl(header_tcp->th_seq));
        #endif

        /*flux tcp brisé, on drop*/
        if(seq_entry->flags & SEG_FLAGS_BROKEN)
        {
            #if defined(PRINT_DROP) || defined(PRINT_TCP)
            printf("(structlib) checkTCP_ipv6, tcp broken\n");
            #endif

            return -1;
        }
    }


    /*if(paquet_size - TH_OFF(header_tcp)*4 <= 0) pas de traitement supplementaire si le paquet est vide
    {
        printf("tcp drop empty segment\n");
        return 1;
    }*/

    if(ntohl(header_tcp->th_seq) == seq_entry->seq)
    {/*un segment qui suit, on forwarde*/
        #ifdef PRINT_TCP
        printf("(structlib) checkTCP_ipv6, tcp forward\n");
        #endif
        seq_entry->seq = new_seq;
        return 0;
    }
    else if (ntohl(header_tcp->th_seq) > seq_entry->seq)
    {/*le segment est trop loin, inversion probable, on bufferise*/
        printf("(IPV6) waited seq : %u, receive seq %u\n",seq_entry->seq,ntohl(header_tcp->th_seq));
        #if defined(PRINT_TCP) || defined(PRINT_DROP)
        printf("(structlib) checkTCP_ipv6, tcp bufferise\n");
        #endif
        /*le flux tcp est probablement brisé*/
        if(seq_entry->count >= SEGMAXBUFFBYSOCK)
        {
            #if defined(PRINT_TCP) || defined(PRINT_DROP)
            printf("maybe tcp broken : %u\n",seq_entry->seq);
            #endif
            seq_entry->flags |= SEG_FLAGS_BROKEN;
            cleanData(seq_entry);
            return -1;
        }
        addData(seq_entry,ntohl(header_tcp->th_seq),&datas[link_info.header_size + HL_IP6 + TH_OFF(header_tcp)*4],segment_size-TH_OFF(header_tcp)*4);
        return -1;
    }
    /*data duplicate*/
    else /* if(ntohl(header_tcp->th_seq) <  seq_entry->seq)*/
    {
        #if defined(PRINT_TCP) || defined(PRINT_DROP)
        printf("(structlib) checkTCP_ipv6, tcp duplicate data\n");
        #endif
        
        /*TODO*/
        
        if(new_seq >  seq_entry->seq)
        {
            printf("!!!!! WARNING OVERLAP WITH LOSE !!!!!, waited seq : %u, received seq : %u, new received seq : %u\n",seq_entry->seq,ntohl(header_tcp->th_seq),new_seq);
        }
        
        return -1;
    }
}

void sendReadySegment_ipv4(sniff_tcp * tcp, sniff_ip * ip, struct timeval t)
{
    sequence_entry_ipv4 * seq_entry_ipv4;
    sequence_entry * seq_entry;
    next_buffer * buff_tmp;
    uint8 * tmp;
    
    if(ip != NULL && ip->ip_p == IP_TYPE_TCP && (seq_entry_ipv4 = getEntry(ip->ip_src.s_addr,ip->ip_dst.s_addr,ntohs(tcp->th_sport),ntohs(tcp->th_dport))) != NULL)
    {
        seq_entry = &seq_entry_ipv4->seq;
    }
    else
    {
        return;
    }
    
    while(seq_entry->linked_buffer != NULL && seq_entry->linked_buffer->seq <= seq_entry->seq)
    {
        if(seq_entry->linked_buffer->seq + seq_entry->linked_buffer->dsize-1 > seq_entry->seq)
        {
            #ifdef PRINT_TCP
            printf("SEND FORGED, seq = %u\n",seq_entry->linked_buffer->seq);
            printf("\nSEND forged packet\n");
            #endif
            
            /*forge segment*/
            tmp = forgeSegment_ipv4(seq_entry_ipv4, seq_entry->linked_buffer,link_info.header_size); /*TODO check if error*/
            ip = (sniff_ip*)(tmp + link_info.header_size);
            
            #ifdef PRINT_IP
            printf("(dispatch) forge packet : ip.size : %d, ip_len : %d, ip.src :  %s",IP4_HL(ip), ntohs(ip->ip_len), inet_ntoa(ip->ip_src));
            printf(", ip.dst : %s\n",inet_ntoa(ip->ip_dst));
            #endif
            
            /*send segment*/
            sendToAllNode(tmp,ntohs(ip->ip_len)+link_info.header_size,t);
            tcp = (sniff_tcp*)(tmp + link_info.header_size + 20);
            
            #ifdef PRINT_TCP
                printf("tcp.src : %u, tcp.dst : %u, tcp.seq : %u, tcp.ack %u", ntohs(tcp->th_sport), ntohs(tcp->th_dport),ntohl(tcp->th_seq),ntohl(tcp->th_ack));
                printf(", tpc header size (word 32 bits) : %u, payload : %u\n",TH_OFF(tcp), htons(ip->ip_len) - 20 - TH_OFF(tcp)*4);
            #endif
            
            free(tmp);
            /*on met a jour le prochain numero de sequence attendu*/
            seq_entry->seq = seq_entry->linked_buffer->seq + seq_entry->linked_buffer->dsize;     
        }
        
        #ifdef PRINT_TCP
        printf("old seq : %u new seq =  %u + %u \n",seq_entry->seq,seq_entry->linked_buffer->seq,seq_entry->linked_buffer->dsize );
        #endif

        /*on retire le buffer qu'on vient d'utiliser de la liste*/
        buff_tmp = seq_entry->linked_buffer;
        seq_entry->linked_buffer = seq_entry->linked_buffer->next_buffer;
        seq_entry->count--;
        
        /*free le buffer*/
        free(buff_tmp->data);
        free(buff_tmp);
        #ifdef DEBUG_MEMORY_SEG
        cont_buffer--;
        #endif
        
        /*set NULL previous on new first buffer*/
        if(seq_entry->linked_buffer != NULL)
        {
            seq_entry->linked_buffer->previous_buffer = NULL;
        }
    }
    
    /*suppression en cas de fin de flux*/
    if( tcp->th_flags&TH_FIN )
    {
        if(seq_entry->linked_buffer == NULL)
        {
            removeEntry_ipv4(seq_entry_ipv4);
        }
        else
        {
            seq_entry->flags |= SEG_FLAGS_END;
        }
    }
    /*un flux marqué comme fini et sans données supplémentaires est retiré*/
    else if(seq_entry->flags & SEG_FLAGS_END && seq_entry->linked_buffer == NULL)
    {
        removeEntry_ipv4(seq_entry_ipv4);
    }
}

void sendReadySegment_ipv6(sniff_tcp * tcp, sniff_ip6 * ip6, struct timeval t)
{
    sequence_entry_ipv6 * seq_entry_ipv6;
    sequence_entry * seq_entry;
    next_buffer * buff_tmp;
    uint8 * tmp;
    
    if(ip6 != NULL && ip6->ip_p == IP_TYPE_TCP && (seq_entry_ipv6 = getEntry_ipv6(ip6->ip_src.s6_addr,ip6->ip_dst.s6_addr,ntohs(tcp->th_sport),ntohs(tcp->th_dport))) != NULL)
    {
        seq_entry = &seq_entry_ipv6->seq;
    }
    else
    {
        return;
    }
    
    while(seq_entry->linked_buffer != NULL && seq_entry->linked_buffer->seq <= seq_entry->seq)
    {
        if(seq_entry->linked_buffer->seq + seq_entry->linked_buffer->dsize-1 > seq_entry->seq)
        {
            #ifdef PRINT_TCP
            printf("\nSEND forged packet\n");
            #endif
            
            /*forge segment*/
            tmp = forgeSegment_ipv6(seq_entry_ipv6, seq_entry->linked_buffer,link_info.header_size); /*TODO check if error*/
            ip6 = (sniff_ip6*)(tmp + link_info.header_size);
            #ifdef PRINT_IP
            printf("(dispatch) forge packet : ip_len : %d, ip.src : ",ntohs(ip6->ip_len));printIPV6(&ip6->ip_src);
            printf(", ip.dst : ");printIPV6(&ip6->ip_dst);
            #endif
            
            /*send segment*/
            sendToAllNode(tmp,ntohs(ip6->ip_len)+40+link_info.header_size,t);
            
            tcp = (sniff_tcp*)(tmp + link_info.header_size + 40);
            
            #ifdef PRINT_TCP
                printf("tcp.src : %u, tcp.dst : %u, tcp.seq : %u, tcp.ack %u", ntohs(tcp->th_sport), ntohs(tcp->th_dport),ntohl(tcp->th_seq),ntohl(tcp->th_ack));
                printf(", tpc header size (word 32 bits) : %u, payload : %u\n",TH_OFF(tcp), htons(ip6->ip_len) - TH_OFF(tcp)*4);
            #endif        
            
            free(tmp);
            /*on met a jour le prochain numero de sequence attendu*/
            seq_entry->seq = seq_entry->linked_buffer->seq + seq_entry->linked_buffer->dsize;     
        }
        #ifdef PRINT_TCP
        printf("old seq : %u new seq =  %u + %u \n",seq_entry->seq,seq_entry->linked_buffer->seq,seq_entry->linked_buffer->dsize );
        #endif

        /*on retire le buffer qu'on vient d'utiliser de la liste*/
        buff_tmp = seq_entry->linked_buffer;
        seq_entry->linked_buffer = seq_entry->linked_buffer->next_buffer;
        seq_entry->count--;
        
        /*free le buffer*/
        free(buff_tmp->data);
        free(buff_tmp);
        #ifdef DEBUG_MEMORY_SEG
        cont_buffer--;
        #endif
        
        /*set NULL previous on new first buffer*/
        if(seq_entry->linked_buffer != NULL)
        {
            seq_entry->linked_buffer->previous_buffer = NULL;
        }
    }
    
    /*suppression en cas de fin de flux*/
    if( tcp->th_flags&TH_FIN )
    {
        if(seq_entry->linked_buffer == NULL)
        {
            removeEntry_ipv6(seq_entry_ipv6);
        }
        else
        {
            seq_entry->flags |= SEG_FLAGS_END;
        }
    }
    /*un flux marqué comme fini et sans données supplémentaires est retiré*/
    else if(seq_entry->flags & SEG_FLAGS_END && seq_entry->linked_buffer == NULL)
    {
        removeEntry_ipv6(seq_entry_ipv6);
    }
}

void setIPv4TCP(sniff_ip * ip, sniff_tcp * tcp)
{
    last_header_ip = ip;
    last_header_tcp = tcp;
    last_header_ip6 = NULL;
}

void setIPv6TCP(sniff_ip6 * ip, sniff_tcp * tcp)
{
    last_header_ip = NULL;
    last_header_tcp = tcp;
    last_header_ip6 = ip;
}

void forwardSegmentInBuffer(struct timeval t)
{
    if(last_header_tcp != NULL)
    {
        if(last_header_ip != NULL)
        {
            sendReadySegment_ipv4(last_header_tcp,last_header_ip, t);
        }
        else if(last_header_ip6 != NULL)
        {
            sendReadySegment_ipv6(last_header_tcp,last_header_ip6, t);
        }
    }
} 




