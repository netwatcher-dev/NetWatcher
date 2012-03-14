#include "structlib.h"

int checkETHERNET(sniff_ethernet * header_ethernet,const uint8 * datas, int data_length)
{
    #ifdef PRINT_ETHERNET
    printf("type prot ethernet : %x\n",ntohs(header_ethernet->ether_type));
    #endif
    
    return 0;
}

int checkIPV4(sniff_ip * header_ip,const uint8 * datas, int data_length,struct ifaddrs *ifp)
{
    uint8 buffer[100];
    uint16 checksum;
    int size_ip = IP4_HL(header_ip)*4;
    struct ifaddrs *ifp_tmp;
    
    if (size_ip < 20) 
    {
    	fprintf(stderr,"   * Invalid IP header length: %u bytes\n", size_ip);
    	return -1;
    }
    
#ifdef PRINT_IP
    printf("(structlib) checkIPV4, ip.size : %d, ip.src :  %s",IP4_HL(header_ip), inet_ntoa(header_ip->ip_src));
    printf(", ip.dst : %s, ip.ip_len %u",inet_ntoa(header_ip->ip_dst), ntohs(header_ip->ip_len));
#endif
    
    /*check data_length*/
    if(data_length < (link_info.header_size + ntohs(header_ip->ip_len)))
    {
        #if defined(PRINT_IP) || defined(PRINT_DROP)
        printf("(structlib) checkIPV4, too short packet\n");
        #endif
        return -1;
    }
    
    if(link_info.frame_max_size < ntohs(header_ip->ip_len))
    {
        #if defined(PRINT_IP) || defined(PRINT_DROP)
        printf("(structlib) checkIPV4, too big packet\n");
        #endif
        return -1;
    }
    
    /*on copie le paquet ip et on met le checksum à zero*/
    bzero(buffer,100);        
    memcpy(buffer, &datas[link_info.header_size], size_ip);
    buffer[10] = 0;
    buffer[11] = 0;
    
    checksum = cksum2(0,buffer,size_ip);

#ifdef PRINT_IP
    printf(", checksum ip : original %x vs %x\n",ntohs(header_ip->ip_sum),checksum);
#endif
	
	/*check checksum ip*/
	if(ntohs(header_ip->ip_sum) != checksum)
	{
        ifp_tmp = ifp;
        while(ifp_tmp != NULL)
        {
            if (ifp_tmp->ifa_addr->sa_family == AF_INET) /*WARNING : only ipv4*/
            {   
                if( ((struct sockaddr_in *)  ifp_tmp->ifa_addr)->sin_addr.s_addr == header_ip->ip_src.s_addr)
                {
                    return 1;
                }
            }
            ifp_tmp = ifp_tmp->ifa_next;
        }
        
        #if defined(PRINT_IP) || defined(PRINT_DROP)
        printf("packet ip checksum invalid\n");
        #endif
        
        return -1;
	}
    return 0;
}

int checkTCP(sniff_tcp * header_tcp,const uint8 * datas, int data_length, sniff_ip * header_ip, int local_source)
{
    uint8 buffer[1600];/*TODO il y a moyen de se passer ce tableau pour faire les calculs*/
    uint16 checksum;
#ifndef NO_RESEQ
    uint32 new_seq;
    sequence_entry * seq_entry;
#endif
    pseudo_entete_ip pe_ip;
    unsigned int header_ip_size = IP4_HL(header_ip)*4, segment_size;
    
    
    segment_size = ntohs(header_ip->ip_len)-header_ip_size;

#ifdef PRINT_TCP
    printf("tcp.src : %u, tcp.dst : %u, tcp.seq : %u, tcp.ack %u", ntohs(header_tcp->th_sport), ntohs(header_tcp->th_dport),ntohl(header_tcp->th_seq),ntohl(header_tcp->th_ack));
    printf(", tpc header size (word 32 bits) : %u, payload : %u",TH_OFF(header_tcp), segment_size - TH_OFF(header_tcp)*4);
#endif

    /*check checksum tcp*/
    bzero(buffer,1600);        
    /*pseudo header*/
    pe_ip.ip_source = header_ip->ip_src.s_addr;
    pe_ip.ip_destination = header_ip->ip_dst.s_addr;
    pe_ip.mbz = 0; /*doit toujours etre a zero*/
    pe_ip.type = header_ip->ip_p;
    pe_ip.length = htons(segment_size);/*TODO check this, le htons est il necessaire?*/
    memcpy(buffer, &pe_ip, 12);
    memcpy(&buffer[12], &datas[link_info.header_size+header_ip_size], segment_size);

    /*on met le checksum a zero 12+16 et 12+17*/
    buffer[28] = 0;
    buffer[29] = 0;

    if(segment_size % 2 == 0)
    {
        checksum = cksum2(0,buffer,12+segment_size);
    }
    else
    {
        checksum = cksum2(0,buffer,12+segment_size+1);
    }

#ifdef PRINT_TCP
    printf(", tcp checksum %x vs %x\n", ntohs(header_tcp->th_sum),checksum);
#endif

    if(ntohs(header_tcp->th_sum) != checksum)
    {
        /*TEST tcp offload*/
        if(!local_source)
        {
            #if defined(PRINT_TCP) || defined(PRINT_DROP)
            printf("packet tcp corrupted : drop\n");
            #endif

            return -1;
        }
    }
    
#ifndef NO_RESEQ
    if( (header_tcp->th_flags & TH_SYN) ||  (header_tcp->th_flags & TH_FIN)) 
    {
        new_seq = 1 + ntohl(header_tcp->th_seq) + ntohs(header_ip->ip_len) - header_ip_size - TH_OFF(header_tcp)*4;
    }
    else
    {
        new_seq = ntohl(header_tcp->th_seq) + ntohs(header_ip->ip_len) - header_ip_size - TH_OFF(header_tcp)*4;
    }


    /*verification de sequence*/
    if((seq_entry = getEntry(header_ip->ip_src.s_addr,header_ip->ip_dst.s_addr,ntohs(header_tcp->th_sport),ntohs(header_tcp->th_dport))) == NULL)
    {     
        #ifdef PRINT_TCP   
        printf("new seq : %u\n",ntohl(header_tcp->th_seq));
        #endif

        if((seq_entry = createEntry(header_ip->ip_src.s_addr,header_ip->ip_dst.s_addr,ntohs(header_tcp->th_sport),ntohs(header_tcp->th_dport),new_seq)) == NULL)
        {
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
            printf("tcp forward\n");
            #endif
            return 0;
        }
    }
    else
    {
        /*flux tcp brisé, on drop*/
        if(seq_entry->flags & SEG_FLAGS_BROKEN)
        {
            return -1;
        }
    }
    
    #ifdef PRINT_TCP
    else
    {
        printf("waited seq : %u, receive seq %u\n",seq_entry->seq,ntohl(header_tcp->th_seq));
    }
    #endif

    /*if(paquet_size - TH_OFF(header_tcp)*4 <= 0) pas de traitement supplementaire si le paquet est vide
    {
        printf("tcp drop empty segment\n");
        return 1;
    }*/
    
    if(ntohl(header_tcp->th_seq) == seq_entry->seq)
    {/*un segment qui suit, on forwarde*/
        #ifdef PRINT_TCP
        printf("tcp forward\n");
        #endif
        seq_entry->seq = new_seq;
        return 0;
    }
    else if (ntohl(header_tcp->th_seq) > seq_entry->seq)
    {/*le segment est trop loin, inversion probable, on bufferise*/
        #if defined(PRINT_TCP) || defined(PRINT_DROP)
        printf("tcp bufferise\n");
        #endif
        
        /*le flux tcp est probablement brisé*/
        if(seq_entry->count >= SEGMAXBUFFBYSOCK)
        {
            printf("maybe tcp broken : %lx",(unsigned long)seq_entry);
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
        printf("tcp duplicate data\n");
        #endif
        return -1;
    }
#endif
    return 0;
}

/* http://www.roman10.net/how-to-calculate-iptcpudp-checksumpart-2-implementation/ */
int checkUDP(sniff_ip * header_ip, uint16 * packet, int local_source)
{
	uint32 sum = 0;
	int size_ip = IP4_HL(header_ip)*4;
	sniff_udp *header_udp = (sniff_udp*)(packet + link_info.header_size/2 + size_ip/2); 
	uint16* ip_payload = (uint16 *)(packet + link_info.header_size/2 + size_ip/2);
	short len = htons(header_udp->uh_len);
	uint16 checksum = header_udp->uh_sum;
	
	/* Adding ip src & dst  */
	sum += (header_ip->ip_src.s_addr>>16)&0xFFFF;
	sum += (header_ip->ip_src.s_addr)&0xFFFF;
	sum += (header_ip->ip_dst.s_addr>>16)&0xFFFF;
	sum += (header_ip->ip_dst.s_addr)&0xFFFF;
	
	sum += htons(17);
	sum += header_udp->uh_len;
	
	header_udp->uh_sum = 0; /* Set to 0 for the computation */
	 
	if(cksum(sum,ip_payload,len) == checksum) /* TODO essayer de faire un fonction cksum pour IP TCP UDP v4 */
    {   
        header_udp->uh_sum = checksum; /* Set the previous value, just in case */
		return 0;
    }
	else
	{
	    /*TEST tcp offload*/
        if(local_source)
        {
            return 1;
        }
	}
	return -1;
}

uint16 cksum(uint32 sum, uint16 *ip, int len)
{


    while(len > 1)
    {
        sum += *(ip)++;
        if(sum & 0x80000000)   /* if high order bit set, fold */
        {
               sum = (sum & 0xFFFF) + (sum >> 16);
        }
        len -= 2;
    }

    if(len)       /* take care of left over byte */
        sum += ((*ip)&htons(0xFF00));

    while(sum>>16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

uint16 cksum2(uint32 sum ,uint8 * bytes, int len)
{
    /*unsigned long sum = 0;   assume 32 bit long, 16 bit short */
    uint16 word16 = 0;

    while(len > 1)
    {
        word16 = ((*bytes++ << 8) &0xFF00);
        word16 += (*bytes++ & 0xFF);
        sum += word16;
        if(sum & 0x80000000)   /* if high order bit set, fold */
        {
               sum = (sum & 0xFFFF) + (sum >> 16);
        }
        len -= 2;
    }
    while(sum>>16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}