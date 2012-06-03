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

#include "structlib.h"

datalink_check datalink_check_function_plop[DATALINK_MANAGED] = 
{
    {DLT_EN10MB    ,14,1500,0,checkETHERNET},
    {DLT_IEEE802_11_RADIO,57,2373,0,checkIEEE80211},
    
    /*Add new datalink protocole here*/
    
    {-1,0,0,0,checkDatalinkDefault}
};
network_check network_check_function[NETWORK_MANAGED] =
{
    {ETHERNET_TYPE_IP,checkIPV4,
        {
            {0x06,checkTCP},
            {0x11,checkUDP},
            
            /*Add new transport protocole here*/
            
            {-1,checkTransportlinkDefault}
        }},
        
    {ETHERNET_TYPE_IP6,checkIPV6 ,
        {
            {0x06,checkTCP_ipv6},
            {0x11,checkUDP_ipv6},
            
            /*AND add new transport protocole also here*/
            
            {-1,checkTransportlinkDefault}
        }},
        
    /*Add new network protocole here*/
        
    {-1,checkNetworklinkDefault,
        {
            {-1,checkTransportlinkDefault},
            {-1,checkTransportlinkDefault},
            {-1,checkTransportlinkDefault}
        }}
};

int checkETHERNET(const uint8 * datas, int data_length, int * encapslated_protocol)
{
    sniff_ethernet * header_ethernet = (sniff_ethernet *)datas;
    
    #ifdef PRINT_ETHERNET
    printf("(structlib) checkETHERNET, type prot ethernet : %x\n",ntohs(header_ethernet->ether_type));
    #endif
    
    /*check length*/
    if(data_length < 14)
    {
        #if defined(PRINT_DROP) || defined(PRINT_ETHERNET)
        printf("(structlib) checkETHERNET, ip packet is too shot\n");
        #endif
        
        *encapslated_protocol = -1;
        
        return -1;
    }
    
    *encapslated_protocol = ntohs(header_ethernet->ether_type);
    /*CHECK IPV4/IPV6*/
    /*if(ntohs(header_ethernet->ether_type) == ETHERNET_TYPE_IP)
    {
        if(data_length < link_info.header_size + 20)
        {
            #if defined(PRINT_IP) || defined(PRINT_DROP) || defined(PRINT_ETHERNET)
            printf("(structlib) checkETHERNET, ip packet is too shot\n");
            #endif
            return -1;
        }
    }
    else if(ntohs(header_ethernet->ether_type) == ETHERNET_TYPE_IP6)
    {
        if(data_length < link_info.header_size + 40)
        {
            #if defined(PRINT_IP) || defined(PRINT_DROP) || defined(PRINT_ETHERNET)
            printf("(structlib) checkETHERNET, ip packet is too shot\n");
            #endif
            return -1;
        }
    }
    else
    {
        #if defined(PRINT_ETHERNET) || defined(PRINT_DROP) || defined(PRINT_ETHERNET)
        printf("(structlib) checkETHERNET, not an ip(v4/v6) drop : ");
        printEthernetType(ntohs(header_ethernet->ether_type));
        #endif
        
        return -1;
    }*/
    
    return 0;
}

int checkIEEE80211(const uint8 * datas, int data_length, int * encapslated_protocol)
{
    struct llc_snap * llc; /*IN BIG ENDIAN*/
    struct mgmt_header_t * ieee; /*IN LITTLE ENDIAN*/
    struct ieee80211_radiotap_header * ieee_radio = (struct ieee80211_radiotap_header *)datas; /*IN LITTLE ENDIAN*/
    /*sniff_ip * header_ip; IN BIG ENDIAN*/
    /*sniff_ip6 * header_ip6; IN BIG ENDIAN*/
    
    *encapslated_protocol = -1;
    
    /*check ieee_radio length*/
    if(data_length < 8)
    {
        #if defined(PRINT_IEE80211) || defined(PRINT_DROP)
        printf("(structlib) checkIEEE80211, invalid radiotap header length: %u bytes, wait at least 8 bytes, drop\n", data_length);
        #endif
        
        return -1;
    }
    
    /*CHECK HEADER LENGTH*/
    if(data_length < (ieee_radio->it_len+32)) /*radiotap + 802.11 + llc-snap*/
    {
        #if defined(PRINT_IEE80211) || defined(PRINT_DROP)
        printf("(structlib) checkIEEE80211, too short packet to contain data: %u bytes, wait at least %d bytes, drop\n", data_length,ieee_radio->it_len+32);
        #endif
        
        return -1;
    }

    ieee = (struct mgmt_header_t *)&datas[ieee_radio->it_len];

    #if defined(PRINT_IEE80211)
        printf("(structlib) checkIEEE80211, vers=%u, header_size=%u vs %u, it_present=%u",ieee_radio->it_version,ieee_radio->it_len,data_length, ieee_radio->it_present);
        printf(", ver=%u, type=%u, subtype=%u\n", FC_VERSION(ieee->fc),FC_TYPE(ieee->fc),FC_SUBTYPE(ieee->fc));
    #endif

    /*CHECK IEE802.11 FRAME CONTROL*/
    if(FC_VERSION(ieee->fc) != 0 || FC_TYPE(ieee->fc) != 2 /*|| FC_SUBTYPE(ieee->fc) != 0*/)
    {
        #if defined(PRINT_IEE80211) || defined(PRINT_DROP)
        printf("(structlib) checkIEEE80211, not data carried\n");
        #endif
        
        return -1;
    }

    /*CHECK IEEE80211 FLAG*/
    if(ieee->fc & 0x7400) /*no wep, no more data, no power_mgmt, no_more flag*/
    {
        if(FC_MORE_FLAG(ieee->fc))
        {
            printf("MORE\n");
        }
        else if(FC_POWER_MGMT(ieee->fc))
        {
            printf("POWER\n");
        }
        else if(FC_MORE_DATA(ieee->fc))
        {
            printf("MORE DATA\n");
        }
        
        #if defined(PRINT_IEE80211) || defined(PRINT_DROP)
        printf("(structlib) checkIEEE80211, flags wep, more data, power_mgmt, more_frag are not manager, drop\n");
        #endif
        
        return -1;
    }
    
    if( (FC_TO_DS(ieee->fc) && FC_FROM_DS(ieee->fc)) ||  ((FC_TO_DS(ieee->fc)==0 && FC_FROM_DS(ieee->fc)==0)) )/*no ad'hoc or wds*/
    {
        #if defined(PRINT_IEE80211) || defined(PRINT_DROP)
        printf("(structlib) checkIEEE80211, ad'hoc and wds ar not manager, drop\n");
        #endif
        
        return -1;
    }
    
    /*Si le Qos est present, on a 2 bytes en +*/
    if(DATA_FRAME_IS_QOS(FC_SUBTYPE(ieee->fc)))
    {
        llc = (struct llc_snap *)&datas[ieee_radio->it_len+sizeof(struct mgmt_header_t) + 2];
        link_info.header_size = ieee_radio->it_len+34; /*24 + 2 + 8 : ieee + qos + llc*/
    }
    else
    {
        llc = (struct llc_snap *)&datas[ieee_radio->it_len+sizeof(struct mgmt_header_t)];
        link_info.header_size = ieee_radio->it_len+32; /*24 + 8 : iee + llc*/
    }
    
/*CHECK LLC*/
    
    if(llc->dsap != 0xAA && llc->ssap != 0xAA)
    {
        #if defined(PRINT_IEE80211) || defined(PRINT_DROP)
        printf("(structlib) checkIEEE80211, not a LLC SNAP encapsulation, drop\n");
        #endif
        
        return -1;
    }
    
/*CHECK IPV4/IPV6 type*/
    /*if(ntohs(llc->type) == ETHERNET_TYPE_IP)
    {
        if(data_length < link_info.header_size + 20)
        {
            #if defined(PRINT_IP) || defined(PRINT_DROP) || defined(PRINT_IEE80211)
            printf("(structlib) checkIEEE80211, ip packet is too shot\n");
            #endif
            return -1;
        }
    }
    else if(ntohs(llc->type) == ETHERNET_TYPE_IP6)
    {
        if(data_length < link_info.header_size + 40)
        {
            #if defined(PRINT_IP) || defined(PRINT_DROP) || defined(PRINT_IEE80211)
            printf("(structlib) checkIEEE80211, ip packet is too shot\n");
            #endif
            return -1;
        }
    }
    else
    {
        #if defined(PRINT_ETHERNET) || defined(PRINT_DROP) || defined(PRINT_IEE80211)
        printf("(structlib) checkIEEE80211, not an ip(v4/v6) drop : ");
        printEthernetType(ntohs(llc->type));
        #endif
        return -1;
    }*/
    *encapslated_protocol = ntohs(llc->type);
    
    /*update header size*/
    link_info.header_size = ieee_radio->it_len+32;
    
    /*check retry flags*/
    if(FC_RETRY(ieee->fc))
    {
        link_info.footer = 4;
    }
    else
    {
        link_info.footer = 0;
    }
    
    #if defined(PRINT_IEE80211)
    printf("(structlib) checkIEEE80211, FORWARD !!!!!!!!!");
    #endif
    
    return 0;
}

int checkDatalinkDefault(const uint8 * datas, int data_length, int * encapslated_protocol)
{
    *encapslated_protocol = -1;
    return 0;
}

int checkIPV4(const uint8 * datas, int data_length,struct ifaddrs *ifp,unsigned int * network_size, int * encapslated_protocol, int * local_address, collector_entry * entry)
{
    uint8 buffer[100];
    uint16 checksum;
    int size_ip;
    struct ifaddrs *ifp_tmp;
    sniff_ip * header_ip;
    
    *encapslated_protocol = -1;
    *local_address = 0;
    
    if(data_length < link_info.header_size + 20)
    {
        #if defined(PRINT_IP) || defined(PRINT_DROP)
        printf("(structlib) checkIPV4, ip packet is too shot\n");
        #endif
        return -1;
    }
    
    header_ip = (sniff_ip *)&datas[link_info.header_size];
    size_ip = IP4_HL(header_ip)*4;
    
    if (size_ip < 20) 
    {
        #if defined(PRINT_IP) || defined(PRINT_DROP)
    	printf("(structlib) checkIPV4, invalid IP header length: %u bytes\n", size_ip);
    	#endif
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
    
    #ifndef NO_DROP_LOCAL
    /*check ip size*/
    if(link_info.frame_payload_max_size < ntohs(header_ip->ip_len))
    {   
        ifp_tmp = ifp;
        while(ifp_tmp != NULL)
        {
            if(ifp_tmp->ifa_addr->sa_family == AF_INET && ((struct sockaddr_in *)  ifp_tmp->ifa_addr)->sin_addr.s_addr == header_ip->ip_src.s_addr)
            {
                *local_address = 1;
                break;
            }
            ifp_tmp = ifp_tmp->ifa_next;
        }
        
        if(ifp_tmp == NULL)
        {
            #if defined(PRINT_IP) || defined(PRINT_DROP)
            printf("(structlib) checkIPV4, too big packet\n");
            #endif
            
            return -1;
        }
    }
    #endif
    
    *encapslated_protocol = header_ip->ip_p;
    *network_size = ntohs(header_ip->ip_len);
    
    /*on copie le paquet ip et on met le checksum à zero*/
    bzero(buffer,100);        
    memcpy(buffer, &datas[link_info.header_size], size_ip);
    buffer[10] = 0;
    buffer[11] = 0;
    
    checksum = cksum2(0,buffer,size_ip);

#ifdef PRINT_IP
    printf(", checksum ip : original %x vs %x\n",ntohs(header_ip->ip_sum),checksum);
#endif
	
	/* COLLECTOR */
    entry->protocol = header_ip->ip_p;
    entry->ver = 4;
    memcpy(entry->sip, &header_ip->ip_src.s_addr, 4);
    memcpy(entry->dip, &header_ip->ip_dst.s_addr, 4);
	
#ifndef NO_DROP_LOCAL
	/*check checksum ip*/
	if(ntohs(header_ip->ip_sum) != checksum && (*local_address) == 0)
	{
        ifp_tmp = ifp;
        while(ifp_tmp != NULL)
        {
            if (ifp_tmp->ifa_addr->sa_family == AF_INET) /*WARNING : only ipv4*/
            {   
                if( ((struct sockaddr_in *)  ifp_tmp->ifa_addr)->sin_addr.s_addr == header_ip->ip_src.s_addr)
                {
                    *local_address = 1;
                    return 0;
                }
            }
            ifp_tmp = ifp_tmp->ifa_next;
        }
        
        #if defined(PRINT_IP) || defined(PRINT_DROP)
        printf("packet ip checksum invalid\n");
        #endif
        
        return -1;
	}
#endif
    return 0;
}

int checkIPV6(const uint8 * datas, int data_length,struct ifaddrs *ifp,unsigned int * network_size, int * encapslated_protocol, int * local_address, collector_entry * entry)
{
    sniff_ip6 * ip6;
    struct ifaddrs *ifp_tmp;
    
    *local_address = 0;
    *encapslated_protocol = -1;
    
    if(data_length < link_info.header_size + 40)
    {
        #if defined(PRINT_IP) || defined(PRINT_DROP)
        printf("(structlib) checkIPV6, ip packet is too shot\n");
        #endif
        return -1;
    }

    ip6 = (sniff_ip6 *)&datas[link_info.header_size];

    #ifdef PRINT_IP
        printf("(structlib) checkIPV6, ip_len : %d, ip.src : ",ntohs(ip6->ip_len));
        printIPV6(&ip6->ip_src);
        printf(", ip.dst : ");
        printIPV6(&ip6->ip_dst);
        printf("\n");
    #endif

    /*verifier la taille du paquet*/
    if(data_length < (link_info.header_size + 40 + ntohs(ip6->ip_len)))
    {
        #if defined(PRINT_IP) || defined(PRINT_DROP)
        printf("(structlib) checkIPV6, too short packet\n");
        #endif
        return -1;
    }
    
    /*is it local address?*/
    ifp_tmp = ifp;
    while(ifp_tmp != NULL)
    {
        if (ifp_tmp->ifa_addr->sa_family == AF_INET6) /*WARNING : only ipv4*/
        {   
            if(bcmp( ((struct sockaddr_in6 *)  ifp_tmp->ifa_addr)->sin6_addr.s6_addr, ip6->ip_src.s6_addr,16) == 0)
            {
                *local_address = 1;
                break;
            }
        }
        ifp_tmp = ifp_tmp->ifa_next;
    }
    
    *encapslated_protocol = ip6->ip_p;
    *network_size = ntohs(ip6->ip_len) + 40;
    
    /* COLLECTOR */
    entry->protocol = ip6->ip_p;
    entry->ver = 6;
    memcpy(entry->sip, &ip6->ip_src.s6_addr, 16);
    memcpy(entry->dip, &ip6->ip_dst.s6_addr, 16);
    
    return 0;
}

int checkNetworklinkDefault(const uint8 * datas, int data_length,struct ifaddrs *ifp,unsigned int * network_size, int * encapslated_protocol, int * local_address, collector_entry * entry)
{
    *encapslated_protocol = -1;
    *local_address = 0;
    *network_size = data_length - link_info.header_size;
    return 0;
}

int checkTCP(const struct pcap_pkthdr *pkthdr, const uint8 * datas, int local_source, collector_entry * entry)
{
    uint8 buffer[65535];/*TODO il y a moyen de se passer ce tableau pour faire les calculs*/
    uint16 checksum;
    pseudo_entete_ip pe_ip;
    unsigned int header_ip_size, segment_size;
    sniff_tcp * header_tcp;
    sniff_ip * header_ip = (sniff_ip *)&datas[link_info.header_size];
    
    #ifndef NO_RESEQ
    int ret_value;
    #endif
    
    header_ip_size = IP4_HL(header_ip)*4;
    
    if(pkthdr->len < (header_ip_size + 20 + link_info.header_size) )
    {
        #if defined(PRINT_TCP) || defined(PRINT_DROP)
        printf("(structlib) checkTCP, tcp segment has a too short size\n");
        #endif
        return -1;
    }
    
    header_tcp = (sniff_tcp *)&datas[link_info.header_size+header_ip_size];
    segment_size = ntohs(header_ip->ip_len)-header_ip_size;
    
    /*TODO check size
    if(pkthdr->len < (header_ip_size + 20 + link_info.header_size))
    {
        
    }*/
    

#ifdef PRINT_TCP
    printf("tcp.src : %u, tcp.dst : %u, tcp.seq : %u, tcp.ack %u", ntohs(header_tcp->th_sport), ntohs(header_tcp->th_dport),ntohl(header_tcp->th_seq),ntohl(header_tcp->th_ack));
    printf(", tpc header size (word 32 bits) : %u, payload : %u",TH_OFF(header_tcp), segment_size - TH_OFF(header_tcp)*4);
#endif

    /*check checksum tcp*/
    bzero(buffer,65535);        
    /*pseudo header*/
    pe_ip.ip_source = header_ip->ip_src.s_addr;
    pe_ip.ip_destination = header_ip->ip_dst.s_addr;
    pe_ip.mbz = 0; /*doit toujours etre a zero*/
    pe_ip.type = header_ip->ip_p;
    pe_ip.length = htons(segment_size);
    
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

#ifndef NO_DROP_LOCAL
    if(ntohs(header_tcp->th_sum) != checksum)
    {
        /*TEST tcp offload*/
        if(!local_source)
        {
            #if defined(PRINT_TCP) || defined(PRINT_DROP)
            printf("(structlib) checkTCP, packet tcp corrupted : drop\n");
            #endif

            return -1;
        }
    }
#endif
    
    /* COLLECTOR */
    entry->sport = header_tcp->th_sport;
    entry->dport = header_tcp->th_dport;
    entry->status = header_tcp->th_flags;
    
#ifndef NO_RESEQ
    if( !(state & STATE_PARSING) )
    {
        ret_value = addNewSegment_ipv4(header_tcp,header_ip,datas);
        setIPv4TCP(header_ip,header_tcp);
        /*sendReadySegment_ipv4(header_tcp, header_ip,pkthdr->ts);*/
        return ret_value;
    }
#endif
    return 0;
}

int checkTCP_ipv6(const struct pcap_pkthdr *pkthdr, const uint8 * datas,int local_source, collector_entry * entry)
{
    /*unsigned int segment_size = 0;*/
    sniff_ip6 * header_ip6 = (sniff_ip6 *)&datas[link_info.header_size];
    sniff_tcp * header_tcp;    

    #ifndef NO_RESEQ
    int ret_value;
    #endif

    /*segment_size = ntohs(header_ip6->ip_len);*/

    /*TODO check size*/
    
    header_tcp = (sniff_tcp *)&datas[link_info.header_size+40];

    /*TODO CHECKSUM test checksum tcp*/

    entry->sport = header_tcp->th_sport;
    entry->dport = header_tcp->th_dport;
    entry->status = header_tcp->th_flags;

    #ifndef NO_RESEQ
    if( !(state & STATE_PARSING) )
    {
        ret_value = addNewSegment_ipv6(header_tcp,header_ip6,datas);
        setIPv6TCP(header_ip6,header_tcp);
        /*sendReadySegment_ipv6(header_tcp, header_ip6,pkthdr->ts);*/
        return ret_value;
    }

    #endif
    
    return 0;
}

/* http://www.roman10.net/how-to-calculate-iptcpudp-checksumpart-2-implementation/ */
int checkUDP(const struct pcap_pkthdr *pkthdr, const uint8 * data, int local_source, collector_entry * entry)
{
    const uint16 * datas = (uint16 *)data;
    sniff_ip * header_ip = (sniff_ip *)&datas[link_info.header_size/2];
	uint32 sum = 0;
	int size_ip = IP4_HL(header_ip)*4;
	sniff_udp *header_udp = (sniff_udp*)(datas + link_info.header_size/2 + size_ip/2); /*TODO ça ne va pas fonctionner si header de taille impair, EX : LE WIFI, ou si la taille des données est inferieure*/
	uint16* ip_payload = (uint16 *)(datas + link_info.header_size/2 + size_ip/2);
	short len = htons(header_udp->uh_len);
	uint16 checksum = header_udp->uh_sum;
	
	#ifdef PRINT_TCP
        printf("udp.src : %u, udp.dst : %u, udp.length : %u\n", ntohs(header_udp->uh_sport), ntohs(header_udp->uh_dport),ntohs(header_udp->uh_len));
    #endif
	
	/* Adding ip src & dst  */
	sum += (header_ip->ip_src.s_addr>>16)&0xFFFF;
	sum += (header_ip->ip_src.s_addr)&0xFFFF;
	sum += (header_ip->ip_dst.s_addr>>16)&0xFFFF;
	sum += (header_ip->ip_dst.s_addr)&0xFFFF;
	
	sum += htons(17);
	sum += header_udp->uh_len;
	
	header_udp->uh_sum = 0; /* Set to 0 for the computation */
	 
	if(cksum(sum,ip_payload,len) != checksum && !local_source) /* TODO CHECKSUM essayer de faire un fonction cksum pour IP TCP UDP v4 */
    {   
        return -1;
    }
    
    header_udp->uh_sum = checksum; /* Set the previous value, just in case */
	
	entry->sport = header_udp->uh_sport;
    entry->dport = header_udp->uh_dport;
    entry->status = 0;
	
	return 0;
}

int checkUDP_ipv6(const struct pcap_pkthdr *pkthdr, const uint8 * datas, int local_source, collector_entry * entry)
{
    /*sniff_ip * header_ip = (sniff_ip *)&datas[link_info.header_size/2];*/
    sniff_udp * header_udp = (sniff_udp*)(datas + link_info.header_size/2 + 40/2);
    
    /*TODO CHECKSUM check*/
    
    entry->sport = header_udp->uh_sport;
    entry->dport = header_udp->uh_dport;
    entry->status = 0;
    
    return 0;
}

int checkTransportlinkDefault(const struct pcap_pkthdr *pkthdr, const uint8 * datas, int local_source, collector_entry * entry)
{
    return 0;
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

void printEthernetType(uint16 type)
{
    switch(type)
    {
        case 0x0200	:printf("PARC Universal Packet protocol\n");break;
        case 0x0800	:printf("Internet Protocol, Version 4 (IPv4)\n");break;
        case 0x0806	:printf("Address Resolution Protocol (ARP)\n");break;
        case 0x0842	:printf("Wake-on-LAN Magic Packet, as used by ether-wake and Sleep Proxy Service\n");break;
        case 0x1337	:printf("SYN-3 heartbeat protocol (SYNdog)\n");break;
        case 0x22F3	:printf("IETF TRILL Protocol\n");break;
        case 0x6003	:printf("DECnet Phase IV\n");break;
        case 0x8035	:printf("Reverse Address Resolution Protocol (RARP)\n");break;
        case 0x809B	:printf("AppleTalk (Ethertalk)\n");break;
        case 0x80F3	:printf("AppleTalk Address Resolution Protocol (AARP)\n");break;
        case 0x8100	:printf("VLAN-tagged frame (IEEE 802.1Q)\n");break;
        case 0x8137	:printf("Novell IPX (alt)\n");break;
        case 0x8138	:printf("Novell\n");break;
        case 0x8204	:printf("QNX Qnet\n");break;
        case 0x86DD	:printf("Internet Protocol, Version 6 (IPv6)\n");break;
        case 0x8808	:printf("MAC Control\n");break;
        case 0x8809	:printf("Slow Protocols (IEEE 802.3)\n");break;
        case 0x8819	:printf("CobraNet\n");break;
        case 0x8847	:printf("MPLS unicast\n");break;
        case 0x8848	:printf("MPLS multicast\n");break;
        case 0x8863	:printf("PPPoE Discovery Stage\n");break;
        case 0x8864	:printf("PPPoE Session Stage\n");break;
        case 0x886F	:printf("Microsoft NLB heartbeat\n");break;
        case 0x8870	:printf("Jumbo Frames\n");break;
        case 0x887B	:printf("HomePlug 1.0 MME\n");break;
        case 0x888E	:printf("EAP over LAN (IEEE 802.1X)\n");break;
        case 0x8892	:printf("PROFINET Protocol\n");break;
        case 0x889A	:printf("HyperSCSI (SCSI over Ethernet)\n");break;
        case 0x88A2	:printf("ATA over Ethernet\n");break;
        case 0x88A4	:printf("EtherCAT Protocol\n");break;
        case 0x88A8	:printf("Provider Bridging (IEEE 802.1ad)\n");break;
        case 0x88AB	:printf("Ethernet Powerlink\n");break;
        case 0x88CC	:printf("LLDP\n");break;
        case 0x88CD	:printf("sercos III\n");break;
        case 0x88D8	:printf("Circuit Emulation Services over Ethernet (MEF-8)\n");break;
        case 0x88E1	:printf("HomePlug AV MME\n");break;
        case 0x88E3	:printf("Media Redundancy Protocol (IEC62439-2)\n");break;
        case 0x88E5	:printf("MAC security (IEEE 802.1AE)\n");break;
        case 0x88F7	:printf("Precision Time Protocol (IEEE 1588)\n");break;
        case 0x8902	:printf("IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)\n");break;
        case 0x8906	:printf("Fibre Channel over Ethernet\n");break;
        case 0x8914	:printf("FCoE Initialization Protocol\n");break;
        case 0x9000	:printf("Configuration Test Protocol (Loop)\n");break;
        case 0x9100	:printf("Q-in-Q\n");break;
        case 0xCAFE	:printf("Veritas Low Latency Transport (LLT)\n");break;
        default : printf("unknwon ethernet type, maybe it's the size value : 0x%.4x\n",type);
    }
}

void printIpType(uint8 type)
{
    switch(type)
    {
        case 0x00 : printf("HOPOPT\n"); break;
        case 0x01 : printf("ICMP\n"); break;
        case 0x02 : printf("IGMP\n"); break;
        case 0x03 : printf("GGP\n"); break;
        case 0x04 : printf("IP\n"); break;
        case 0x05 : printf("ST\n"); break;
        case 0x06 : printf("TCP\n"); break;
        case 0x07 : printf("CBT\n"); break;
        case 0x08 : printf("EGP\n"); break;
        case 0x09 : printf("IGP\n"); break;
        case 0x0A : printf("BBN-RCC-MON\n"); break;
        case 0x0B : printf("NVP-II\n"); break;
        case 0x0C : printf("PUP\n"); break;
        case 0x0D : printf("ARGUS\n"); break;
        case 0x0E : printf("EMCON\n"); break;
        case 0x0F : printf("XNET\n"); break;
        case 0x10 : printf("CHAOS\n"); break;
        case 0x11 : printf("UDP\n"); break;
        case 0x12 : printf("MUX\n"); break;
        case 0x13 : printf("DCN-MEAS\n"); break;
        case 0x14 : printf("HMP\n"); break;
        case 0x15 : printf("PRM\n"); break;
        case 0x16 : printf("XNS-IDP\n"); break;
        case 0x17 : printf("TRUNK-1\n"); break;
        case 0x18 : printf("TRUNK-2\n"); break;
        case 0x19 : printf("LEAF-1\n"); break;
        case 0x1A : printf("LEAF-2\n"); break;
        case 0x1B : printf("RDP\n"); break;
        case 0x1C : printf("IRTP\n"); break;
        case 0x1D : printf("ISO-TP4\n"); break;
        case 0x1E : printf("NETBLT\n"); break;
        case 0x1F : printf("MFE-NSP\n"); break;
        case 0x20 : printf("MERIT-INP\n"); break;
        case 0x21 : printf("DCCP\n"); break;
        case 0x22 : printf("3PC\n"); break;
        case 0x23 : printf("IDPR\n"); break;
        case 0x24 : printf("XTP\n"); break;
        case 0x25 : printf("DDP\n"); break;
        case 0x26 : printf("IDPR-CMTP\n"); break;
        case 0x27 : printf("TP++\n"); break;
        case 0x28 : printf("IL\n"); break;
        case 0x29 : printf("IPv6\n"); break;
        case 0x2A : printf("SDRP\n"); break;
        case 0x2B : printf("IPv6-Route\n"); break;
        case 0x2C : printf("IPv6-Frag\n"); break;
        case 0x2D : printf("IDRP\n"); break;
        case 0x2E : printf("RSVP\n"); break;
        case 0x2F : printf("GRE\n"); break;
        case 0x30 : printf("MHRP\n"); break;
        case 0x31 : printf("BNA\n"); break;
        case 0x32 : printf("ESP\n"); break;
        case 0x33 : printf("AH\n"); break;
        case 0x34 : printf("I-NLSP\n"); break;
        case 0x35 : printf("SWIPE\n"); break;
        case 0x36 : printf("NARP\n"); break;
        case 0x37 : printf("MOBILE\n"); break;
        case 0x38 : printf("TLSP\n"); break;
        case 0x39 : printf("SKIP\n"); break;
        case 0x3A : printf("IPv6-ICMP\n"); break;
        case 0x3B : printf("IPv6-NoNxt\n"); break;
        case 0x3C : printf("IPv6-Opts\n"); break;
        case 0x3D : printf("Any host internal protocol\n"); break;
        case 0x3E : printf("CFTP\n"); break;
        case 0x3F : printf("Any local network\n"); break;
        case 0x40 : printf("SAT-EXPAK\n"); break;
        case 0x41 : printf("KRYPTOLAN\n"); break;
        case 0x42 : printf("RVD\n"); break;
        case 0x43 : printf("IPPC\n"); break;
        case 0x44 : printf("Any distributed file system\n"); break;
        case 0x45 : printf("SAT-MON\n"); break;
        case 0x46 : printf("VISA\n"); break;
        case 0x47 : printf("IPCV\n"); break;
        case 0x48 : printf("CPNX\n"); break;
        case 0x49 : printf("CPHB\n"); break;
        case 0x4A : printf("WSN\n"); break;
        case 0x4B : printf("PVP\n"); break;
        case 0x4C : printf("BR-SAT-MON\n"); break;
        case 0x4D : printf("SUN-ND\n"); break;
        case 0x4E : printf("WB-MON\n"); break;
        case 0x4F : printf("WB-EXPAK\n"); break;
        case 0x50 : printf("ISO-IP\n"); break;
        case 0x51 : printf("VMTP\n"); break;
        case 0x52 : printf("SECURE-VMTP\n"); break;
        case 0x53 : printf("VINES\n"); break;
        case 0x54 : printf("TTP or IPTM\n"); break;
        case 0x55 : printf("NSFNET-IGP\n"); break;
        case 0x56 : printf("DGP\n"); break;
        case 0x57 : printf("TCF\n"); break;
        case 0x58 : printf("EIGRP\n"); break;
        case 0x59 : printf("OSPF\n"); break;
        case 0x5A : printf("Sprite-RPC\n"); break;
        case 0x5B : printf("LARP\n"); break;
        case 0x5C : printf("MTP\n"); break;
        case 0x5D : printf("AX.25\n"); break;
        case 0x5E : printf("IPIP\n"); break;
        case 0x5F : printf("MICP\n"); break;
        case 0x60 : printf("SCC-SP\n"); break;
        case 0x61 : printf("ETHERIP\n"); break;
        case 0x62 : printf("ENCAP\n"); break;
        case 0x63 : printf("Any private encryption scheme\n"); break;
        case 0x64 : printf("GMTP\n"); break;
        case 0x65 : printf("IFMP\n"); break;
        case 0x66 : printf("PNNI\n"); break;
        case 0x67 : printf("PIM\n"); break;
        case 0x68 : printf("ARIS\n"); break;
        case 0x69 : printf("SCPS\n"); break;
        case 0x6A : printf("QNX\n"); break;
        case 0x6B : printf("A/N\n"); break;
        case 0x6C : printf("IPComp\n"); break;
        case 0x6D : printf("SNP\n"); break;
        case 0x6E : printf("Compaq-Peer\n"); break;
        case 0x6F : printf("IPX-in-IP\n"); break;
        case 0x70 : printf("VRRP\n"); break;
        case 0x71 : printf("PGM\n"); break;
        case 0x72 : printf("Any 0-hop protocol\n"); break;
        case 0x73 : printf("L2TP\n"); break;
        case 0x74 : printf("DDX\n"); break;
        case 0x75 : printf("IATP\n"); break;
        case 0x76 : printf("STP\n"); break;
        case 0x77 : printf("SRP\n"); break;
        case 0x78 : printf("UTI\n"); break;
        case 0x79 : printf("SMP\n"); break;
        case 0x7A : printf("SM\n"); break;
        case 0x7B : printf("PTP\n"); break;
        case 0x7C : printf("IS-IS over IPv4\n"); break;
        case 0x7D : printf("FIRE\n"); break;
        case 0x7E : printf("CRTP\n"); break;
        case 0x7F : printf("CRUDP\n"); break;
        case 0x80 : printf("SSCOPMCE\n"); break;
        case 0x81 : printf("IPLT\n"); break;
        case 0x82 : printf("SPS\n"); break;
        case 0x83 : printf("PIPE\n"); break;
        case 0x84 : printf("SCTP\n"); break;
        case 0x85 : printf("FC\n"); break;
        case 0x86 : printf("RSVP-E2E-IGNORE\n"); break;
        case 0x87 : printf("Mobility Header\n"); break;
        case 0x88 : printf("UDP Lite\n"); break;
        case 0x89 : printf("MPLS-in-IP\n"); break;
        case 0x8A : printf("manet\n"); break;
        case 0x8B : printf("HIP\n"); break;
        case 0x8C : printf("Shim6\n"); break;
        case 0xFF : printf("Reserved\n"); break;
        default : 
            if(0x8D <= type && type <= 0xFC)
            {
                printf("unassigned\n");
            }
            else if(0xFD <= type && type <= 0xFE)
            {
                printf("Use for experimentation and testing\n");
            }
            else
            {
                printf("unknwon ip protocol\n");
            }
    }
}

void printIPV6(struct in6_addr * ip)
{
    printf("%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x"
        ,ip->s6_addr[0],ip->s6_addr[1],ip->s6_addr[2],ip->s6_addr[3],ip->s6_addr[4],ip->s6_addr[5],ip->s6_addr[6],ip->s6_addr[7],ip->s6_addr[8],ip->s6_addr[9],ip->s6_addr[10],ip->s6_addr[11],ip->s6_addr[12],ip->s6_addr[13],ip->s6_addr[14],ip->s6_addr[15]);  
}


