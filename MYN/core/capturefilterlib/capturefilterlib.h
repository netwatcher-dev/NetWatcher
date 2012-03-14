#ifndef _CAPTUREFILTERLIB_H
#define _CAPTUREFILTERLIB_H

/*TODO
    -faire une stack de taille dynamique
        il suffit de garder le nombre de breakpoint consecutif max possible
        et lors d'une insertion, on compte le nombre de breakpoint consecutif max pouvant arriver
            pas vraiment possible sans essayer tous les chemins :/

*/

#ifdef __gnu_linux__

#define _BSD_SOURCE
#include <sys/types.h>

#endif

#include "../core_type.h"
#include <sys/socket.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "../structlib/structlib.h"

#ifndef LBL_ALIGN
#ifndef WIN32
#include <netinet/in.h>
#endif

#define EXTRACT_SHORT(p)	((u_short)ntohs(*(u_short *)p))
#define EXTRACT_LONG(p)		(ntohl(*(uint32 *)p))
#else
#define EXTRACT_SHORT(p)\
	((u_short)\
		((u_short)*((u_char *)p+0)<<8|\
		 (u_short)*((u_char *)p+1)<<0))
#define EXTRACT_LONG(p)\
		((uint32)*((u_char *)p+0)<<24|\
		 (uint32)*((u_char *)p+1)<<16|\
		 (uint32)*((u_char *)p+2)<<8|\
		 (uint32)*((u_char *)p+3)<<0)
#endif

#define compare_filter(a, b)       ((a->instruct.code == b->instruct.code) && (a->instruct.k == b->instruct.k))

extern struct master_filter master_filter;
extern datalink_info link_info;

#define MAX_FILTER_LEVEL 10

struct filter_node
{
    struct filter_item * item;
    struct filter_node * next;
};

struct filter_item
{
    u_short	code;
    uint32 k;
        
    struct filter_node * next_child_t; /*liste chainée des enfants*/
        /*Dans le cas d'une instruction NON CONDITIONNELLE, le next_child_t contiendra l'instruction suivante*/
        /*Dans le cas d'une instruction TERMINALE, le next_child_t contiendra les parents a partir du second*/
    struct filter_node * next_child_f; /*liste chainée des enfants*/
    struct filter_item * parent;
};

struct breakpoint
{
    uint32 A, X;
	int k;
	sint32 mem[BPF_MEMWORDS];
    struct filter_node * next_instruct;
};

struct master_filter
{
    struct filter_node * filter_first_node;
    
    struct breakpoint breakpoint_stack[MAX_FILTER_LEVEL];
    int current_breakpoint;
};

void initFilter();
int addFilter(const char * filter_string, int filter_id, int pipe);
int removeFilter(int end_node_id);
void removeAllFilter();
int sendToAllNode(register const u_char *p,unsigned int buflen);
void traversal();
void innerTraversal(struct filter_item * i, int level);

#endif
