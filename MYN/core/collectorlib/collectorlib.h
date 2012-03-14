#ifndef _COLLECTORLIB_H
#define _COLLECTORLIB_H


#include <sys/socket.h>
#include <sys/time.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h> /* Read */
#include "../collectorlib/collectorlib.h"
#include "../structlib/structlib.h"
#include "../core_type.h"

#define INIT_TIMEOUT 30 /* in second */
#define INIT_ENTRIES 15
#define COMMAND_SET_LENGTH 1 /* Code command */
#define COMMAND_CLEAR 2      /* Code command */
#define COMMAND_GET_PLIST 4  /* Code command */
#define LIVE_MODE 6 /* Live mode */
#define FILE_MODE 8 /* File mode */

extern int capture_mode; /* File or Live mode */

typedef struct
{
    uint8 sip[16];
    uint8 dip[16];
    uint8 ver;
    struct struct_proto * first_child;
}struct_ip;


struct struct_proto
{	
	uint8 protocol; /*see ip protocol list*/
	uint8 data[4];
	uint32 epoch_time;
    uint8 updated;
	struct struct_proto * prev;
	struct struct_proto * next;
	struct node * node_time_list;
	struct node * node_struct_ip;	
};

struct node
{
    void* entry;
    struct node *prev;
    struct node *next;
};

typedef struct
{
    size_t length;
    struct node *head;
    struct node *tail;
}DLinkedList;


typedef struct
{
    uint8 sip[16];
    uint8 dip[16];
    uint8 ver;
    uint8 protocol; /*see ip protocol list*/
    uint8 data[4];
    uint32 epoch_time;
}struct_file;


/* Linked list */
DLinkedList * dlinkedlist_new();
DLinkedList * dlinkedlist_add_last(DLinkedList * ll, void* e);
DLinkedList * dlinkedlist_add_first(DLinkedList * ll, void* e);
DLinkedList * dlinkedlist_add_insert(DLinkedList *list, void* e, int pos);
DLinkedList * dlinkedlist_free(DLinkedList *list);
DLinkedList * dlinkedlist_remove_node(DLinkedList *list, struct node *n_node);
DLinkedList * dlinkedlist_move_to_tail(DLinkedList * list, struct node *n_node);
void dlinkedlist_to_string(DLinkedList *list);
void dlinkedlist_clear(DLinkedList *list);
size_t dlinkedlist_length(DLinkedList *list);


void clear(DLinkedList *list, DLinkedList *list_time); /* Clear the list of IP-PROTO */
int dump(DLinkedList *list, DLinkedList *list_time); /* Copy the list into a file */
void remove_proto(DLinkedList *list, struct struct_proto* n); /* Remove a protocol of the list of IP-PROTO */
struct struct_proto* insert_proto(struct struct_proto* current, struct struct_proto* new); /* Insert a new proto in the list of IP-PROTO */
struct struct_proto* create_proto(collector_entry new_item); /* Create a new proto */
void update_list_entries(DLinkedList *list, DLinkedList *list_time, collector_entry new_item, int max_entries, int syn); /* Update the list with a new item */

#endif