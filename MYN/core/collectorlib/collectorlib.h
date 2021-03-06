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

#ifndef _COLLECTORLIB_H
#define _COLLECTORLIB_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/socket.h>
#include <sys/time.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h> /* Read */
#include "../core_type.h"

#define INIT_ENTRIES 100
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
void update_list_entries(DLinkedList *list, DLinkedList *list_time, collector_entry new_item, int max_entries); /* Update the list with a new item */

#endif