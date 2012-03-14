#include <stdlib.h>
#include <stdio.h>

typedef struct
{
    char sip[16];
    char dip[16];
    int ver;
    struct struct_proto * first_child;
}struct_ip;

struct node
{
    void * entry;
    struct node *prev;
    struct node *next;
};

typedef struct
{
    size_t length;
    struct node *head;
    struct node *tail;
}DLinkedList;


DLinkedList *dlinkedlist_new()
{
    DLinkedList *new_list = malloc(sizeof(*new_list));
    
    if(new_list != NULL) /* Malloc OK */
    {
        new_list->length = 0;
        new_list->head = NULL;
        new_list->tail = NULL;   
    }    
    
    return new_list;
    
}


DLinkedList * dlinkedlist_add_last(DLinkedList * list, void * e)
{
    if(list != NULL)
    {    
        struct node *n_new = calloc(1,sizeof(*n_new));
        if(n_new != NULL)
        {
            n_new->entry = e;
            n_new->next = NULL;
            if(list->tail == NULL)
            {
                n_new->prev = NULL;
                list->tail = n_new;
                list->head = n_new;
            }
            else
            {
                list->tail->next = n_new;
                n_new->prev = list->tail;
                list->tail = n_new;
            }
            list->length += 1;
        }
    }
    
    return list;
}


int main(int argc, char *argv[])
{
	DLinkedList * list;
	struct_ip * item;
	list = dlinkedlist_new();
	item = calloc(1,sizeof(struct_ip));
	item->sip[0] = 66;
	dlinkedlist_add_last(list,item);

	item = calloc(1,sizeof(struct_ip));
	item->sip[0] = 77;
	dlinkedlist_add_last(list,item);

	printf("list->length : %lu\n",list->length);
	printf("%d \n",((struct_ip*)list->head->entry)->sip[0]);
	printf("%d \n",((struct_ip*)list->head->next->entry)->sip[0]);
	return 0;
}