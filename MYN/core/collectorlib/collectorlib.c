#include "collectorlib.h"


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


DLinkedList * dlinkedlist_add_last(DLinkedList * list, void* e)
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

DLinkedList * dlinkedlist_move_to_tail(DLinkedList * list, struct node *n_node)
{
	if(n_node == NULL)
	{
		return list;
	}
	if(list != NULL)
	{

		if(n_node == list->head) /* N_node is the first node */
		{
			
			list->tail->next = n_node;
			n_node->prev = list->tail;
			list->tail = n_node;

			list->head = n_node->next;
			list->head->prev = NULL;

			n_node->next = NULL;

		}
		else if(n_node->next != NULL && n_node->prev != NULL)
		{
			
			n_node->prev->next = n_node->next;
			n_node->next->prev = n_node->prev;

			list->tail->next = n_node;
			n_node->prev = list->tail;
			list->tail = n_node;
			n_node->next = NULL;
		}else
		{
			/*printf("NO CHANGE \n");*/
		}
	}

	return list;
}

DLinkedList * dlinkedlist_add_first(DLinkedList * list, void* e)
{
    if(list != NULL)
    {
        struct node *n_new = calloc(1,sizeof(*n_new));
        if(n_new != NULL)
        {
            n_new->entry = e;
            n_new->prev = NULL;
            if(list->tail == NULL)
            {
                list->tail = n_new;
                list->head = n_new;
                n_new->next = NULL;
            }
            else
            {
                list->head->prev = n_new;
                n_new->next = list->head;
                list->head = n_new;
            }
            list->length += 1;
        }
    }

	return list;
}


DLinkedList *dlinkedlist_add_insert(DLinkedList *list, void* e, int pos)
{
	struct node *n_temp;
	struct node *n_new;
	int i = 1;
	
    if(list != NULL)
	{
		n_temp = list->head;
		while(n_temp != NULL && i <= pos)
		{
			if(i == pos)
			{
				if(n_temp->next == NULL)
					list = dlinkedlist_add_last(list,e);
				else if(n_temp->prev == NULL)
					list = dlinkedlist_add_first(list,e);
				else
				{
					n_new = malloc(sizeof(n_new));
					if(n_new != NULL)
					{
						n_new->entry = e;
						n_temp->next->prev = n_new;
						n_temp->prev->next = n_new;
						n_new->prev = n_temp->prev;
						n_new->next = n_temp;
						list->length += 1;
					}
				}
                break;
			}
			else
			{
				n_temp = n_temp->next;			
			}
			i++;
		}
	}
	
	return list;
}

DLinkedList* dlinkedlist_remove_id(DLinkedList *list, int pos)
{
	struct node *n_temp;
	int i = 1;
    if(list != NULL)
    {
		n_temp = list->head;
		while(n_temp != NULL && i < pos)
		{
			if(i == pos)
			{
				if(n_temp->next == NULL)
				{
					list->tail = n_temp->prev;
					list->tail->next = NULL;
				}
				else if(n_temp->prev == NULL)
				{
					list->head = n_temp->next;
					list->head->prev = NULL;
				}
				else
				{
					n_temp->next->prev = n_temp->prev;
					n_temp->prev->next = n_temp->next;
				}
				list->length -= 1;
				free(n_temp);
			}
			else
			{
				n_temp = n_temp->next;
			}	
			i += 1;
		}
    }
	return list;
}

DLinkedList* dlinkedlist_remove_node(DLinkedList *list, struct node *n_node)
{
    if(list != NULL && n_node != NULL)
    {
		if(n_node->next == NULL)
		{
		    if(n_node->prev == NULL)
		    {
                list->tail = list->head = NULL;
		    }
		    else
		    {
		        list->tail = n_node->prev;
    			list->tail->next = NULL;
		    }
		}
		else if(n_node->prev == NULL)
		{
			list->head = n_node->next;
			list->head->prev = NULL;
		}
		else
		{
			n_node->next->prev = n_node->prev;
			n_node->prev->next = n_node->next;
		}
		list->length -= 1;
		free(n_node);
    }
	return list;
}

void dlinkedlist_clear(DLinkedList *list)
{
	struct node *n_temp,*n_to_remove;
	if(list != NULL)
	{
		n_temp = list->head;
		while(n_temp != NULL)
		{
			n_to_remove = n_temp;
			n_temp = n_temp->next;
			free(n_to_remove);
		}		
	}
	free(n_temp);
	list->head=NULL;
	list->tail=NULL;
	list->length=0;
}

size_t dlinkedlist_length(DLinkedList *list)
{
    int value = 0;
    if(list != NULL)
    {
        value = list->length;
    }
    
    return value;
}


void dlinkedlist_to_string(DLinkedList *list)
{
	struct node *n_temp;
	if(list != NULL)
	{
		n_temp = list->head;
		while(n_temp != NULL)
		{
			/*printf("[sip=%d.%d.%d.%d dip=%d.%d.%d.%d dport=%d, sport=%d,time=%u ]->",n_temp->entry.sip[0],n_temp->entry.sip[1],n_temp->entry.sip[2],n_temp->entry.sip[3],n_temp->entry.dip[0],n_temp->entry.dip[1],n_temp->entry.dip[2],n_temp->entry.dip[3],ntohs(n_temp->entry.dport),ntohs(n_temp->entry.sport),ntohs(n_temp->entry.epoch_time));
			n_temp = n_temp->next;*/
		}		
	}
	printf("NIL\n");
}

void clear(DLinkedList *list, DLinkedList *list_time)
{
	struct node *n_temp;
	struct struct_proto * proto_tmp;

	n_temp = list->head; /* First item */
	while(n_temp != NULL)
	{
		proto_tmp = ((struct_ip*)n_temp->entry)->first_child; /* First protocol */
		
		while(proto_tmp != NULL)
		{
			proto_tmp = proto_tmp->next; /* Next Proto structure */		
			if(proto_tmp != NULL)	
				free(proto_tmp->prev); /* Free memory */
		}
		n_temp = n_temp->next; /* Next IP structure */
	}
	
	dlinkedlist_clear(list);
	dlinkedlist_clear(list_time);
}

int dump(DLinkedList *list, DLinkedList *list_time)
{
	struct node *n_temp = NULL;
	struct struct_proto * proto_tmp = NULL;
	struct_ip * ip_tmp = NULL;
	int fd ; /* File descriptor */
	collector_entry file_entry; /* An element in the file */
	uint32 tmp_size = 0; /* Number of element in the file */
	int size_entry_file = (sizeof(collector_entry)-(2*sizeof(uint8)));


	/* CREATION  AND OPENING OF THE FILE */
    if((fd = open("temp_plist", O_CREAT|O_RDWR, 0644)) < 0)
    {
    	perror("(collector) file open error: ");
    	return EXIT_FAILURE;
    }

    /* READING THE SIZE */
    if(read(fd, &tmp_size, sizeof(uint32)) == 0)
    {
    	if(write(fd, &tmp_size, sizeof(uint32)) != sizeof(uint32))
    	{
    		perror("(collector) write error: ");
            close(fd);
    		return EXIT_FAILURE;
    	}
    }

    /*printf("TAILLE LUE %d \n", tmp_size);*/

    if(list != NULL)
	{
		/* READING and UPDATING */
		while(read(fd, &file_entry, size_entry_file) > 0 ) /* Read a file entry */
		{
			n_temp = list->head; /* First item */
			while(n_temp != NULL)
			{
				if(memcmp( ((struct_ip*)n_temp->entry)->sip,file_entry.sip,sizeof(file_entry.sip)) == 0 && 
				memcmp( ((struct_ip*)n_temp->entry)->dip,file_entry.dip,sizeof(file_entry.dip)) == 0) /* Verif IP SRC & DST */
				{
					proto_tmp = ((struct_ip*)n_temp->entry)->first_child; /* First protocol */
					while(proto_tmp != NULL) /* Iterate over all protocols for this IP */
					{
						if(memcmp(proto_tmp->data,&file_entry.sport,sizeof(uint8)*4) == 0)
						{
							file_entry.epoch_time = proto_tmp->epoch_time;

							/* Update the entry in the file */
							if(lseek(fd,-size_entry_file,SEEK_CUR) < 0)
							{
								perror("(collector) fseek error: ");
                                close(fd);
                                return EXIT_FAILURE;
							}
							if(write(fd ,&file_entry, size_entry_file) != size_entry_file)
							{   
								printf("Error on writing \n");
                                close(fd);
                                return EXIT_FAILURE;
                                
							}
							/*printf("UPDATED !!!!!! \n");*/
							proto_tmp->updated = 1; /* Mark as Updated in the file */
						}

						if(proto_tmp->next == NULL) /* End of the list of proto */
							break;

						proto_tmp = proto_tmp->next; /* Next Proto structure */
					}
					break;
				}
				n_temp = n_temp->next; /* Next node */
			}
		}
		

		
	}
	else
	{
		return EXIT_FAILURE;
	}

	/* Adding entry in the file */
	n_temp = list->head; /* First item */
	while(n_temp != NULL)
	{
		ip_tmp = ((struct_ip*)n_temp->entry);
		proto_tmp = ip_tmp->first_child; /* First protocol */
		while(proto_tmp != NULL) /* Iterate over all protocols for this IP */
		{
			if(proto_tmp->updated != 1)
			{
				memcpy(file_entry.sip, ip_tmp->sip,sizeof(ip_tmp->sip)); /* IP SRC */
				memcpy(file_entry.dip, ip_tmp->dip,sizeof(ip_tmp->dip)); /* IP DST */				
				memcpy(&file_entry.sport,proto_tmp->data , sizeof(file_entry.sport)); /* SOURCE port */
				memcpy(&file_entry.dport, &proto_tmp->data[sizeof(file_entry.sport)] ,sizeof(file_entry.dport)); /* DESTINATION port */
				file_entry.ver = ip_tmp->ver; /* VERSION */
				file_entry.protocol = proto_tmp->protocol; /* PROTOCOL */
				file_entry.epoch_time = proto_tmp->epoch_time; /* TIME */


				if(write(fd ,&file_entry, size_entry_file) != size_entry_file)
				{
					perror("(collector) write error: \n");
                    close(fd);
                    return EXIT_FAILURE;
				}
				tmp_size++;
			}

			if(proto_tmp->next == NULL) /* End of the list of proto */
				break;

			proto_tmp = proto_tmp->next; /* Next Proto structure */
		}
		n_temp = n_temp->next; /* Next node */
	}


	/* Updating the number of element in the file */
	/* Set fd at the beginning of the file */
	if(lseek(fd,0,SEEK_SET) < 0)
	{
		perror("(collector) fseek error: ");
	}

	if(write(fd, &tmp_size, sizeof(uint32)) != sizeof(uint32))
	{
		perror("(collector) write error: \n");
	}

	/*printf("FINAL SIZE %d \n",tmp_size);*/
	/* Clear memory */
	clear(list, list_time);

    close(fd);
	return 0;
}

void remove_proto(DLinkedList *list, struct struct_proto* n)
{
	if(n->prev == NULL && n->next == NULL) /* Just one proto */
	{
		dlinkedlist_remove_node(list, n->node_struct_ip);
	}
	else if(n->prev == NULL && n->next != NULL) /* The first of the list */
	{
		n->next->prev = NULL;
		((struct_ip*)n->node_struct_ip->entry)->first_child = n->next;
	}
	else if(n->next == NULL)
	{
		n->prev->next = NULL;	
	}
	else
	{
		n->prev->next = n->next;
		n->next->prev = n->prev;    	
	}

	free(n);
}

struct struct_proto* insert_proto(struct struct_proto* current, struct struct_proto* new)
{
	current->next = new;
	new->prev = current;
	return new;
}

struct struct_proto* create_proto(collector_entry new_item)
{
	struct struct_proto * proto;

	proto = calloc(1,sizeof(struct struct_proto)); /* Allocation */
	proto->epoch_time = new_item.epoch_time; /* Epoch time */
	proto->protocol = new_item.protocol; /* Protocol */
	memcpy(proto->data,&new_item.sport,sizeof(new_item.sport)); /* Source port */
	memcpy(&proto->data[sizeof(new_item.sport)],&new_item.dport,sizeof(new_item.dport)); /* Destination port */
	proto->next = NULL;
	proto->prev = NULL;

	return proto;
}

void update_list_entries(DLinkedList *list, DLinkedList *list_time, collector_entry new_item, int max_entries)
{
	struct_ip * item = calloc(1,sizeof(struct_ip));
	struct node *n_temp = NULL;
	struct struct_proto * proto;
	struct struct_proto * proto_tmp;
	short ip_founded = 0;
	short proto_founded = 0;

	/* Initialisation of struct_ip */
	memcpy(item->sip, new_item.sip,sizeof(new_item.sip));
	memcpy(item->dip, new_item.dip,sizeof(new_item.dip));
	item->ver = new_item.ver;


	if(list != NULL)
	{
		n_temp = list->head; /* First item */
		while(n_temp != NULL && proto_founded != 1)
		{
			if(memcmp( ((struct_ip*)n_temp->entry)->sip,item->sip,sizeof(item->sip)) == 0 && 
				memcmp( ((struct_ip*)n_temp->entry)->dip,item->dip,sizeof(item->dip)) == 0) /* Verif IP SRC & DST */
			{
				ip_founded = 1;
				proto_tmp = ((struct_ip*)n_temp->entry)->first_child; /* First protocol */
				while(proto_tmp != NULL)
				{
					if(memcmp(proto_tmp->data,&new_item.sport,sizeof(uint8)*4) == 0)
					{
						proto_tmp->epoch_time = new_item.epoch_time; /* Update time */

						dlinkedlist_move_to_tail(list_time, proto_tmp->node_time_list); 

						proto_founded = 1;
						break;
					}

					if(proto_tmp->next == NULL) /* End of the list of proto */
						break;

					proto_tmp = proto_tmp->next; /* Next Proto structure */
				}
				break;
			}

			n_temp = n_temp->next; /* Next IP structure */
		}
		
		if(capture_mode == LIVE_MODE)
		{
			while(list_time->length >= max_entries)
			{
				remove_proto(list, ((struct struct_proto *)list_time->head->entry));
				dlinkedlist_remove_node(list_time, list_time->head);
			}
		}
		else
		{
			if(list_time->length >= max_entries)
			{
				dump(list, list_time);
			}
		}
		

		if(ip_founded == 1 && proto_founded == 0) /* IP Found but no proto found, so add a proto for this IP */
		{
			proto = create_proto(new_item);
			dlinkedlist_add_last(list_time, insert_proto(proto_tmp, proto));
			proto->node_time_list = list_time->tail;
			proto->node_struct_ip = proto->prev->node_struct_ip;
			/*printf("PROTO ADDED %lu \n",list_time->length);	*/
			return;
		}

		if(ip_founded == 0) /* IP not found, so add a IP */
		{
			if(new_item.protocol != IP_TYPE_TCP || (new_item.protocol == IP_TYPE_TCP && new_item.status&TH_SYN && !(new_item.status&TH_ACK)))
			{
				item->first_child = create_proto(new_item); /* Link the child */
				dlinkedlist_add_last(list_time, item->first_child);
				dlinkedlist_add_last(list, item);
				item->first_child->node_time_list = list_time->tail;			
				item->first_child->node_struct_ip = list->tail;
				/*printf("ADDED %lu \n",list_time->length);		*/
										
			}
			else
			{
				free(item);
			}
			
		}
		else
		{
			free(item);
		}
		
	}
}

