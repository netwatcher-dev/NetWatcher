#include <stdio.h> /*printf, fprintf*/
#include <stdlib.h> /*exit, atoi*/
#include <unistd.h> /* Read */
#include <sys/select.h> /* Select */
#include <errno.h>
#include <fcntl.h>
#include "./collectorlib/collectorlib.h"
#include "./structlib/structlib.h"
#include "./command.h"


int dump(DLinkedList *list)
{
	struct node *n_temp = NULL;
	int fd ;
	collector_entry file_entry;
	uint32 tmp_size = 0;

	printf("TAILLE DE LA LISTE %lu \n",list->length);
    if((fd = open("temp_plist", O_CREAT|O_RDWR, 0644)) < 0)
    {
    	perror("(collector) file open error: ");
    	return EXIT_FAILURE;
    }

    if(read(fd, &tmp_size, sizeof(uint32)) == 0)
    {
    	if(write(fd, &tmp_size, sizeof(uint32)) != sizeof(uint32))
    	{
    		perror("(collector) write error: ");
    	}
    }

    if(list != NULL)
	{
		/* READING and UPDATING */
		while(read(fd, &file_entry, (sizeof(collector_entry)-sizeof(uint8))) > 0 )
		{
			n_temp = list->head; /* First item */
			while(n_temp != NULL)
			{
				if(memcmp(n_temp->entry.sip, file_entry.sip,(sizeof(uint8)*16)) == 0 
					&& memcmp(n_temp->entry.dip, file_entry.dip,(sizeof(uint8)*16)) == 0 
					&& (n_temp->entry.sport && file_entry.sport)
					&& (n_temp->entry.dport && file_entry.dport))
				{
					file_entry.epoch_time = n_temp->entry.epoch_time;
					if(lseek(fd,-((sizeof(collector_entry)-sizeof(uint8))),SEEK_CUR) < 0)
					{
						perror("(collector) fseek error: ");
					}
					if(write(fd ,&n_temp->entry, (sizeof(collector_entry)-sizeof(uint8))) != (sizeof(collector_entry)-sizeof(uint8)))
					{
						printf("Error on writing \n");
					}

					n_temp->entry.updated = 1;
					printf("FOUNDED \n");
					/* break; ???*/ 
				}

				n_temp = n_temp->next;
			}
		}

		/* ADDING */
		/* Set fd at the end of the file */
		if(lseek(fd,0,SEEK_END) < 0)
		{
			perror("(collector) fseek error: ");
		}

		n_temp = list->head; /* First item */
		while(n_temp != NULL)
		{
			if(n_temp->entry.updated != 1)
			{
				if(write(fd ,&n_temp->entry, (sizeof(collector_entry)-sizeof(uint8))) != (sizeof(collector_entry)-sizeof(uint8)))
				{
					printf("Error on writing \n");
				}
				else
				{
					tmp_size++;
				}

			}

			n_temp = n_temp->next;
		}

		
	}
	
	/* Set fd at the beginning of the file */
	if(lseek(fd,0,SEEK_SET) < 0)
	{
		perror("(collector) fseek error: ");
	}

	if(write(fd, &tmp_size, sizeof(uint8)) != sizeof(uint8))
	{
		perror("Error on writing \n");
	}

	printf("FINAL SIZE %d \n",tmp_size);
	/* Clear memory */
	dlinkedlist_clear(list);

    close(fd);
	return 0;
}

void set_length(int new_length, int *length)
{
	if(new_length <= 0)
		fprintf(stderr,"The size of the list can't be zero or negative \n");
	else
	{
		printf("Change length from %d to %d \n",*length,new_length); /* REMOVE */
		*length= new_length;	
	}
}

void clear(DLinkedList *list, int *max_entries)
{
	*max_entries = INIT_ENTRIES;
	dlinkedlist_clear(list);
	printf("CLEAR \n"); /* REMOVE */
}

void update_list_entries(DLinkedList *list, collector_entry new_item, int max_entries, int syn)
{
	struct node *n_temp, *n_older;
	char founded = 0;
	
	if(list != NULL)
	{
		n_temp = list->head; /* First item */
		n_older = n_temp; /* Oldest item */
		printf("ICI!!! \n");
		while(n_temp != NULL)
		{
			/* Search the correct entry */
			if(memcmp(n_temp->entry.sip, new_item.sip,(sizeof(uint8)*16)) == 0 
				&& memcmp(n_temp->entry.dip, new_item.dip,(sizeof(uint8)*16)) == 0 
				&& (n_temp->entry.sport && new_item.sport)
				&& (n_temp->entry.dport && new_item.dport))
			{
				
				dlinkedlist_add_last(list, new_item);
				founded = 1;
			    break;
			}			
			
			/* Remove old one 
			if((new_item.epoch_time - n_temp->entry.epoch_time) > n_older)
				dlinkedlist_remove_node(list,n_temp);*/
			
			/* Keep track of the oldest item */
			/*if(n_temp->entry.epoch_time < n_older->entry.epoch_time)
				n_older = n_temp;	*/
			
			n_temp = n_temp->next;
			
		}
		if(founded == 1)
		{
			dlinkedlist_remove_node(list,n_temp);
		}
		/*if(list->length >= max_entries && n_older != NULL) /* If the list is full, remove the oldest item */
		/*	dlinkedlist_remove_node(list,list->head);
		*/

		if((founded == 0)) /* Don't add a TCP without SYN */
		{		

			if(new_item.protocol != IP_TYPE_TCP || (new_item.protocol == IP_TYPE_TCP && new_item.status&TH_SYN && !(new_item.status&TH_ACK)))
			{
				dlinkedlist_add_last(list, new_item);
			}
			/*dlinkedlist_to_string(list);  TODO REMOVE  FOR DEbuG*/
		}
		
	}

}

void send_protocol_list(DLinkedList *list, int pipe_to_control)
{
	struct node *n_temp;
	uint32 size_list = 0;

	size_list = dlinkedlist_length(list);

	if(list != NULL)
	{	
		if(write(pipe_to_control,&size_list, sizeof(uint32)) != sizeof(uint32)) /*Number of items*/
	    {
	        perror("(controllib) getProtocolList, failed to send state");
	        return;
	    }

		n_temp = list->head;
		while(n_temp != NULL)
		{
			if(write(pipe_to_control,&n_temp->entry, (sizeof(collector_entry)-sizeof(uint8))) != (sizeof(collector_entry)-sizeof(uint8))) /*send items*/
		    {
		        perror("(controllib) getProtocolList, failed to send items");
		        return;
		    }
		 	n_temp = n_temp->next;
		}		
	}
}

void send_protocol_list_from_file(int pipe_to_control)
{
	collector_entry file_entry;
	uint32 size_list = 0;
	int fd ;

	if((fd = open("temp_plist", O_CREAT|O_RDWR, 0644)) < 0)
    {
    	perror("(collector) file open error: ");
    	return;
    }

	/* Set fd at the beginning of the file */
	if(lseek(fd,0,SEEK_SET) < 0)
	{
		perror("(collector) fseek error: ");
	}

    if(read(fd, &size_list, sizeof(uint32)) == 0)
    {
    	if(write(fd, &size_list, sizeof(uint32)) != sizeof(uint32))
    	{
    		perror("(collector) write error: ");
    	}
    }
    printf("SIZE TO SEND %d \n", size_list);
    if(write(pipe_to_control,&size_list, sizeof(uint32)) != sizeof(uint32)) /*Number of items*/
    {
        perror("(controllib) getProtocolList, failed to send state");
        return;
    }

	while(read(fd, &file_entry, (sizeof(collector_entry)-sizeof(uint8))) > 0 )
	{
		printf("[ip.src=%d.%d.%d.%d ip.dst=%d.%d.%d.%d port.dst=%d port.src=%d time=%u ]\n",file_entry.sip[0],file_entry.sip[1],file_entry.sip[2],file_entry.sip[3],file_entry.dip[0],file_entry.dip[1],file_entry.dip[2],file_entry.dip[3],ntohs(file_entry.dport),ntohs(file_entry.sport),ntohs(file_entry.epoch_time));

		if(write(pipe_to_control,&file_entry, (sizeof(collector_entry)-sizeof(uint8))) != 
			(sizeof(collector_entry)-sizeof(uint8))) /*send items*/
	    {
	        perror("(controllib) getProtocolList, failed to send items");
	        return;
	    }
	}
	close(fd);
}

int main(int argc, char *argv[])
{
    int i, nb_b;
	int from_dispatcher, from_control, to_control; /* Communication pipe */
	fd_set fifo_read, ready_read; /* File descriptor */
	int buffer_int[2]; /* Read buffer command, buffer_in[0] -> COMMAND, buffer_in[0] -> VALUE */
	collector_entry buffer_entry; /* Read buffer */
	int max_entries = INIT_ENTRIES; /* Init */
	int time_out = INIT_TIMEOUT; /* Init */
	DLinkedList *list = NULL; /* Empty list */
	int capture_mode = SET_LIVE_MODE;
       
    
    if(argc < 4)
    {
        fprintf(stderr,"need at least 3 arg : PIPE_FROM_COLLECTOR PIPE_FROM_CONTROL PIPE_TO_CONTROL [ARGS ...]\n");
        return EXIT_FAILURE;
    }
    
    /*arg0 = prgr_name, arg1=from_dispatcher, arg2=from_control, arg3=to_control*/
    printf("COLLECTOR\n");
    for(i = 0; i < argc;i++)
    {
        printf("(collector) arg %d : %s\n",i,argv[i]);
    }
    
	/* PIPES */
	if( (from_dispatcher = strtol(argv[1],NULL,10)) == 0)
	{
	 	perror("(collector) failed to convert pipe id from_collector : ");
		exit(EXIT_FAILURE);
	}		
	
	if( (from_control = strtol(argv[2],NULL,10)) == 0)
	{
		perror("(collector) failed to convert pipe id from_control : ");
	   	exit(EXIT_FAILURE);
	}
	
	if( (to_control = strtol(argv[3],NULL,10)) == 0)
	{	
	   perror("(collector) failed to convert pipe id to_control : ");
	   exit(EXIT_FAILURE);
	}
	
	FD_ZERO(&fifo_read);
	FD_SET(from_dispatcher, &fifo_read);
	FD_SET(from_control, &fifo_read);
	
	
	
	list = dlinkedlist_new(); /* Initialization of the list */
	
	while(1)
	{
		ready_read = fifo_read;
		if(select(FD_SETSIZE, &ready_read, NULL, NULL, NULL ) < 0)
		{
			perror("(collector) failed in the select function : ");
			exit(EXIT_FAILURE);
		}
		
		/* FROM DISPATCHER */
		if(FD_ISSET(from_dispatcher,&ready_read))
		{		
			nb_b = read(from_dispatcher, &buffer_entry, sizeof(collector_entry));
			if(nb_b > 0)
				update_list_entries(list, buffer_entry, max_entries, time_out);
			else
			{
				fprintf(stderr,"(collector) Reading error from dispatcher \n");
				return EXIT_FAILURE;
			}
		}
		
		/* FROM CONTROL */
		if(FD_ISSET(from_control,&ready_read))
		{
			nb_b = read(from_control, buffer_int, sizeof(int)*2);
			if(nb_b > 0)
			{
				switch(buffer_int[0])
				{
					case COMMAND_SET_BUFFER_LENGTH_PROTO_LIST:
						set_length(buffer_int[1],&max_entries);
						break;
					case COMMAND_CLEAR_PROTO_LIST:
						clear(list,&max_entries);
						break;
					case COMMAND_GET_PROTOCOL_LIST:
						
						if(capture_mode == SET_LIVE_MODE)
						{
							send_protocol_list(list,to_control);					
						}
						else
						{
							dump(list);
							send_protocol_list_from_file(to_control);
						}
						break;
					case SET_LIVE_MODE:
						clear(list,&max_entries);
						capture_mode = SET_LIVE_MODE;
						printf("(collector) LIVE MODE \n");
						break;
					case SET_FILE_MODE:
						clear(list,&max_entries);
						capture_mode = SET_FILE_MODE;
						unlink("./temp_plist");
						printf("(collector) FILE MODE \n");
						break;
					default:
						printf("Error, command unknown: %d \n", buffer_int[0]);
				}
			}
			else
			{
				fprintf(stderr,"(collector) Reading error from control \n");
				return EXIT_FAILURE;

			}
		}
	}
    
    return EXIT_SUCCESS;
}


