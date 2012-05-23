#include <stdio.h> /*printf, fprintf*/
#include <stdlib.h> /*exit, atoi*/
#include <sys/select.h> /* Select */
#include <errno.h>
#include "./command.h"
#include "./collectorlib/collectorlib.h"

int capture_mode;

void set_length(int new_length, int *length)
{
	if(new_length <= 0)
		fprintf(stderr,"(collector) The size of the list can't be zero or negative \n");
	else
	{
		printf("(collector) Change length from %d to %d \n",*length,new_length); /* REMOVE */
		*length= new_length;	
	}
}

void send_protocol_list(DLinkedList *list, DLinkedList *list_time, int pipe_to_control)
{
	struct node *n_temp = NULL;
	struct struct_proto * proto_tmp;
	struct_ip * ip_tmp = NULL;
	collector_entry file_entry; /* An element in the file */
	int size_entry_file = (sizeof(collector_entry)-(2*sizeof(uint8))), count = 0;

	if(list != NULL)
	{
		if(write(pipe_to_control,&list_time->length, sizeof(uint32)) != sizeof(uint32)) /*Number of items*/
	    {
	        perror("(controllib) getProtocolList, failed to send state");
	        return;
	    }

		n_temp = list->head; /* First item */
        for(;n_temp != NULL;count++)
		{
			/*printf("[ip.src=%d.%d.%d.%d ip.dst=%d.%d.%d.%d ]\n",((struct_ip*)n_temp->entry)->sip[0],((struct_ip*)n_temp->entry)->sip[1],((struct_ip*)n_temp->entry)->sip[2],((struct_ip*)n_temp->entry)->sip[3],((struct_ip*)n_temp->entry)->dip[0],((struct_ip*)n_temp->entry)->dip[1],((struct_ip*)n_temp->entry)->dip[2],((struct_ip*)n_temp->entry)->dip[3]
			);*/
			ip_tmp = ((struct_ip*)n_temp->entry);
			proto_tmp = ((struct_ip*)n_temp->entry)->first_child;
			while(proto_tmp != NULL)
			{
				memcpy(file_entry.sip, ip_tmp->sip,sizeof(ip_tmp->sip)); /* IP SRC */
				memcpy(file_entry.dip, ip_tmp->dip,sizeof(ip_tmp->dip)); /* IP DST */				
				memcpy(&file_entry.sport,proto_tmp->data , sizeof(file_entry.sport)); /* SOURCE port */
				memcpy(&file_entry.dport, &proto_tmp->data[sizeof(file_entry.sport)] ,sizeof(file_entry.dport)); /* DESTINATION port */
				file_entry.ver = ip_tmp->ver; /* VERSION */
				file_entry.protocol = proto_tmp->protocol; /* PROTOCOL */
				file_entry.epoch_time = proto_tmp->epoch_time; /* TIME */

				/*printf("(collector) debug : TIME %d \n",file_entry.epoch_time);*/
				if(write(pipe_to_control ,&file_entry, size_entry_file) != size_entry_file)
				{

					perror("(collector) write error: \n");
				}

				if(proto_tmp->next == NULL) /* End of the list of proto */
					break;
				proto_tmp = proto_tmp->next; /* Next Proto structure */
			}
			n_temp = n_temp->next;
		}
        printf("count = %d vs list_time->length = %lu\n",count, list_time->length);		
	}
}

void send_protocol_list_from_file(int pipe_to_control)
{
	collector_entry file_entry;
	uint32 size_list = 0;
	int fd ;
	int size_entry_file = (sizeof(collector_entry)-(2*sizeof(uint8)));

	if((fd = open("temp_plist", O_CREAT|O_RDWR, 0644)) < 0)
    {
    	perror("(collector) file open error: ");
    	return;
    }

	/* Set fd at the beginning of the file */
	if(lseek(fd,0,SEEK_SET) < 0)
	{
		perror("(collector) fseek error: ");
        close(fd);
        return;
	}

    if(read(fd, &size_list, sizeof(uint32)) == 0)
    {
    	if(write(fd, &size_list, sizeof(uint32)) != sizeof(uint32))
    	{
    		perror("(collector) write error: ");
            close(fd);
            return;
    	}
    }
    printf("(collector) SIZE TO SEND %d \n", size_list);
    if(write(pipe_to_control,&size_list, sizeof(uint32)) != sizeof(uint32)) /*Number of items*/
    {
        perror("(collector) getProtocolList, failed to send state");
        close(fd);
        return;
    }

	while(read(fd, &file_entry, size_entry_file) > 0 )
	{
		/*printf("[ip.src=%d.%d.%d.%d ip.dst=%d.%d.%d.%d port.dst=%d port.src=%d time=%u ]\n",file_entry.sip[0],file_entry.sip[1],file_entry.sip[2],file_entry.sip[3],file_entry.dip[0],file_entry.dip[1],file_entry.dip[2],file_entry.dip[3],ntohs(file_entry.dport),ntohs(file_entry.sport),ntohs(file_entry.epoch_time));*/
		
		if(write(pipe_to_control,&file_entry, size_entry_file) != 
			size_entry_file) /*send items*/
	    {
	        perror("(collector) getProtocolList, failed to send items");
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
	DLinkedList *list = NULL; /* Empty list */
	DLinkedList *list_time = NULL; /* Empty list ordered by time */
	
	/* INIT*/
	capture_mode = LIVE_MODE;
       
    
    if(argc < 4)
    {
        fprintf(stderr,"(collector) need at least 3 arg : PIPE_FROM_COLLECTOR PIPE_FROM_CONTROL PIPE_TO_CONTROL [ARGS ...]\n");
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
	list_time = dlinkedlist_new();

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
				update_list_entries(list, list_time, buffer_entry, max_entries);
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
						clear(list, list_time);				
						break;
					case COMMAND_GET_PROTOCOL_LIST:		
						if(capture_mode == LIVE_MODE )
						{
							send_protocol_list(list,list_time,to_control);					
						}
						else
						{
							dump(list, list_time);
							send_protocol_list_from_file(to_control);
						}
						break;
					case LIVE_MODE:
						clear(list, list_time);
						capture_mode = LIVE_MODE;
						printf("(collector) LIVE MODE \n");
						break;
					case FILE_MODE:
						clear(list, list_time);
						capture_mode = FILE_MODE;
						unlink("./temp_plist");
						printf("(collector) FILE MODE \n");
						break;
					default:
						printf("(collector) Error, command unknown: %d \n", buffer_int[0]);
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


