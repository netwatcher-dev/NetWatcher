#include "controllib.h"

char * file_path = NULL;

int sendEntries(int socket)
{
    pcap_if_t * alldevsp = NULL;
    pcap_if_t * next;

    int size;

    if(pcap_findalldevs(&alldevsp,errbuf)  != 0)
    {
        fprintf(stderr,"(controllib) sendEntries, failed to list all devs : %s\n",errbuf);
        
        /*on indique l'erreur au client*/
        size = htonl(STATE_PCAP_ERROR);
        send(socket,&size, sizeof(size), 0); /*on ne se soucie pas de l'erreur, il y en a deja une*/
        
        return EXIT_FAILURE;
    }

    /*on envoie l'etat courant*/
    size = htonl(STATE_NO_ERROR);
    if( send(socket,&size, sizeof(size), 0) < sizeof(size))
    {
        fprintf(stderr,"(controllib) sendEntries, failed to send the state\n");
        pcap_freealldevs(alldevsp);
        return EXIT_FAILURE;
    }

    /*on envoie la liste des entrees*/
    next = alldevsp;
    while(next != NULL)
    {
        if(writeString(socket, next->name) != 0)
        {
            fprintf(stderr,"(controllib) sendEntries, failed to send an entry\n");
            pcap_freealldevs(alldevsp);
            return EXIT_FAILURE;
        }
        
        next = next->next;
    }

    pcap_freealldevs(alldevsp);

    /*on envoie un integer de 0 pour signaler la fin de la liste*/
    size = 0;
    if( send(socket,&size, sizeof(size), 0) < sizeof(size))
    {
        return EXIT_FAILURE;
    }
    return 0;
}

int getProtocolList(int socket)
{
    int command;
    uint32 response;
    uint32 resp;
    collector_entry entry;
    
    printf("(control) COMMANDE RECEIVED and FORWARDING !!!!\n");
    command = COMMAND_GET_PROTOCOL_LIST;
    if(write(to_collector,&command, sizeof(command)) != sizeof(command))
    {
        perror("(controllib) getProtocolList, failed to send state:");
        return EXIT_FAILURE;
    }

    /* INFORMATION SIZE */
    if(read(from_collector, &response, sizeof(response)) < 0)
    {
        perror("(controllib) getProtocolList size, failed to send state:");
        return EXIT_FAILURE;
    }
    printf("Size recieved %d \n",response);
    response = htonl(response);
    if(send(socket,&response, sizeof(uint32), 0) != sizeof(uint32))
    {
        perror("(controllib) getProtocolList, send information size to command failed:");
        return EXIT_FAILURE;
    }

    response = ntohl(response);
    /* PROTOCOL LIST */
    while((response--) > 0)
    {
        if(read(from_collector, &entry, (sizeof(collector_entry)-2*sizeof(uint8))) < 0)
        {
            perror("(controllib) getProtocolList size, failed to send state:");
            return EXIT_FAILURE;
        }
        
        entry.epoch_time = htonl(entry.epoch_time);/*il n'y a que ce champ à convertir, les autres le sont deja ou sont des bytes*/
        
        if(send(socket,&entry, (sizeof(collector_entry)-2*sizeof(uint8)), 0) != (sizeof(collector_entry)-2*sizeof(uint8)))
        {
            perror("(controllib) getProtocolList, send information to command failed:");
            return EXIT_FAILURE;
        }
    }
    
    /*send answer*/
    resp = htonl(STATE_NO_ERROR);
    if(send(socket,&resp, sizeof(resp), 0) != sizeof(resp))
    {
        perror("(controllib) getProtocolList, failed to send state");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int clearProtocolList(int socket)
{
    int command;
    int response;

    command = COMMAND_CLEAR_PROTO_LIST;
    if(write(to_collector,&command, sizeof(command)) != sizeof(command))
    {
        perror("(controllib) clearProtocolList, failed to send command:");
        return EXIT_FAILURE;
    }

    /*send answer*/
    response = htonl(STATE_NO_ERROR);
    if(send(socket,&response, sizeof(response), 0) != sizeof(response))
    {
        perror("(controllib) clearProtocolList, error");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int setLengthProtocolList(int socket)
{
    int command, value_int;
    int response;
    short value;

    if(  (command = recv(socket,&value,sizeof(short),MSG_WAITALL)) != sizeof(short))
    {
        printf("ret size = %d\n",command);
        perror("(controllib) setLengthProtocolList, failed to receive value");
        return EXIT_FAILURE;
    }

    /* Value verification */
    if(ntohs(value) <= 0)
    {
       response = htonl(STATE_VALUE_POSITIVE_INVALID);
       send(socket,&response, sizeof(response), 0);
       return EXIT_FAILURE;
    }
    else
    {
       /*send answer OK*/
        response = htonl(STATE_NO_ERROR);
        if(send(socket,&response, sizeof(int), 0) != sizeof(int))
            return EXIT_FAILURE;
    }

    /* Sending command */
    command = COMMAND_SET_BUFFER_LENGTH_PROTO_LIST;
    if(write(to_collector,&command, sizeof(command)) != sizeof(command))
    {
        perror("(controllib) setLengthProtocolList, failed to send command:");
        return EXIT_FAILURE;
    }

    /* Sending value */
    value = ntohs(value);
    value_int = value;
    if(write(to_collector,&value_int, sizeof(value_int)) != sizeof(value_int))
    {
        perror("(controllib) setTimeoutProtocolList, failed to send value:");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int selectCaptureDevice(int socket, int command)
{
    pcap_if_t * alldevsp= NULL;
    pcap_if_t * next;

    int response;
    char * string;
    my_args arg;
    
    if(   (string = readString(socket)) == NULL)
    {
        response = htonl(STATE_FAILED_TO_RECEIVED_STRING);
        send(socket,&response, sizeof(response), 0);
        return EXIT_FAILURE;
    }

    printf("(controllib) device received : %s\n",string);

    /*device exists ?*/
    if(pcap_findalldevs(&alldevsp,errbuf)  != 0)
    {
        fprintf(stderr,"(controllib) selectCaptureDevice, failed to list all devs : %s\n",errbuf);
        
        /*on indique l'erreur au client*/
        response = htonl(STATE_PCAP_ERROR);
        send(socket,&response, sizeof(response), 0); /*on ne se soucie pas de l'erreur, il y en a deja une*/
        free(string);
        return EXIT_FAILURE;
    }
    
    
    next = alldevsp;
    while(next != NULL)
    {
        if( strcmp(next->name,string) == 0)
            break;
        
        next = next->next;
    }
    pcap_freealldevs(alldevsp);
    if(next == NULL)
    {
        fprintf(stderr,"(controllib) selectCaptureDevice, unknown device : %s\n",string);
        response = htonl(STATE_UNKNOWN_CAPTURE_DEVICE);
        free(string);
    }
    else
    {
        printf("(controllib) device found\n");

        /*envoi de la commande au dispatch*/
        arg.values = string;
        arg.size = strlen(string)+1;
        arg.type = ARG_SET;
        if( (response = sendCommandToDispatch(command,1, 0,arg)) < 0)
        {
            fprintf(stderr,"(controllib) selectCaptureDevice, failed to send command to dispatch\n");
            response = htonl(STATE_SEND_COMMAND_TO_DISPATCH_FAILED);
            send(socket,&response, sizeof(response), 0);
            free(string);
            return EXIT_FAILURE;
        }

        printf("(controllib) selected device : %s\n",string);
        file_path = string;
        /*free(string);*/

        response = htonl(response);
    }
    
    if(send(socket,&response, sizeof(response), 0) != sizeof(response))
    {
        perror("(controllib) selectCaptureDevice, failed to send state");
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

int selectCaptureFile(int socket)
{
    int response;
    char * string, *string2;
    my_args arg;
    
    if(   (string = readString(socket)) == NULL)
    {
        fprintf(stderr,"(controllib) selectCaptureFile, failed to read string\n");
        response = htonl(STATE_FAILED_TO_RECEIVED_STRING);
        send(socket,&response, sizeof(response), 0); /*on ne se soucie pas de l'erreur*/
        return EXIT_FAILURE;
    }

    if( (string2 = calloc(strlen(string)+17,sizeof(char))) == NULL)
    {
        free(string);
        perror("(controllib) selectCaptureFile, failed to allocate path memory : ");
        response = htonl(STATE_SERVER_ERROR);
        send(socket,&response, sizeof(response), 0); /*on ne se soucie pas de l'erreur*/
        return EXIT_FAILURE;
    }
    strcpy(string2,"./capture_files/");
    strcat(string2,string);
    free(string);
    
    /*file exists ? capture_files */
    if(fileExist(string2)==0)
    {
        fprintf(stderr,"(controllib) selectCaptureFile, file doesn't exist %s\n",string2);
        response = htonl(STATE_UNKNOWN_FILE);
        free(string2);
    }
    else
    {
        /*envoi de la commande au dispatch*/
        arg.values = string2;
        arg.size = strlen(string2)+1;
        arg.type = ARG_SET;
        if( (response = sendCommandToDispatch(COMMAND_SELECT_CAPTURE_FILE,1,0,arg)) < 0)
        {
            /*manage error*/
            fprintf(stderr,"(controllib) selectCaptureFile, failed to send command to dispatch\n");
            response = htonl(STATE_SEND_COMMAND_TO_DISPATCH_FAILED);
            send(socket,&response, sizeof(response), 0);
            free(string2);
            return EXIT_FAILURE;
        }
    
    
        printf("(controllib) selected file : %s\n",string2);
        file_path = string2;
        /*free(string2);*/
    
        response = htonl(response);
    }
    

    if(send(socket,&response, sizeof(response), 0) != sizeof(response))
    {
        perror("(controllib) selectCaptureFile, failed to send state");
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

int setSpeed(int socket)
{
    uint8 value;
    int response = STATE_NO_ERROR;
    my_args arg;
    
    printf("(controllib) set speed in function\n");
    
    if(recv(socket,&value,sizeof(value),MSG_WAITALL) != sizeof(value))
    {
        perror("(controllib) setSpeed, failed to receive value");
        return EXIT_FAILURE;
    }
    
    if( (value & 0x80) )
    {
        printf("(controllib) slower : %u\n",(value&0x7F));
    }
    else
    {
        printf("(controllib) faster : %u\n",(value&0x7F));
    }

    /*envoi de la commande au dispatch*/
    arg.values = &value;
    arg.size = sizeof(uint8);
    arg.type = ARG_SET;
    if( (response = sendCommandToDispatch(COMMAND_SET_SPEED,1,0,arg)) < 0)
    {
        /*manage error*/
        fprintf(stderr,"(controllib) setSpeed, failed to send command to dispatch\n");
        response = htonl(STATE_SEND_COMMAND_TO_DISPATCH_FAILED);
        send(socket,&response, sizeof(response), 0);
        return EXIT_FAILURE;
    }

    response = htonl(response);
    if(send(socket,&response, sizeof(response), 0) != sizeof(response))
    {
        perror("(controllib) setSpeed, failed to send state");
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

int stopCapture(int socket)
{
    int response = STATE_NO_ERROR;
    uint16 id;
    my_args arg;
    
    /*read id*/
    if(recv(socket,&id, sizeof(uint16), MSG_WAITALL) != sizeof(uint16))
    {
        perror("(controllib) startCapture, failed to receive addr");
        return EXIT_FAILURE;
    }
    
    id = ntohs(id);
    
    /*envoi de la commande au dispatch*/
    arg.values = &id;
    arg.size = sizeof(id);
    arg.type = ARG_SET;
    if( (response = sendCommandToDispatch(COMMAND_STOP_CAPTURE,1, 0,arg)) < 0)
    {
        /*manage error*/
        fprintf(stderr,"(controllib) stopCapture, failed to send command to dispatch\n");
        response = htonl(STATE_SEND_COMMAND_TO_DISPATCH_FAILED);
        send(socket,&response, sizeof(response), 0);
        return EXIT_FAILURE;
    }
    
    printf("(controllib) id to stop : %u\n",id);
    
    /*write answer*/
    response = htonl(response);
    if(send(socket,&response, sizeof(response), 0) != sizeof(response))
    {
        perror("(controllib) stopAllCapture, failed to send state");
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

int listFiles(int socket)
{
    DIR * dir;
    struct dirent dir_entry, * dir_result;
    int ret;
    char file[1024];
    
    if( (dir = opendir("./capture_files")) == NULL)
    {
        ret = htonl(STATE_SERVER_ERROR);
        send(socket,&ret, sizeof(ret), 0);
        return EXIT_FAILURE;
    }
    
    ret = htonl(STATE_NO_ERROR);    
    if(send(socket,&ret, sizeof(ret), 0) != sizeof(ret))
    {
        perror("(controllib) listFiles, failed to send state");
        return EXIT_FAILURE;
    }
    
    while ((ret = readdir_r(dir, &dir_entry,&dir_result)) == 0 && dir_result != NULL)
    {
        strcpy(file,"./capture_files/");
        
        if(isDir(strcat(file,dir_entry.d_name)))
           continue;
           
        if(writeString(socket, dir_entry.d_name) != 0)
        {
            fprintf(stderr,"(controllib) listFiles, failed to send an entry\n");
            closedir(dir);
            return -1;
        }
    }
    closedir(dir);
    
    if(ret != 0)
    {
        perror("(controllib) listFiles, readdir_r error");
    }
    
    /*on envoie un integer de 0 pour signaler la fin de la liste*/
    ret = 0;
    if(send(socket,&ret, sizeof(ret), 0) != sizeof(ret))
    {
        perror("(controllib) listFiles, failed to send zero");
        return EXIT_FAILURE;
    }
    
        
    return EXIT_SUCCESS;
}

int startRecord(int socket)
{
    int response;
    char * string, *string2;
    my_args arg;
    
    if(   (string = readString(socket)) == NULL)
    {
        response = htonl(STATE_FAILED_TO_RECEIVED_STRING);
        send(socket,&response, sizeof(response), 0);
        return EXIT_FAILURE;
    }
    
    if( (string2 = calloc(strlen(string)+17,sizeof(char))) == NULL)
    {
        free(string);
        perror("(controllib) selectCaptureFile, failed to allocate path memory : ");
        response = htonl(STATE_SERVER_ERROR);
        send(socket,&response, sizeof(response), 0); /*on ne se soucie pas de l'erreur*/
        return EXIT_FAILURE;
    }
    
    strcpy(string2,"./capture_files/");
    strcat(string2,string);
    free(string);
    
    /*envoi de la commande au dispatch*/
    arg.values = string2;
    arg.size = strlen(string2)+1;
    arg.type = ARG_SET;
    if( (response = sendCommandToDispatch(COMMAND_START_RECORD,1, 0,arg)) < 0)
    {
        /*manage error*/
        fprintf(stderr,"(controllib) startRecord, failed to send command to dispatch\n");
        response = htonl(STATE_SEND_COMMAND_TO_DISPATCH_FAILED);
        send(socket,&response, sizeof(response), 0);
        free(string2);
        return EXIT_FAILURE;
    }
    
    printf("(controllib) record into file : %s\n",string2);
    free(string2);
    
    response = htonl(response);
    if(send(socket,&response, sizeof(response), 0) != sizeof(response))
    {
        perror("(controllib) startRecord, failed to send state");
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

int setCaptureMode(int mode)
{
    /* Sending command */   
    if(write(to_collector,&mode, sizeof(int)) != sizeof(int))
    {
        perror("(controllib) setCaptureMode, failed to send command:");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;

}

int directTransmit(int socket, int command)
{
    int response;
    
    /*envoi de la commande au dispatch*/
    if( (response = sendCommandToDispatch(command,0,0)) < 0)
    {
        /*manage error*/
        fprintf(stderr,"(controllib) directTransmit, failed to send command to dispatch\n");
        response = htonl(STATE_SEND_COMMAND_TO_DISPATCH_FAILED);
        send(socket,&response, sizeof(response), 0);
        return EXIT_FAILURE;
    }
    
    response = htonl(response);
    if(send(socket,&response, sizeof(response), 0) != sizeof(response))
    {
        perror("(controllib) stopRecord, failed to send state");
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

int setFilter(int socket, int command)
{
    uint32 response = STATE_NO_ERROR;
    uint16 port;
    int exit_status=EXIT_SUCCESS;
    char * string;
    my_args arg, arg2;
    
    pcap_t * descr;
    struct bpf_program filter;
    
    /*recuperation de la chaine de caractere du filtre*/
    if(   (string = readString(socket)) == NULL)
    {
        fprintf(stderr,"(controllib) setFilter, failed to read string\n");
        response = STATE_FAILED_TO_RECEIVED_STRING;
        exit_status = EXIT_FAILURE;
        goto end2;
    }
    
    printf("command %d : %s\n",command, string);
    
    /*test du filtre*/
    /*ouverture d'une fausse instance de libcap*/
    if( (descr = pcap_open_dead(DLT_EN10MB,MAXBYTES2CAPTURE)) == NULL)
    {
        fprintf(stderr,"(controllib) setFilter, pcap_open_dead : %s\n",pcap_geterr(descr));
        response = STATE_SERVER_ERROR;
        exit_status = EXIT_FAILURE;
        goto end1;
    }
    
    /*tentative de compilation du filtre*/
    if(pcap_compile(descr,&filter, string,1,0) != 0)
    {
        fprintf(stderr,"(controllib) setFilter, pcap_compile : %s\n",pcap_geterr(descr));
        response = STATE_WRONG_BPF;
        exit_status = EXIT_SUCCESS; /*ce n'est pas un cas d'erreur du programme, mais de l'utilisateur*/
        goto end1;
    }
    pcap_freecode(&filter);
    
    /*transmettre le filtre au dispatch*/
    if(command != COMMAND_TEST_MASTER_FILTER)
    {
        arg.values = string;
        arg.size = strlen(string)+1;
        arg.type = ARG_SET;

        if(command == COMMAND_START_CAPTURE)
        {
            arg2.values = &port;
            arg2.size = sizeof(port);
            arg2.type = ARG_GET;
            
            if( (response = sendCommandToDispatch(command,1,1,arg, arg2)) < 0)
            {
                fprintf(stderr,"(controllib) setFilter, failed to send command to dispatch\n");
                response = STATE_SEND_COMMAND_TO_DISPATCH_FAILED;
                exit_status = EXIT_FAILURE;
                goto end1;
            }
        }
        else
        {
            if( (response = sendCommandToDispatch(command,1,0,arg)) < 0)
            {
                fprintf(stderr,"(controllib) setFilter, failed to send command to dispatch\n");
                response = STATE_SEND_COMMAND_TO_DISPATCH_FAILED;
                exit_status = EXIT_FAILURE;
                goto end1;
            }
        }
        
    }
    
    /*routine de fin, reponse au client*/
    end1:
    free(string);
    end2:
    pcap_close(descr);
    
    response = htonl(response);
    if(send(socket,&response, sizeof(response), 0) != sizeof(response))
    {
        perror("(controllib) setFilter, failed to send state");
        return EXIT_FAILURE;
    }
    
    if(command == COMMAND_START_CAPTURE && response == htonl(STATE_NO_ERROR))
    {
        /*SEND NUMBER*/
        printf("port = %u\n",port);
        port = htons(port);
        if(send(socket,&port, sizeof(port), 0) != sizeof(port))
        {
            perror("(controllib) selectCaptureFile, failed to send port");
            return EXIT_FAILURE;
        }
    }
    
    return exit_status;
}

int file_goto(int socket)
{
    int response = STATE_NO_ERROR;
    uint32 secs, microsecs;
    struct timeval tval;
    my_args arg;
    
    if(recv(socket,&secs,sizeof(secs),MSG_WAITALL) != sizeof(secs))
    {
        perror("(controllib) file_goto, failed to receive secs");
        return EXIT_FAILURE;
    }
    
    if(recv(socket,&microsecs,sizeof(microsecs),MSG_WAITALL) != sizeof(microsecs))
    {
        perror("(controllib) file_goto, failed to receive microsecs");
        return EXIT_FAILURE;
    }
    
    tval.tv_sec = ntohl(secs);
    tval.tv_usec = ntohl(microsecs);
        
    arg.values = &tval;
    arg.size = sizeof(tval);
    arg.type = ARG_SET;
    if( (response = sendCommandToDispatch(COMMAND_FILE_GOTO,1,0,arg)) < 0)
    {
        /*manage error*/
        fprintf(stderr,"(controllib) setSpeed, failed to send command to dispatch\n");
        response = htonl(STATE_SEND_COMMAND_TO_DISPATCH_FAILED);
        send(socket,&response, sizeof(response), 0);
        return EXIT_FAILURE;
    }
        
    response = htonl(response);
    if(send(socket,&response, sizeof(response), 0) != sizeof(response))
    {
        perror("(controllib) setSpeed, failed to send state");
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

int get_state(int socket)
{
    int response = STATE_NO_ERROR;
    my_args arg;
    struct core_state state;
    
    arg.values = &state;
    arg.size = sizeof(state);
    arg.type = ARG_GET;
    
    if( (response = sendCommandToDispatch(COMMAND_GET_STATE,0,1,arg)) < 0)
    {
        /*manage error*/
        fprintf(stderr,"(controllib) get_state, failed to send command to dispatch\n");
        response = htonl(STATE_SEND_COMMAND_TO_DISPATCH_FAILED);
        send(socket,&response, sizeof(response), 0);
        return EXIT_FAILURE;
    }

    response = htonl(response);
    if(send(socket,&response, sizeof(response), 0) != sizeof(response))
    {
        perror("(controllib) setSpeed, failed to send state");
        return EXIT_FAILURE;
    }
    
    printf("Running : %d, Recording : %d, File : %d, Stream : %d, Parsing : %d, Reading : %d, Pause : %d, Goto : %d, Parsed : %d, Finished : %d\n",
        (IS_RUNNING((&state))?1:0), (IS_RECORDING((&state))?1:0),(IS_FILE((&state))?1:0),(IS_STREAM((&state))?1:0),(IS_PARSING((&state))?1:0),
        (IS_READING((&state))?1:0), (IS_PAUSE((&state))?1:0),(IS_GOTO((&state))?1:0),(IS_PARSED((&state))?1:0),(IS_FINISHED((&state))?1:0));
    
    printf("%lu,%.6u sur %lu,%.6u\n",state.file_current.tv_sec,state.file_current.tv_usec,state.file_duration.tv_sec,state.file_duration.tv_usec);
    printf("%d sur %d\n",state.packet_readed, state.packet_in_file);
    printf("file/interface : %s\n",(file_path == NULL)?"none":file_path);
    
    /*envoyer l'etat*/
    state.state = htonl(state.state);
    if(send(socket,&state.state, sizeof(state.state), 0) != sizeof(state.state))
    {
        perror("(controllib) get_state, failed to send state");
        return EXIT_FAILURE;
    }
    
    state.packet_readed = htonl(state.packet_readed);
    if(send(socket,&state.packet_readed, sizeof(state.packet_readed), 0) != sizeof(state.packet_readed))
    {
        perror("(controllib) get_state, failed to send packet_readed");
        return EXIT_FAILURE;
    }
    
    state.packet_in_file = htonl(state.packet_in_file);
    if(send(socket,&state.packet_in_file, sizeof(state.packet_in_file), 0) != sizeof(state.packet_in_file))
    {
        perror("(controllib) get_state, failed to send packet_in_file");
        return EXIT_FAILURE;
    }
    
    state.file_current.tv_sec = htonll(state.file_current.tv_sec);
    if(send(socket,&state.file_current.tv_sec, sizeof(state.file_current.tv_sec), 0) != sizeof(state.file_current.tv_sec))
    {
        perror("(controllib) get_state, failed to send file_current.tv_sec");
        return EXIT_FAILURE;
    }
    
    state.file_current.tv_usec = htonll(state.file_current.tv_usec);
    if(send(socket,&state.file_current.tv_usec, sizeof(state.file_current.tv_usec), 0) != sizeof(state.file_current.tv_usec))
    {
        perror("(controllib) get_state, failed to send file_current.tv_usec");
        return EXIT_FAILURE;
    }
    
    state.file_duration.tv_sec = htonll(state.file_duration.tv_sec);
    if(send(socket,&state.file_duration.tv_sec, sizeof(state.file_duration.tv_sec), 0) != sizeof(state.file_duration.tv_sec))
    {
        perror("(controllib) get_state, failed to send file_duration.tv_sec");
        return EXIT_FAILURE;
    }
    
    state.file_duration.tv_usec = htonll(state.file_duration.tv_usec);
    if(send(socket,&state.file_duration.tv_usec, sizeof(state.file_duration.tv_usec), 0) != sizeof(state.file_duration.tv_usec))
    {
        perror("(controllib) get_state, failed to send file_duration.tv_usec");
        return EXIT_FAILURE;
    }
    
    /*envoyer la source*/
    if(writeString(socket,(file_path == NULL)?"":file_path) != 0)
    {
        fprintf(stderr,"(controllib) get_state, failed to send an entry\n");
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

int disable_device(int socket)
{
    if(file_path != NULL)
    {
        free(file_path);
        file_path = NULL;
    }
    
    return directTransmit(socket,COMMAND_DISABLE_CAPTURE_DEVICE);
}

int sendCommandToDispatch(int command, int argc_set, int argc_get, ...)
{   
    va_list ap;
    int i;
    my_args argx;
    void * dest;
            
    /*on verrouille la memoire*/
    if(openMemory(mem)< 0)
    {
        perror("(controllib) sendCommandToDispatch, failed to open memory (1):");
        return EXIT_FAILURE;
    }
    
    /*on nettoye la memoire des dernieres donnees*/
    cleanAreaMemories(mem);
    
    setAction(mem,command);
    
    va_start(ap, argc_get);
    for(i = 0;i<argc_set;i++)
    {
        argx = va_arg(ap, my_args);
        if( (dest = getNextAvailableAreaMemory(mem, argx.size)) == NULL)
        {
            fprintf(stderr,"(controllib) sendCommandToDispatch, failed to allocate memory area on shared memory\n");
            closeMemory(mem);
            return EXIT_FAILURE;
        }
        
        memcpy(dest,argx.values,argx.size);

    }
    
    
    /*on deverrouille la memoire*/
    if(closeMemory(mem)< 0)
    {
        perror("(controllib) sendCommandToDispatch, failed to close memory (1):");
        va_end(ap);
        return EXIT_FAILURE;
    }
    
    /*on attend le semaphore du dispatch, il doit avoir fini de traiter la commande precedente
    printf("(controllib) lock\n");
    if(lockSem(mem->semDescr, 1) < 0)
    {
        perror("(controllib) sendCommandToDispatch, failed to wait semaphore from dispatch");
        va_end(ap);
        return EXIT_FAILURE;
    }
    printf("(controllib) delock\n");*/
    
    /*send signal*/
    if(kill(dispatch_id,SIGUSR1)<0)
    {
        perror("(controllib) sendCommandToDispatch, failed to send signal to dispatch:");
        va_end(ap);
        return EXIT_FAILURE;
    }
    
    printf("(controllib) lock\n");
    /*on attend le semaphore du dispatch, il doit avoir fini de lire la memoire partagée*/
    if(lockSem(mem->semDescr, 1) < 0)
    {
        perror("(controllib) sendCommandToDispatch, failed to wait semaphore from dispatch");
        va_end(ap);
        return EXIT_FAILURE;
    }
    printf("(controllib) delock\n");
    
    /*on verrouille la memoire*/
    if(openMemory(mem)< 0)
    {
        perror("(controllib) sendCommandToDispatch, failed to open memory (2):");
        va_end(ap);
        return EXIT_FAILURE;
    }
    
    /*on recupere les reponses s'il doit y en avoir*/
    for(i = 0;i<argc_get;i++)
    {
        argx = va_arg(ap, my_args);
        
        if( getAreaMemory(mem,i,&dest,&i) != 0)
        {
            fprintf(stderr,"(controllib) sendCommandToDispatch, failed to load memory at index %d\n",i);
            break;
        }
        
        memcpy(argx.values,dest,argx.size);
    }
    va_end(ap);
    
    /*on lit l'etat dans la memoire l'etat du dispatch*/
    i = getState(mem);
    
    /*on deveroulle la memoire*/
    if(closeMemory(mem)< 0)
    {
        perror("(controllib) sendCommandToDispatch, failed to close memory (2):");
        return EXIT_FAILURE;
    }
    
    /*on retourne l'etat*/
    return i;
}
