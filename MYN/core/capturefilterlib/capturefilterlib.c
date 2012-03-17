#include "capturefilterlib.h"

void initFilter()
{
    master_filter.filter_first_node = NULL;
    master_filter.current_breakpoint = 0;
}

int insertNode(struct filter_item ** flist, int i, struct bpf_program filter, char insert_true, int j)
{
    struct filter_node * node_tmp = NULL, * node_tmp2 = NULL;
    struct filter_item * item_tmp = NULL;
    
    /*on recupere le premier fils de gauche ou de droite*/
    if(insert_true)
    {
        node_tmp = flist[i]->next_child_t;
    }
    else
    {
        node_tmp = flist[i]->next_child_f;
    }

    /*on regarde s'il y a un fils a gauche ou a droite deja existant qui serait equivalent a celui que l'on souhaite inserer*/
    for(;node_tmp != NULL;node_tmp = node_tmp->next)
    {
        if(node_tmp->item->code == filter.bf_insns[j].code && node_tmp->item->k == filter.bf_insns[j].k)
        {
            item_tmp = node_tmp->item;
            break;
        }
    }
    
    /*si le branchement n'existe pas encore dans le system, on le cree*/
    if(item_tmp == NULL)
    {
        /*on cree le nouveau noeud*/
        if( (node_tmp = malloc(sizeof(struct filter_node))) == NULL )
        {
            perror("(capturefilterlib) insertNode, failed to allocate a new filter node:");
            return -1;
        }
        
        /*on a deja trouvé/généré un noeud pour un noeud precedent ?*/
        if(flist[j] == NULL)
        {
            if( (node_tmp->item = malloc(sizeof(struct filter_item))) == NULL )
            {
                perror("(capturefilterlib) insertNode, failed to allocate a new filter item:");
                free(node_tmp);
                return -1;
            }

            node_tmp->item->code = filter.bf_insns[j].code;
            node_tmp->item->k = filter.bf_insns[j].k;
            node_tmp->item->next_child_f = NULL;
            node_tmp->item->next_child_t = NULL;
            node_tmp->item->parent = flist[i];
        }
        else
        {
            if(BPF_CLASS(flist[j]->code) == BPF_RET)
            {
                if( (node_tmp2 = malloc(sizeof(struct filter_node))) == NULL )
                {
                    perror("(capturefilterlib) insertNode, failed to allocate a new filter node (2):");
                    free(node_tmp);
                    return -1;
                }
                
                /*on ajoute le parent dans la liste de l'element terminal*/
                node_tmp2->item = flist[i];
                node_tmp2->next = flist[j]->next_child_t;
                flist[j]->next_child_t = node_tmp2;
            }
            else
            {
                /*TODO seul les noeuds terminaux peuvent avoir plusieurs parents, sinon risque de creer des programmes paralelle lors des fusions*/
                fprintf(stderr,"!!! WARNING !!! : no-terminal item with several parent %u\n",flist[i]->code);
            }
            
            node_tmp->item = flist[j];
        }

        if(insert_true)
        {
            node_tmp->next = flist[i]->next_child_t;
            flist[i]->next_child_t = node_tmp;
        }
        else
        {
            node_tmp->next = flist[i]->next_child_f;
            flist[i]->next_child_f = node_tmp;
        }
    }
    
    flist[j] = node_tmp->item;
    return 0;
}

int addFilter(const char * filter_string, int filter_id, int pipe)
{
    int i;
    pcap_t * descr;
    struct bpf_program filter;
    struct filter_item ** flist;
    struct filter_node * node_tmp;
    
    /*compilation du filtre*/
    if( (descr = pcap_open_dead(DLT_EN10MB,pipe)) == NULL)
    {
        fprintf(stderr,"(capturefilterlib) addFilter, pcap_open_dead : %s\n",pcap_geterr(descr));
        return -1;
    }
    
    /*tentative de compilation du filtre*/
    if(pcap_compile(descr,&filter, filter_string,1,0) != 0)
    {
        fprintf(stderr,"(capturefilterlib) addFilter, pcap_compile : %s\n",pcap_geterr(descr));
        pcap_close(descr);
        return -1;
    }
    pcap_close(descr);
    
    if(filter.bf_len < 1)
    {
        fprintf(stderr,"(capturefilterlib) addFilter, filter size is lower than 1\n");
        pcap_freecode(&filter);
        return -1;
    }
    
    if( (flist = calloc(filter.bf_len, sizeof(struct filter_item *))) ==NULL )
    {
        perror("(capturefilterlib) addFilter, failed to allocate filter_node tab");
        pcap_freecode(&filter);
        return -1;
    }
    
    /*recherche d'un noeud root compatible*/
    node_tmp = master_filter.filter_first_node;
    for(;node_tmp != NULL;node_tmp = node_tmp->next)
    {
        if(node_tmp->item->code == filter.bf_insns[0].code && node_tmp->item->k == filter.bf_insns[0].k)
        {
            break;
        }
    }
    
    /*on cree un nouveau noeud root*/
    if(node_tmp == NULL)
    {
        /*on cree le nouveau noeud*/
        if( (node_tmp = malloc(sizeof(struct filter_node))) == NULL )
        {
            perror("(capturefilterlib) addFilter, failed to allocate a new filter node:");
            pcap_freecode(&filter);
            free(flist);
            return -1;
        }
        
        if( (node_tmp->item = malloc(sizeof(struct filter_item))) == NULL )
        {
            perror("(capturefilterlib) addFilter, failed to allocate a new filter item:");
            pcap_freecode(&filter);
            free(flist);
            free(node_tmp);
            return -1;
        }
        
        node_tmp->item->next_child_t = NULL;
        node_tmp->item->next_child_f = NULL;
        node_tmp->item->parent = NULL;
        
        node_tmp->item->code = filter.bf_insns[0].code;
        node_tmp->item->k = filter.bf_insns[0].k;
        
        /*on fait le chainage avec la liste des roots*/
        node_tmp->next = master_filter.filter_first_node;
        master_filter.filter_first_node = node_tmp;
    }
    
    flist[0] = node_tmp->item;
    
    /*exploration insertion a partir de flist[0]*/
    for(i=0;i<filter.bf_len;i++)
    {
        if(BPF_CLASS(flist[i]->code) == BPF_JMP)
        {
            if(BPF_OP(flist[i]->code) == BPF_JA)
            {
                /*check le fils a K*/
                if(insertNode(flist, i, filter, 1, filter.bf_insns[i].k+i+1) != 0)
                {
                    
                    /*TODO decapsulate from here*/
                    
                    free(flist);
                    pcap_freecode(&filter);
                    return -1;
                }
            }
            else
            {
                /*check le fils true*/
                if(insertNode(flist, i, filter, 1, filter.bf_insns[i].jt+i+1) != 0)
                {
                    
                    /*TODO decapsulate from here*/
                    
                    free(flist);
                    pcap_freecode(&filter);
                    return -1;
                }
                
                /*check le fils false*/
                if(insertNode(flist, i, filter, 0, filter.bf_insns[i].jf+i+1) != 0)
                {
                    /*TODO decapsulate from here*/
                    
                    free(flist);
                    pcap_freecode(&filter);
                    return -1;
                }
            }
        }
        else if(BPF_CLASS(flist[i]->code) != BPF_RET)
        {
            /*check le fils suivant si ce n'est pas un endpoint*/
            if(insertNode(flist, i, filter, 1, i+1) != 0)
            {
                /*TODO decapsulate from here*/
                
                free(flist);
                pcap_freecode(&filter);
                return -1;
            }
        }
        /*
        else
        {
            il ne reste que les end point a gerer, s'il ne sont pas inserer par un jump ou autre, c'est que personne n'y accede
        }*/
    }
    
    free(flist);
    pcap_freecode(&filter);
    
    return 0;
}

void removeItem(struct filter_item * parent, struct filter_item * item)
{
    struct filter_node * node_tmp, * node_tmp2;
    if(item != NULL)
    {
        if(BPF_CLASS(item->code) == BPF_RET)
        {
            if(item->parent == parent)
            {
                item->parent = NULL;
            }
            else
            {
                if(item->next_child_t->item == parent)
                {
                    item->next_child_t = item->next_child_t->next;
                }
                else
                {
                    node_tmp = item->next_child_t;
                    node_tmp2 = item->next_child_t->next;
                    while(node_tmp2 != NULL)
                    {
                        if(node_tmp2->item == parent)
                        {
                            node_tmp->next = node_tmp2->next;
                            free(node_tmp2);
                            break;
                        }
                        
                        node_tmp = node_tmp2;
                        node_tmp2 = node_tmp2->next;
                    }
                }
            }
            
            if(item->parent == NULL && item->next_child_t == NULL)
            {
                free(item);
                if(item->k != 0)
                {
                    close(item->k);
                }
            }
        }
        else
        {
            node_tmp = item->next_child_t;
            while(node_tmp != NULL)
            {
                removeItem(item,node_tmp->item);

                node_tmp2 = node_tmp->next;
                free(node_tmp);
                node_tmp = node_tmp2;
            }

            node_tmp = item->next_child_f;
            while(node_tmp != NULL)
            {
                removeItem(item,node_tmp->item);

                node_tmp2 = node_tmp->next;
                free(node_tmp);
                node_tmp = node_tmp2;
            }

            free(item);
        }
    }    
}

int removeFilter(int end_node_id)
{
    /*TODO*/
    return 0;
}

void removeAllFilter()
{
    struct filter_node * node_tmp, *node_tmp2;
    
    node_tmp =master_filter.filter_first_node;
    while(node_tmp != NULL)
    {
        removeItem(NULL,node_tmp->item);
        node_tmp2 = node_tmp;
        node_tmp = node_tmp->next;
        free(node_tmp2);
    }
    master_filter.filter_first_node = NULL;
}

int sendToAllNode(register const uint8 *p,unsigned int buflen, struct timeval ts)
{
    struct filter_node * root_node = master_filter.filter_first_node, * node_tmp;
    struct filter_item * pc;
    
    register uint32 A, X;
	register int k;
	sint32 mem[BPF_MEMWORDS];
    
    while(root_node != NULL)
    {
        master_filter.current_breakpoint = -1;
        pc = root_node->item;
        
        while(1)
        {
            switch (pc->code) 
    		{
        		default:
                    fprintf(stderr,"(capturefilterlib) sendToAllNode, warning unknwon bpf instruction\n");
                    return -1;
        		case BPF_RET|BPF_K:
        			if( ((u_int)pc->k) != 0)
        			{
        			    buflen -= link_info.header_size;
                        write(pc->k,&ts,sizeof(struct timeval));
                        write(pc->k,&buflen,sizeof(unsigned int));/*TODO verifier la valeur de retour si le wait plante*/
        			    write(pc->k,&p[link_info.header_size],buflen);/*TODO verifier la valeur de retour si le wait plante*/
        			}
    			
        			while(master_filter.current_breakpoint >= 0)
    			    {
    			        if(master_filter.breakpoint_stack[master_filter.current_breakpoint].next_instruct != NULL)
    			        {
    			            /*restore break point*/
                            pc = master_filter.breakpoint_stack[master_filter.current_breakpoint].next_instruct->item;
                            A = master_filter.breakpoint_stack[master_filter.current_breakpoint].A;
                            X = master_filter.breakpoint_stack[master_filter.current_breakpoint].X;
                            k = master_filter.breakpoint_stack[master_filter.current_breakpoint].k;
                        
                            /*TODO copy the mem*/
                        
                            /*prepare the next break point*/
                            master_filter.breakpoint_stack[master_filter.current_breakpoint].next_instruct = master_filter.breakpoint_stack[master_filter.current_breakpoint].next_instruct->next;
                        
                            continue;
    			        }
                        master_filter.current_breakpoint--;
    			    }
			    
                    goto MAIN_WHILE_CONTINUE;

        		case BPF_RET|BPF_A:
        			if( ((u_int)A) != 0)
        			{
        			    buflen -= link_info.header_size;
        			    write(pc->k,&ts,sizeof(struct timeval));
                        write(pc->k,&buflen,sizeof(unsigned int));/*TODO verifier la valeur de retour si le wait plante*/
        			    write(pc->k,&p[link_info.header_size],buflen);/*TODO verifier la valeur de retour si le wait plante*/
        			}
    			
        			while(master_filter.current_breakpoint >= 0)
    			    {
    			        if(master_filter.breakpoint_stack[master_filter.current_breakpoint].next_instruct != NULL)
    			        {
    			            /*restore break point*/
                            pc = master_filter.breakpoint_stack[master_filter.current_breakpoint].next_instruct->item;
                            A = master_filter.breakpoint_stack[master_filter.current_breakpoint].A;
                            X = master_filter.breakpoint_stack[master_filter.current_breakpoint].X;
                            k = master_filter.breakpoint_stack[master_filter.current_breakpoint].k;
                        
                            /*TODO copy the mem*/
                        
                            /*prepare the next break point*/
                            master_filter.breakpoint_stack[master_filter.current_breakpoint].next_instruct = master_filter.breakpoint_stack[master_filter.current_breakpoint].next_instruct->next;
                        
                            continue;
    			        }
                        master_filter.current_breakpoint--;
    			    }
			    
                    goto MAIN_WHILE_CONTINUE;

        		case BPF_LD|BPF_W|BPF_ABS:
        			k = pc->k;
        			if (k + sizeof(sint32) > buflen) 
        			{
        				return 0;
        			}
        			A = EXTRACT_LONG(&p[k]);
        			break;

        		case BPF_LD|BPF_H|BPF_ABS:
        			k = pc->k;
        			if (k + sizeof(short) > buflen)
        			{
        				return 0;
        			}
        			A = EXTRACT_SHORT(&p[k]);
        			break;

        		case BPF_LD|BPF_B|BPF_ABS:
        			k = pc->k;
        			if (k >= buflen) 
        			{
        				return 0;
        			}
        			A = p[k];
        			break;

        		case BPF_LD|BPF_W|BPF_LEN:
        			A = buflen;
        			break;

        		case BPF_LDX|BPF_W|BPF_LEN:
        			X = buflen;
        			break;

        		case BPF_LD|BPF_W|BPF_IND:
        			k = X + pc->k;
        			if (k + sizeof(sint32) > buflen) 
        			{
        				return 0;
        			}
        			A = EXTRACT_LONG(&p[k]);
        			break;

        		case BPF_LD|BPF_H|BPF_IND:
        			k = X + pc->k;
        			if (k + sizeof(short) > buflen) 
        			{
        				return 0;
        			}
        			A = EXTRACT_SHORT(&p[k]);
        			break;

        		case BPF_LD|BPF_B|BPF_IND:
        			k = X + pc->k;
        			if (k >= buflen) 
        			{
        				return 0;
        			}
        			A = p[k];
        			break;

        		case BPF_LDX|BPF_MSH|BPF_B:
        			k = pc->k;
        			if (k >= buflen) 
        			{
        				return 0;
        			}
        			X = (p[pc->k] & 0xf) << 2;
        			break;

        		case BPF_LD|BPF_IMM:
        			A = pc->k;
        			break;

        		case BPF_LDX|BPF_IMM:
        			X = pc->k;
        			break;

        		case BPF_LD|BPF_MEM:
        			A = mem[pc->k];
        			break;

        		case BPF_LDX|BPF_MEM:
        			X = mem[pc->k];
        			break;

        		case BPF_ST:
        			mem[pc->k] = A;
        			break;

        		case BPF_STX:
        			mem[pc->k] = X;
        			break;

        		case BPF_JMP|BPF_JA:
        			/*pc += pc->k;*/
        			break;

        		case BPF_JMP|BPF_JGT|BPF_K:
        			node_tmp = (A > pc->k) ? pc->next_child_t : pc->next_child_f;
        			goto jump;

        		case BPF_JMP|BPF_JGE|BPF_K:
        			node_tmp = (A >= pc->k) ? pc->next_child_t : pc->next_child_f;
        			goto jump;

        		case BPF_JMP|BPF_JEQ|BPF_K:
        			node_tmp = (A == pc->k) ? pc->next_child_t : pc->next_child_f;
        			goto jump;

        		case BPF_JMP|BPF_JSET|BPF_K:
        			node_tmp = (A & pc->k) ? pc->next_child_t : pc->next_child_f;
        			goto jump;

        		case BPF_JMP|BPF_JGT|BPF_X:
        			node_tmp = (A > X) ? pc->next_child_t : pc->next_child_f;
        			goto jump;

        		case BPF_JMP|BPF_JGE|BPF_X:
        			node_tmp = (A >= X) ? pc->next_child_t : pc->next_child_f;
        			goto jump;

        		case BPF_JMP|BPF_JEQ|BPF_X:
        			node_tmp = (A == X) ? pc->next_child_t : pc->next_child_f;
        			goto jump;

        		case BPF_JMP|BPF_JSET|BPF_X:
        			node_tmp = (A & X) ? pc->next_child_t : pc->next_child_f;
        			goto jump;

        		case BPF_ALU|BPF_ADD|BPF_X:
        			A += X;
        			break;

        		case BPF_ALU|BPF_SUB|BPF_X:
        			A -= X;
        			break;

        		case BPF_ALU|BPF_MUL|BPF_X:
        			A *= X;
        			break;

        		case BPF_ALU|BPF_DIV|BPF_X:
        			if (X == 0)
        				return 0;
        			A /= X;
        			break;

        		case BPF_ALU|BPF_AND|BPF_X:
        			A &= X;
        			break;

        		case BPF_ALU|BPF_OR|BPF_X:
        			A |= X;
        			break;

        		case BPF_ALU|BPF_LSH|BPF_X:
        			A <<= X;
        			break;

        		case BPF_ALU|BPF_RSH|BPF_X:
        			A >>= X;
        			break;

        		case BPF_ALU|BPF_ADD|BPF_K:
        			A += pc->k;
        			break;

        		case BPF_ALU|BPF_SUB|BPF_K:
        			A -= pc->k;
        			break;

        		case BPF_ALU|BPF_MUL|BPF_K:
        			A *= pc->k;
        			break;

        		case BPF_ALU|BPF_DIV|BPF_K:
        			A /= pc->k;
        			break;

        		case BPF_ALU|BPF_AND|BPF_K:
        			A &= pc->k;
        			break;

        		case BPF_ALU|BPF_OR|BPF_K:
        			A |= pc->k;
        			break;

        		case BPF_ALU|BPF_LSH|BPF_K:
        			A <<= pc->k;
        			break;

        		case BPF_ALU|BPF_RSH|BPF_K:
        			A >>= pc->k;
        			break;

        		case BPF_ALU|BPF_NEG:
        			A = -A;
        			break;

        		case BPF_MISC|BPF_TAX:
        			X = A;
        			break;

        		case BPF_MISC|BPF_TXA:
        			A = X;
        			break;
    		}
            pc = pc->next_child_t->item;
            continue;
            
            jump:		    
		    /*need to create a break point?*/
		    if(node_tmp->next != NULL)
		    {
                master_filter.current_breakpoint++;
                
                if(master_filter.current_breakpoint == MAX_FILTER_LEVEL)
                {
                    fprintf(stderr,"(capturefilterlib) sendToAllNode, breakpoint stack overflow\n");
                    return -1;
                }
                
                master_filter.breakpoint_stack[master_filter.current_breakpoint].next_instruct = node_tmp->next;
                master_filter.breakpoint_stack[master_filter.current_breakpoint].A = A;
                master_filter.breakpoint_stack[master_filter.current_breakpoint].X = X;
                master_filter.breakpoint_stack[master_filter.current_breakpoint].k = k;
                
                /*TODO copy the memory*/
                
		    }
		    
            pc = node_tmp->item;
    	}
        
        MAIN_WHILE_CONTINUE:
        root_node = root_node->next;
    }
    
    return 0;
}

void traversal()
{
    struct filter_node * filter_node_tmp = master_filter.filter_first_node;
    
    while(filter_node_tmp != NULL)
    {
        innerTraversal(filter_node_tmp->item, 0);
        filter_node_tmp = filter_node_tmp->next;
    }
}

void innerTraversal(struct filter_item * i, int level)
{
    struct filter_node * node_tmp = NULL;
    int j;
        
    for(j = 0;j< level;j++)
    {
        printf(" ");
    }

    printf("(%d) fnode (code:%u - k:%u)\n",level, i->code, i->k);
    if(BPF_CLASS(i->code) != BPF_RET)
    {
        node_tmp = i->next_child_t;
        while(node_tmp != NULL)
        {
            innerTraversal(node_tmp->item, level+1);
            node_tmp = node_tmp->next;
        }

        node_tmp = i->next_child_f;
        while(node_tmp != NULL)
        {
            innerTraversal(node_tmp->item, level+1);
            node_tmp = node_tmp->next;
        }
    }
}

