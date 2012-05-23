#include "capturefilterlib.h"

void initFilter()
{
    master_filter.filter_first_node = NULL;
    master_filter.current_breakpoint = 0;
    master_filter.end_node = NULL;
    master_filter.max_filter_level_count = 0;
}

/*
 *  
 */
int compileGraph(const char * filter_string, struct bpf_program * filter, int id)
{
    pcap_t * descr;
    
    /*creation d'un descripteur sur une interface inexistante, elle sert juste à la compilation du filtre*/
    if( (descr = pcap_open_dead(link_info.datalink_type,id)) == NULL)
    {
        fprintf(stderr,"(capturefilterlib) compileGraph, pcap_open_dead : %s\n",pcap_geterr(descr));
        return -1;
    }
    
    /*tentative de compilation du filtre*/
    if(pcap_compile(descr,filter, filter_string,1,0) != 0)
    {
        fprintf(stderr,"(capturefilterlib) compileGraph, pcap_compile : %s\n",pcap_geterr(descr));
        pcap_close(descr);
        return -1;
    }
    
    /*fermeture de l'interface inexistante*/
    pcap_close(descr);
    
    return 0;
}

/*
 *  cette methode explore le graphe existant et compte le nombre de noeud NON TERMINAUX necessaire pour la mise a plat du graphe   
 */
unsigned int countNoTerminalNodes(struct bpf_program * filter, int i)
{
    if(BPF_CLASS(filter->bf_insns[i].code) == BPF_JMP)
    {
        if(BPF_OP(filter->bf_insns[i].code) == BPF_JA)
        {
            return 1 + countNoTerminalNodes(filter,filter->bf_insns[i].k+i+1);
        }
        else
        {
            return 1 + countNoTerminalNodes(filter,filter->bf_insns[i].jt+i+1) 
            + countNoTerminalNodes(filter,filter->bf_insns[i].jf+i+1);
        }
    }
    else if(BPF_CLASS(filter->bf_insns[i].code) != BPF_RET)
    {
        return 1 + countNoTerminalNodes(filter,i+1);
    }
    
    /*on ne compte pas les noeuds terminaux ici*/
    
    return 0;
}

/*
 *  cette methode explore le graphe existant et compte le nombre de noeud TERMINAUX necessaire pour la mise a plat du graphe   
 */
unsigned int countTerminalNodes(struct bpf_program * filter)
{
    unsigned int ret = 0, i;
    
    for(i=0;i<filter->bf_len;i++)
    {
        if(  BPF_CLASS(filter->bf_insns[i].code) == BPF_RET )
        {
            ret += 1;
        }
    }
    
    return ret;
}

/*
 * cette fonction met a plat un graphe bpf
 *
 * @param graph : le graphe applati à remplir
 * @param filter : le graphe bpf à convertir
 * @param non_terminal_count : le nombre de noeud non terminaux dans le graphe applati
 * @param terminal_count : le nombre de noeud terminaux dans le graphe
 * @param i : l'indice de l'instruction dans le graphe bpf
 * @param id : le prochain identifiant disponible pour ajouter un noeud
 * @return : l'id du noeud ajouté dans l'appel de la fonction
 */
int flatteGraph(struct flatten_item * graph, struct bpf_program * filter,int non_terminal_count, int terminal_count, int i, int * id)
{
    int current_id, indice;
    
    if(BPF_CLASS(filter->bf_insns[i].code) == BPF_JMP) /*JUMP INSTRUCTION*/
    {
        current_id = (*id)++;
        graph[current_id].bf_instruct_link = i;
        
        if(BPF_OP(filter->bf_insns[i].code) == BPF_JA)
        {
            graph[current_id].true_instruct = flatteGraph(graph, filter, non_terminal_count, terminal_count, filter->bf_insns[i].k+i+1,id);
        }
        else
        {
            graph[current_id].true_instruct = flatteGraph(graph, filter, non_terminal_count, terminal_count, filter->bf_insns[i].jt+i+1, id);
            graph[current_id].false_instruct = flatteGraph(graph, filter, non_terminal_count, terminal_count, filter->bf_insns[i].jf+i+1, id);
        }
    }
    else if(BPF_CLASS(filter->bf_insns[i].code) != BPF_RET) /*OTHER INSTRUCTION*/
    {
        current_id = (*id)++;
        graph[current_id].bf_instruct_link = i;
        graph[current_id].true_instruct = flatteGraph(graph, filter, non_terminal_count, terminal_count, i+1,id);
    }
    else /*TERMINAL INSTRUCTION*/
    {                
        for(indice = 0 ; (indice<terminal_count) && ( graph[non_terminal_count + indice].bf_instruct_link != -1) ; indice++)
        {
            if(graph[non_terminal_count + indice].bf_instruct_link == i)
            {
                graph[non_terminal_count + indice].true_instruct += 1;
                return non_terminal_count + indice;
            }
        }
        
        /*noeud terminal non encore recontré, on l'ajoute*/
        current_id = non_terminal_count + indice;
        graph[current_id].bf_instruct_link = i;
        graph[current_id].true_instruct = 1;
        graph[current_id].false_instruct = indice;
    }
    
    return current_id;
}

/*
 * cette fonction compare le graphe existant avec le nouveau graphe applati
 *
 * @param graph : le graphe applati
 * @param filter : le graphe bpf correspondant
 * @param indice : l'indice du noeud a comparer
 * @param node : la liste de noeud pouvant contenir un noeud similaire
 * @return : le nombre de noeud equivalent dans l'arbre
 *
 */
unsigned int compareGraphExploreChild(struct flatten_item * graph, struct bpf_program * filter, int indice, struct filter_node * node,unsigned int * collide)
{
    int i = graph[indice].bf_instruct_link;
    unsigned int local_collide = 0, child_collide_true = 0, child_collide_false = 0;
    unsigned int ret = 0;
    struct filter_node * current_node = node;
    
    /*recherche d'un noeud racine correspondant*/
    for( ; current_node != NULL ; current_node = current_node->next)
    {
        if(current_node->item->code == filter->bf_insns[i].code && current_node->item->k == filter->bf_insns[i].k)
        {
            break;
        }
    }
    
    /*pas de noeud correspondant, on devra insérer ici*/
    if(current_node == NULL)
    {
        if(indice > 0 && node!= NULL)
        {
            /*on a un noeud pouvant causer un breakpoint*/
            local_collide = 1;
        }
        
        *collide = local_collide;
        return 0;
    }
    else
    {
        if(indice > 0 && node != NULL && node->next!=NULL)
        {
            local_collide = 1;
        }
    }
    
    if(BPF_CLASS(filter->bf_insns[i].code) == BPF_JMP && BPF_OP(filter->bf_insns[i].code) != BPF_JA) /*noeud conditionnel*/
    {
        ret = 1 + compareGraphExploreChild(graph, filter, graph[indice].true_instruct, current_node->item->next_child_t,&child_collide_true)
                 + compareGraphExploreChild(graph, filter, graph[indice].false_instruct, current_node->item->next_child_f, &child_collide_false);
    }
    else if(BPF_CLASS(filter->bf_insns[i].code) != BPF_RET) /*noeud normal*/
    {
        ret = 1 + compareGraphExploreChild(graph, filter, graph[indice].true_instruct, current_node->item->next_child_t,&child_collide_true);
    }
    /*else
    {
        on ne se soucie pas des noeuds terminaux, ils seront ajoutés quoi qu'il arrive, c'est necessaire pour la suppression
    }*/

    *collide = local_collide + (child_collide_true > child_collide_false)?child_collide_true:child_collide_false;

    return ret;
}

/*
 * cette fonction compare le graphe existant avec le nouveau graphe applati
 */
unsigned int compareGraph(struct flatten_item * graph, struct bpf_program * filter, unsigned int * collide)
{
    return compareGraphExploreChild(graph, filter, 0, master_filter.filter_first_node,collide);

}

void updateWorkingGraph(struct flatten_item * graph, struct bpf_program * filter, int indice, 
                        struct filter_node ** where_to_insert, struct filter_node *** next_available_node, 
                        struct filter_item *** next_available_item, struct filter_item * parent, struct filter_item ** terminal_nodes)
{
    int i = graph[indice].bf_instruct_link;
    
    struct filter_node * node = (*where_to_insert);
    
    if(BPF_CLASS(filter->bf_insns[i].code) != BPF_RET)
    {
        /*recherche d'un noeud racine correspondant*/
        for( ; node != NULL ; node = node->next)
        {
            if(node->item->code == filter->bf_insns[i].code && node->item->k == filter->bf_insns[i].k)
            {
                break;
            }
        }
        
        /*pas de noeud racine correspondant, on l'ajoute*/
        if(node == NULL)
        {
            /*on insere le nouveau noeud*/
            (**next_available_item)->code = filter->bf_insns[i].code;
            (**next_available_item)->k    = filter->bf_insns[i].k;
            (**next_available_item)->next_child_t = NULL;
            (**next_available_item)->next_child_f = NULL;
            (**next_available_item)->parent = parent;
        
            (**next_available_node)->item = (**next_available_item);
            (**next_available_node)->next = (*where_to_insert); 
            (*where_to_insert) = (**next_available_node);
        
            node = (**next_available_node);
        
            (*next_available_node) ++; 
            (*next_available_item) ++; 
        }
    
        if(BPF_CLASS(filter->bf_insns[i].code) == BPF_JMP && BPF_OP(filter->bf_insns[i].code) != BPF_JA) /*noeud conditionnel*/
        {
            updateWorkingGraph(graph, filter, graph[indice].true_instruct, &node->item->next_child_t,next_available_node,next_available_item, node->item, terminal_nodes);
            updateWorkingGraph(graph, filter, graph[indice].false_instruct, &node->item->next_child_f,next_available_node,next_available_item, node->item, terminal_nodes);
        }
        else /*tous les autres*/
        {
            updateWorkingGraph(graph, filter, graph[indice].true_instruct, &node->item->next_child_t,next_available_node,next_available_item, node->item, terminal_nodes);
        }        
    }
    else /*les noeud terminaux sont obligatoirement inséré*/
    {
        /*faire le lien avec le terminal node correspondant */
        (**next_available_node)->item = terminal_nodes[graph[indice].false_instruct];
        
        (**next_available_node)->next = (*where_to_insert); 
        (*where_to_insert) = (**next_available_node);
        (*next_available_node) ++; 
        
        /*ajouter le parent au noeud terminal*/
        if(terminal_nodes[graph[indice].false_instruct]->parent == NULL)
        {
            terminal_nodes[graph[indice].false_instruct]->parent = parent;
        }
        else
        {
            (**next_available_node)->item = parent;

            (**next_available_node)->next = terminal_nodes[graph[indice].false_instruct]->next_child_t; 
            terminal_nodes[graph[indice].false_instruct]->next_child_t = (**next_available_node);
            (*next_available_node) ++;
        }
    }
}

/*
    hypothese de fonctionnement:
        -un noeud non terminal ne peut avoir qu'un unique parent
        -les noeuds terminaux stockent la suite des noeuds parents dans les noeud true à partir du second parent
            -le premier noeud parent d'un noeud terminal est stocké dans la variable parent
        -la comparaison d'un noeud se fait sur :
            -son action
            -son paramètre
            -son parent
        
*/

/*
    cette méthode permet d'ajouter un nouveau filtre dans le graphe des filtres
    @param filter_string : la chaine de caractère représentant le filtre
    @param filter_id : l'identifiant du filtre (le numéro de port du client)
    @param pipe : le descriptor du pipe destiné au données
    @param control_pipe : le descriptor du pipe destiné au control
    
    @return : 0 si tout s'est bien passé, sinon -1
 */
int addFilter(const char * filter_string, int filter_id, int pipe, int control_pipe)
{
    int i;
    struct bpf_program filter;
    struct filter_item ** item_list, ** item_list_iterator;
    struct filter_node ** node_list, ** node_list_iterator;
    struct filter_end_node * end_node_tmp;
    struct breakpoint * breakpoint_stack_tmp;
    
    unsigned int non_terminal_count, terminal_count, common_non_terminal_count, new_node_needed, new_item_needed, collision_count;
    struct flatten_item * flatten_graph;
    
/*FILTER COMPILATION*/
    /*on compile le filtre*/
    if( compileGraph(filter_string, &filter, pipe) != 0 )
    {
        fprintf(stderr,"(capturefilterlib) addFilter, failed to compile new graph\n");
        return -1;
    }
    
    /*cas du filtre vide*/
    if(filter.bf_len < 1)
    {
        fprintf(stderr,"(capturefilterlib) addFilter, filter size is lower than 1\n");
        pcap_freecode(&filter);
        return -1;
    }

/*FILTER EXPLORATION*/
    /*on compte le nombre de noeud non terminaux*/
    non_terminal_count = countNoTerminalNodes(&filter,0);
    /*printf("NON terminal : %u\n", non_terminal_count);*/
    
    /*on compte le nombre de noeud terminaux*/
    terminal_count = countTerminalNodes(&filter);
    /*printf("terminal : %u\n", terminal_count);*/

/*FLATTEN GRAPH*/
    if( (flatten_graph = calloc( (non_terminal_count + terminal_count), sizeof(struct flatten_item))) == NULL)
    {
        perror("(capturefilterlib) addFilter, failed to allocate flat graph\n");
        pcap_freecode(&filter);
        return -1;
    }
    
    for(i=0;i<terminal_count;i++)
    {
        flatten_graph[non_terminal_count+i].bf_instruct_link = -1;
    }
    i = 0;
    flatteGraph(flatten_graph,&filter,non_terminal_count,terminal_count,0,&i);
    
    /*for(i=0;i<non_terminal_count + terminal_count;i++)
    {
        printf("%d // %d : %d : %d\n",i, flatten_graph[i].bf_instruct_link, flatten_graph[i].true_instruct, flatten_graph[i].false_instruct);
    }*/

    /*flattenGraphTraversal(flatten_graph,&filter, 0,0);*/
/*GRAPH COMPARAISON*/
    common_non_terminal_count = compareGraph(flatten_graph,&filter, &collision_count);
 
    new_item_needed = terminal_count + (non_terminal_count - common_non_terminal_count);
    new_node_needed = (non_terminal_count - common_non_terminal_count); /*chaque item sera contenu par l'item parent et a donc besoin d'un node, y compris les noeuds root*/
    
    for(i=0;i<terminal_count;i++)/*chaque noeud terminal possèdera une référence vers ses parents, un node par parent, -1 car il existe deja une varible parent, 
                                chaque noeud non terminal possédant un référence vers un noeud terminal a besoin d'un node pour le stocker*/
    {
        new_node_needed += (flatten_graph[non_terminal_count+i].true_instruct - 1)+flatten_graph[non_terminal_count+i].true_instruct;
    }
    
    new_node_needed += terminal_count; /*chaque noeud terminal est referencé dans le filter_end_node */
    
    /*printf("new_item_needed = %d, new_node_needed = %d\n",new_item_needed,new_node_needed);*/
/*MEMORY ALLOCATION*/

    if(master_filter.max_filter_level_count < collision_count)
    {
        if( (breakpoint_stack_tmp = malloc(collision_count * sizeof(struct breakpoint))) == NULL )
        {
            perror("(capturefilterlib) addFilter, failed to allocate new breakpoint stack");
            pcap_freecode(&filter);
            free(flatten_graph);
            return -1;
        }
        
        /*liberation des précédentes ressources*/
        if(master_filter.max_filter_level_count > 0)
        {
            free(master_filter.breakpoint_stack);
        }
        
        /*modification du master_filter*/
        master_filter.breakpoint_stack = breakpoint_stack_tmp;
        master_filter.max_filter_level_count = collision_count;
    }

    /*allocation d'un noeud pour l'item final*/
    if( (end_node_tmp = malloc(sizeof(struct filter_end_node))) == NULL )
    {
        perror("(capturefilterlib) addFilter, failed to allocate filter_end_node");
        pcap_freecode(&filter);
        free(flatten_graph);
        free(breakpoint_stack_tmp);
        return -1;
    }

    /*allocation de la liste des items*/
    if((item_list = malloc(new_item_needed * sizeof(struct filter_item *))) == NULL)
    {
        perror("(capturefilterlib) addFilter, failed to allocate item list\n");
        pcap_freecode(&filter);
        free(flatten_graph);
        free(end_node_tmp);
        free(breakpoint_stack_tmp);
        return -1;
    }
    
    /*allocation de la liste des nodes*/
    if((node_list = malloc(new_node_needed * sizeof(struct filter_node *))) == NULL)
    {
        perror("(capturefilterlib) addFilter, failed to allocate node_list\n");
        pcap_freecode(&filter);
        free(item_list);
        free(flatten_graph);
        free(end_node_tmp);
        free(breakpoint_stack_tmp);
        return -1;
    }
    
    /*allocation des items*/
    for(i = 0;i<new_item_needed;i+=1)
    {
        if((item_list[i] = malloc(sizeof(struct filter_item))) == NULL)
        {
            perror("(capturefilterlib) addFilter, failed to allocate a new node\n");
            
            for(i-=1;i>=0;i-=1)
            {
                free(item_list[i]);
            }
            
            pcap_freecode(&filter);
            free(item_list);
            free(node_list);
            free(flatten_graph);
            free(end_node_tmp);
            free(breakpoint_stack_tmp);
            return -1;
        }
    }
    
    /*allocation des nodes*/
    for(i = 0;i<new_node_needed;i++)
    {
        if((node_list[i] = malloc(sizeof(struct filter_node))) == NULL)
        {
            perror("(capturefilterlib) addFilter, failed to allocate a new node\n");
            
            for(i-=1;i>=0;i-=1)
            {
                free(node_list[i]);
            }
            
            for(i = 0;i<new_item_needed;i+=1)
            {
                free(item_list[i]);
            }
            
            pcap_freecode(&filter);
            free(item_list);
            free(node_list);
            free(flatten_graph);
            free(end_node_tmp);
            free(breakpoint_stack_tmp);
            return -1;
        }
    }
    
    node_list_iterator = node_list;
    item_list_iterator = item_list;
    
/*FILTER INSERTION*/    
    /*preparation du filter_end_node*/
    end_node_tmp->control_pipe = control_pipe;
    end_node_tmp->port_id = filter_id;
    
    end_node_tmp->next = master_filter.end_node;
    master_filter.end_node = end_node_tmp;
    
    end_node_tmp->next_end_node = NULL;
    
    /*preparation des noeuds terminaux*/
    for(i=0;i<terminal_count;i++)
    {
        item_list[new_item_needed - terminal_count + i]->code         = filter.bf_insns[flatten_graph[non_terminal_count+i].bf_instruct_link].code;
        item_list[new_item_needed - terminal_count + i]->k            = filter.bf_insns[flatten_graph[non_terminal_count+i].bf_instruct_link].k;
        item_list[new_item_needed - terminal_count + i]->next_child_t = NULL;
        item_list[new_item_needed - terminal_count + i]->next_child_f = NULL;
        item_list[new_item_needed - terminal_count + i]->parent       = NULL;
        
        /*enlistage des noeuds dans la structure end_node*/
        (*node_list_iterator)->item = item_list[new_item_needed - terminal_count + i];
        (*node_list_iterator)->next = end_node_tmp->next_end_node;
        end_node_tmp->next_end_node = (*node_list_iterator);
        node_list_iterator++;
    }

    updateWorkingGraph(flatten_graph, &filter, 0, &master_filter.filter_first_node, &node_list_iterator, &item_list_iterator, NULL, &item_list[new_item_needed - terminal_count]);
    
    /*liberation des ressources*/
    pcap_freecode(&filter);
    free(item_list);
    free(node_list);
    free(flatten_graph);
    
    return 0;
}


/*
 *    cette fonction permet de supprimer tous les enfant d'un noeud
 *    @param parent : le noeud parent du noeud a supprimer, ou null s'il s'agit d'un noeud racine
 *    @param item : le noeud a supprimer
 */
void removeItem(struct filter_item * parent, struct filter_item * item)
{
    struct filter_node * node_current, * node_previous;
    if(item != NULL)
    {
        /*cas special pour les noeud return qui peuvent avoir plusieurs parent*/
        if(BPF_CLASS(item->code) == BPF_RET)
        {
            if(parent != NULL)
            {
                if(item->parent == parent) /*le premier parent est toujours stockés dans le champs prévu*/
                {
                    item->parent = NULL;
                }
                else /*les autres parents sont stockés dans la chaine des fils true*/
                {
                    node_previous = NULL;
                    node_current = item->next_child_t;

                    while(node_current != NULL) /*exploration de la liste des parents*/
                    {
                        if(node_current->item == parent) /*on a un parent match*/
                        {
                            if(node_previous == NULL) /*c'est le premier de la liste*/
                            {
                                item->next_child_t = node_current->next;
                            }
                            else /*il est au millieu de la liste*/
                            {
                                node_previous->next = node_current->next;
                            }

                            /*on libere la ressource*/
                            node_current->next = NULL;
                            free(node_current);

                            break;
                        }
                        node_previous = node_current;
                        node_current = node_current->next;
                    }
                }
            }
            
            /*lorsqu'il n'y a plus de parent pour le noeud, on ferme le canal de sortie et on libere l'item*/
            if(item->parent == NULL && item->next_child_t == NULL)
            {
                if(item->k != 0)
                {
                    close(item->k);
                }
                free(item);
            }
        }
        else /*cas d'un noeud non terminal*/
        {
            /*on retire tous les enfants true*/
            node_current = item->next_child_t;
            while(node_current != NULL)
            {
                removeItem(item,node_current->item);

                /*on libere le noeud et on passe au suivant*/
                node_previous = node_current;
                node_current  = node_current->next;
                free(node_previous);
            }

            /*on retire tous les enfants false*/
            node_current = item->next_child_f;
            while(node_current != NULL)
            {
                removeItem(item,node_current->item);

                /*on libere le noeud et on passe au suivant*/
                node_previous = node_current;
                node_current  = node_current->next;
                free(node_previous);
            }

            /*on libere la ressource alloué par l'item*/
            free(item);
        }
    }    
}

/*
 * -on supprime vers le haut, on ne redescend jamais
 * -on n'aura jamais affaire a un noeud terminal
 */
void removeUpperItem(struct filter_item * current_item, struct filter_item * child_item)
{
    struct filter_node * current_node, * previous_node;
    
    if(current_item == NULL) /*le noeud a supprimer est une racine*/
    {
        /*on le supprime de la liste des noeuds racine*/
        previous_node = NULL;
        current_node = master_filter.filter_first_node;
        for(;current_node != NULL;previous_node = current_node, current_node = current_node->next)
        {
            if(current_node->item == child_item)
            {
                if(previous_node != NULL)
                {
                    previous_node->next = current_node->next;
                }
                else
                {
                    master_filter.filter_first_node = current_node->next;
                }
                free(current_node);
                break;
            }
        }
    }
    else
    {   
        /*le noeud source se trouve t'il dans la liste des noeuds vrai?*/
        previous_node = NULL;
        current_node = current_item->next_child_t;
        for(;current_node != NULL;previous_node = current_node, current_node = current_node->next)
        {
            if(current_node->item == child_item)
            {
                if(previous_node != NULL)
                {
                    previous_node->next = current_node->next;
                }
                else
                {
                    current_item->next_child_t = current_node->next;
                }
                free(current_node);
                goto explore_parent;
            }
        }

        /*le noeud source se trouve t'il dans la liste des noeuds faux?*/
        previous_node = NULL;
        current_node = current_item->next_child_f;
        for(;current_node != NULL;previous_node = current_node, current_node = current_node->next)
        {
            if(current_node->item == child_item)
            {
                if(previous_node != NULL)
                {
                    previous_node->next = current_node->next;
                }
                else
                {
                    current_item->next_child_f = current_node->next;
                }
                free(current_node);
                break;
            }
        }

        explore_parent:
        /*s'il n'y a plus d'autre enfant, on propage la suppression vers le noeud parent*/
        if(current_item->next_child_t == NULL && current_item->next_child_f == NULL)
        {
            /*propagation de la suppression*/
            removeUpperItem(current_item->parent, current_item);

            /*liberation de l'item*/
            free(current_item);
        }
    }
}

int removeFilter(int end_node_id)
{
    struct filter_end_node * end_node_current = master_filter.end_node, * end_node_previous = NULL;
    struct filter_node * node_current, * node_tmp, * node_current_parent;
    uint8 command = KILL_YOU;
    
    /*identifier le noeud finale correspondant*/  
    for(;end_node_current != NULL;end_node_previous = end_node_current, end_node_current = end_node_current->next)
    {
        if(end_node_current->port_id == end_node_id)
        {
            break;
        }
    }
    
    /*on a trouvé un end_node correspondant*/
    if(end_node_current != NULL)
    {
        /*envoi de la commande de suicide au wait, cela est necessaire car la fermeture des pipes ne semble pas suffisante pour terminer les waits*/
        if(write(end_node_current->control_pipe,&command,sizeof(command)) < 0)
        {
            perror("(capturefilterlib) removeFilter, failed to write command KILL YOU :");
            return -1;
        }
        
        /*fermeture du pipe de control*/
        printf("CLOSE control pipe : %d\n",end_node_current->control_pipe);
        if(close(end_node_current->control_pipe)<0)
        {
            perror("(capturefilterlib) removeFilter, failed to close descriptor");
        }
        
        /*parcourt de tous les noeud terminaux liés*/
        node_current = end_node_current->next_end_node;
        while(node_current!= NULL)
        {
            /*fermeture du pipe de données*/
            if(node_current->item->k != 0)
            {
                printf("CLOSE data pipe : %d\n",node_current->item->k);
                if(close(node_current->item->k)<0)
                {
                    perror("(capturefilterlib) removeFilter, failed to close descriptor");
                }
            }
            
            /*suppression des parents du noeud terminal*/
            node_current_parent = node_current->item->next_child_t;
            while(node_current_parent != NULL)
            {
                removeUpperItem(node_current_parent->item,node_current->item);
                
                node_tmp = node_current_parent;
                node_current_parent = node_current_parent->next;
                free(node_tmp);
            }
            
            /*suppression du parent unique du noeud terminal*/
            removeUpperItem(node_current->item->parent, node_current->item);
            
            node_tmp = node_current;
            node_current = node_current->next;
            
            /*liberation du noeud*/
            free(node_tmp->item);
            free(node_tmp);
        }
        
        /*liberation du end_node*/
        if(end_node_previous != NULL)
        {
            end_node_previous->next = end_node_current->next;
        }
        else
        {
            master_filter.end_node = end_node_current->next;
        }
        
        free(end_node_current);
        return 0;
    }
    return -1;  
}

/*
 *    cette fonction permet de supprimer tous les noeuds du systeme.
 */
void removeAllFilter()
{
    struct filter_node * node_current, *node_previous;
    struct filter_end_node * end_node_previous;
    
    capture_kill();
    
    /*remove all filter_node*/
    node_current = master_filter.filter_first_node;
    while(node_current != NULL)
    {
        removeItem(NULL,node_current->item);
        node_previous = node_current;
        node_current = node_current->next;
        free(node_previous);
    }
    master_filter.filter_first_node = NULL;
    
    /*remove all filter_end_node*/
    while(master_filter.end_node != NULL)
    {
        close(master_filter.end_node->control_pipe);
        end_node_previous = master_filter.end_node;
        master_filter.end_node = master_filter.end_node->next;
        free(end_node_previous);
    }
}

int sendToAllNode(register const uint8 *p,unsigned int buflen, struct timeval ts)
{
    struct filter_node * root_node = master_filter.filter_first_node, * node_tmp;
    struct filter_item * pc;
    
    register uint32 A, X;
	register int k, iterateur;
	sint32 mem[BPF_MEMWORDS];
        
    while(root_node != NULL)
    {
        master_filter.current_breakpoint = -1;
        pc = root_node->item;
        
        restart_mainloop:
        while(1)
        {
            /*printf("FILTER : %s\n",filter_item_image(pc));*/
            
            switch (pc->code) 
    		{
        		default:
                    fprintf(stderr,"(capturefilterlib) sendToAllNode, warning unknwon bpf instruction\n");
                    return -1;
        		case BPF_RET|BPF_K:
        			if( ((u_int)pc->k) != 0)
        			{
                        printf("SEND %u\n",buflen);
        			    buflen -= link_info.header_size;
        			    
                        if( write(pc->k,&ts,sizeof(struct timeval))       < 0 ||
                            write(pc->k,&buflen,sizeof(unsigned int))     < 0 ||
        			        write(pc->k,&p[link_info.header_size],buflen) < 0 )
        			    {
        			        /*soit le wait a fermé le canal, soit on a reçu une interruption en provenance du CONTROL*/
        			        /*TODO WRITE, reprendre l'ecriture ou elle s'est arretée*/
        			    }
        			    buflen += link_info.header_size;
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
                        
                            /*copy the mem*/
                            for(iterateur = 0;iterateur < BPF_MEMWORDS;iterateur+=1)
                            {
                                mem[iterateur] = master_filter.breakpoint_stack[master_filter.current_breakpoint].mem[iterateur];
                            }
                        
                            /*prepare the next break point*/
                            master_filter.breakpoint_stack[master_filter.current_breakpoint].next_instruct = master_filter.breakpoint_stack[master_filter.current_breakpoint].next_instruct->next;
                        
                            goto restart_mainloop;
    			        }
                        master_filter.current_breakpoint--;
    			    }
			    
                    goto MAIN_WHILE_CONTINUE;

        		case BPF_RET|BPF_A:
        			if( ((u_int)A) != 0)
        			{
        			    printf("SEND %u\n",buflen);
        			    buflen -= link_info.header_size;
        			    if( write(pc->k,&ts,sizeof(struct timeval))       < 0 ||
                            write(pc->k,&buflen,sizeof(unsigned int))     < 0 ||
        			        write(pc->k,&p[link_info.header_size],buflen) < 0 )
        			    {
        			        /*soit le wait a fermé le canal, soit on a reçu une interruption en provenance du CONTROL*/
        			        /*TODO WRITE, reprendre l'ecriture ou elle s'est arretée*/
        			    }
        			    
        			    buflen += link_info.header_size;
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
                        
                            /*copy the mem*/
                            for(iterateur = 0;iterateur < BPF_MEMWORDS;iterateur+=1)
                            {
                                mem[iterateur] = master_filter.breakpoint_stack[master_filter.current_breakpoint].mem[iterateur];
                            }
                        
                            /*prepare the next break point*/
                            master_filter.breakpoint_stack[master_filter.current_breakpoint].next_instruct = master_filter.breakpoint_stack[master_filter.current_breakpoint].next_instruct->next;
                        
                            goto restart_mainloop;
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
                    /*printf("X = %u\n",X);*/
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
                
                if(master_filter.current_breakpoint == master_filter.max_filter_level_count)
                {
                    fprintf(stderr,"(capturefilterlib) sendToAllNode, breakpoint stack overflow\n");
                    return -1;
                }
                
                master_filter.breakpoint_stack[master_filter.current_breakpoint].next_instruct = node_tmp->next;
                master_filter.breakpoint_stack[master_filter.current_breakpoint].A = A;
                master_filter.breakpoint_stack[master_filter.current_breakpoint].X = X;
                master_filter.breakpoint_stack[master_filter.current_breakpoint].k = k;
                
                /*copy the memory*/
                for(iterateur = 0;iterateur < BPF_MEMWORDS;iterateur+=1)
                {
                    master_filter.breakpoint_stack[master_filter.current_breakpoint].mem[iterateur] = mem[iterateur];
                }
		    }
		    
            pc = node_tmp->item;
    	}
        
        MAIN_WHILE_CONTINUE:
        root_node = root_node->next;
    }
    
    return 0;
}

/*########################################################################################################################################################*/
/*######################### TRAVERSAL METHOD (debug) #####################################################################################################*/
/*########################################################################################################################################################*/

void flattenGraphTraversal(struct flatten_item * graph, struct bpf_program * filter, int indice, int level)
{
    int j;
    struct bpf_insn *insn = &filter->bf_insns[  graph[indice].bf_instruct_link  ];
    
    if(level > 50)
        return;
     
    for(j = 0;j< level;j++)
    {
        printf(" ");
    }

    printf("(%d : %d) fnode (code:%u - k:%u)\n",level, indice, insn->code, insn->k);
    /*printf("(%d) %s\n",level, bpf_image(insn,indice));*/
    if(BPF_CLASS(insn->code) == BPF_JMP)
    {
        if(BPF_OP(insn->code) == BPF_JA)
        {
            flattenGraphTraversal(graph, filter, graph[indice].true_instruct, level+1);
        }
        else
        {
            flattenGraphTraversal(graph, filter, graph[indice].true_instruct, level+1);
            flattenGraphTraversal(graph, filter, graph[indice].false_instruct, level+1);
        }
    }
    else if(BPF_CLASS(insn->code) != BPF_RET)
    {
        flattenGraphTraversal(graph, filter, graph[indice].true_instruct, level+1);
    }
}

void traversal()
{
    struct filter_node * filter_node_tmp = master_filter.filter_first_node;
    
    while(filter_node_tmp != NULL)
    {
        innerTraversal("",filter_node_tmp->item, 0);
        filter_node_tmp = filter_node_tmp->next;
    }
}

void innerTraversal(const char * pre,struct filter_item * i, int level)
{
    struct filter_node * node_tmp = NULL;
    int j;
    
    if(i == NULL)
    {
        return;
    }
    
    for(j = 0;j< level;j++)
    {
        printf(" ");
    }
    printf("%s",pre);
    printf("(%d) fnode (code:%u - k:%u) \n",level, i->code, i->k);
    
    if(BPF_CLASS(i->code) != BPF_RET)
    {
        node_tmp = i->next_child_t;
        while(node_tmp != NULL)
        {
            if(i->next_child_f == NULL)
                innerTraversal("",node_tmp->item, level+1);
            else
                innerTraversal("(t):",node_tmp->item, level+1);
            node_tmp = node_tmp->next;
        }

        node_tmp = i->next_child_f;
        while(node_tmp != NULL)
        {
            innerTraversal("(f):",node_tmp->item, level+1);
            node_tmp = node_tmp->next;
        }
    }
}

/*########################################################################################################################################################*/
/*######################### CONTROL METHOD ###############################################################################################################*/
/*########################################################################################################################################################*/

int captureSendCommand(uint8 command)
{
    struct filter_end_node * tmp = master_filter.end_node;
    while(tmp != NULL)
    {
        printf("write command %d\n", tmp->control_pipe);
        if(write(tmp->control_pipe,&command,sizeof(command)) < 0)
        {
            perror("(capturefilterlib) captureSendCommand, failed to write command :");
            return -1;
        }
        tmp = tmp->next;
    }
    
    return 0;
}

int capture_setSpeed(uint8 speed)
{
    struct filter_end_node * tmp = master_filter.end_node;
    uint8 command = DELAY_PARAM;
    
    while(tmp != NULL)
    {
        printf("write speed to %d\n", tmp->control_pipe);
        if(write(tmp->control_pipe,&command,sizeof(command)) < 0)
        {
            perror("(capturefilterlib) captureSendCommand, failed to write command :");
            return -1;
        }
        if(write(tmp->control_pipe,&speed,sizeof(speed)) < 0)
        {
            perror("(capturefilterlib) captureSendCommand, failed to write command :");
            return -1;
        }
        tmp = tmp->next;
    }
    
    return 0;
}

int capture_setFileMode()
{
    return captureSendCommand(DISABLE_BUFFER);
}

int capture_pause()
{
    return captureSendCommand(PAUSE_EVENT);
}

int capture_resume()
{
    return captureSendCommand(RESUME_EVENT);
}

int capture_flush()
{
    return captureSendCommand(FLUSH_EVENT);
}

int capture_kill()
{
    return captureSendCommand(KILL_YOU);
}

char * filter_item_image(const struct filter_item * p)
{
	int v;
	const char *fmt, *op;
	static char image[256];
	char operand[64];

	v = p->k;
	switch (p->code) {

	default:
		op = "unimp";
		fmt = "0x%x";
		v = p->code;
		break;

	case BPF_RET|BPF_K:
		op = "ret";
		fmt = "#%d";
		break;

	case BPF_RET|BPF_A:
		op = "ret";
		fmt = "";
		break;

	case BPF_LD|BPF_W|BPF_ABS:
		op = "ld";
		fmt = "[%d]";
		break;

	case BPF_LD|BPF_H|BPF_ABS:
		op = "ldh";
		fmt = "[%d]";
		break;

	case BPF_LD|BPF_B|BPF_ABS:
		op = "ldb";
		fmt = "[%d]";
		break;

	case BPF_LD|BPF_W|BPF_LEN:
		op = "ld";
		fmt = "#pktlen";
		break;

	case BPF_LD|BPF_W|BPF_IND:
		op = "ld";
		fmt = "[x + %d]";
		break;

	case BPF_LD|BPF_H|BPF_IND:
		op = "ldh";
		fmt = "[x + %d]";
		break;

	case BPF_LD|BPF_B|BPF_IND:
		op = "ldb";
		fmt = "[x + %d]";
		break;

	case BPF_LD|BPF_IMM:
		op = "ld";
		fmt = "#0x%x";
		break;

	case BPF_LDX|BPF_IMM:
		op = "ldx";
		fmt = "#0x%x";
		break;

	case BPF_LDX|BPF_MSH|BPF_B:
		op = "ldxb";
		fmt = "4*([%d]&0xf)";
		break;

	case BPF_LD|BPF_MEM:
		op = "ld";
		fmt = "M[%d]";
		break;

	case BPF_LDX|BPF_MEM:
		op = "ldx";
		fmt = "M[%d]";
		break;

	case BPF_ST:
		op = "st";
		fmt = "M[%d]";
		break;

	case BPF_STX:
		op = "stx";
		fmt = "M[%d]";
		break;

	case BPF_JMP|BPF_JA:
		op = "ja";
        fmt = "long";
		fmt = "%d";
		/*v = n + 1 + p->k;*/
		break;

	case BPF_JMP|BPF_JGT|BPF_K:
		op = "jgt";
		fmt = "#0x%x";
		break;

	case BPF_JMP|BPF_JGE|BPF_K:
		op = "jge";
		fmt = "#0x%x";
		break;

	case BPF_JMP|BPF_JEQ|BPF_K:
		op = "jeq";
		fmt = "#0x%x";
		break;

	case BPF_JMP|BPF_JSET|BPF_K:
		op = "jset";
		fmt = "#0x%x";
		break;

	case BPF_JMP|BPF_JGT|BPF_X:
		op = "jgt";
		fmt = "x";
		break;

	case BPF_JMP|BPF_JGE|BPF_X:
		op = "jge";
		fmt = "x";
		break;

	case BPF_JMP|BPF_JEQ|BPF_X:
		op = "jeq";
		fmt = "x";
		break;

	case BPF_JMP|BPF_JSET|BPF_X:
		op = "jset";
		fmt = "x";
		break;

	case BPF_ALU|BPF_ADD|BPF_X:
		op = "add";
		fmt = "x";
		break;

	case BPF_ALU|BPF_SUB|BPF_X:
		op = "sub";
		fmt = "x";
		break;

	case BPF_ALU|BPF_MUL|BPF_X:
		op = "mul";
		fmt = "x";
		break;

	case BPF_ALU|BPF_DIV|BPF_X:
		op = "div";
		fmt = "x";
		break;

	case BPF_ALU|BPF_AND|BPF_X:
		op = "and";
		fmt = "x";
		break;

	case BPF_ALU|BPF_OR|BPF_X:
		op = "or";
		fmt = "x";
		break;

	case BPF_ALU|BPF_LSH|BPF_X:
		op = "lsh";
		fmt = "x";
		break;

	case BPF_ALU|BPF_RSH|BPF_X:
		op = "rsh";
		fmt = "x";
		break;

	case BPF_ALU|BPF_ADD|BPF_K:
		op = "add";
		fmt = "#%d";
		break;

	case BPF_ALU|BPF_SUB|BPF_K:
		op = "sub";
		fmt = "#%d";
		break;

	case BPF_ALU|BPF_MUL|BPF_K:
		op = "mul";
		fmt = "#%d";
		break;

	case BPF_ALU|BPF_DIV|BPF_K:
		op = "div";
		fmt = "#%d";
		break;

	case BPF_ALU|BPF_AND|BPF_K:
		op = "and";
		fmt = "#0x%x";
		break;

	case BPF_ALU|BPF_OR|BPF_K:
		op = "or";
		fmt = "#0x%x";
		break;

	case BPF_ALU|BPF_LSH|BPF_K:
		op = "lsh";
		fmt = "#%d";
		break;

	case BPF_ALU|BPF_RSH|BPF_K:
		op = "rsh";
		fmt = "#%d";
		break;

	case BPF_ALU|BPF_NEG:
		op = "neg";
		fmt = "";
		break;

	case BPF_MISC|BPF_TAX:
		op = "tax";
		fmt = "";
		break;

	case BPF_MISC|BPF_TXA:
		op = "txa";
		fmt = "";
		break;
	}
	(void)snprintf(operand, sizeof operand, fmt, v);
	(void)snprintf(image, sizeof image,
		      (BPF_CLASS(p->code) == BPF_JMP && BPF_OP(p->code) != BPF_JA) ?
		      /*"(%03d) %-8s %-16s jt %d\tjf %d" : "(%03d) %-8s %s",
		      n, op, operand, n + 1 + p->jt, n + 1 + p->jf);*/
		      "(%03d) %-8s %-16s jt\tjf" : "(%03d) %-8s %s",
  		      0, op, operand/*, n + 1 + p->jt, n + 1 + p->jf*/);
	return image;
}
