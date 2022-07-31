#include "napt.h"

#include "net.h"

void dump_napt_tables(){
    net_device* a;
    for(a = net_dev; a; a = a->next){
        if(a->ip_dev != nullptr and a->ip_dev->napt_inside_dev != nullptr){

            for(int i = 0; i < NAPT_GLOBAL_PORT_SIZE; ++i){
                if(a->ip_dev->napt_inside_dev->entries->tcp[i].global_port != 0){
                    printf("[NAT] TCP %s:%d => %s:%d\n",
                           inet_htoa(a->ip_dev->napt_inside_dev->entries->tcp[i].local_address),
                           a->ip_dev->napt_inside_dev->entries->tcp[i].local_port,
                           inet_htoa(a->ip_dev->napt_inside_dev->entries->tcp[i].global_address),
                           a->ip_dev->napt_inside_dev->entries->tcp[i].global_port
                    );
                }
                if(a->ip_dev->napt_inside_dev->entries->udp[i].global_port != 0){
                    printf("[NAT] UDP %s:%d => %s:%d\n",
                           inet_htoa(a->ip_dev->napt_inside_dev->entries->udp[i].local_address),
                           a->ip_dev->napt_inside_dev->entries->udp[i].local_port,
                           inet_htoa(a->ip_dev->napt_inside_dev->entries->udp[i].global_address),
                           a->ip_dev->napt_inside_dev->entries->udp[i].global_port
                    );
                }
            }
            for(int i = 0; i < NAPT_ICMP_ID_SIZE; ++i){
                if(a->ip_dev->napt_inside_dev->entries->icmp[i].global_port != 0){
                    printf("[NAT] ICMP %s:%d => %s:%d\n",
                           inet_htoa(a->ip_dev->napt_inside_dev->entries->icmp[i].local_address),
                           a->ip_dev->napt_inside_dev->entries->icmp[i].local_port,
                           inet_htoa(a->ip_dev->napt_inside_dev->entries->icmp[i].global_address),
                           a->ip_dev->napt_inside_dev->entries->icmp[i].global_port
                    );
                }
            }
        }
    }
}

napt_entry* get_napt_icmp_entry_by_global(napt_entries* entries, uint32_t address, uint16_t id){

    for(int i = 0; i < NAPT_ICMP_ID_SIZE; ++i){
        if(entries->icmp[i].global_address == address and entries->icmp[i].global_port == id){
            return &entries->icmp[i];
        }
    }
    return nullptr;
}

napt_entry* get_napt_icmp_entry_by_local(napt_entries* entries, uint32_t address, uint16_t id){

    for(int i = 0; i < NAPT_ICMP_ID_SIZE; ++i){
        if(entries->icmp[i].local_address == address and entries->icmp[i].local_port == id){
            return &entries->icmp[i];
        }
    }
    return nullptr;
}


napt_entry* get_napt_tcp_entry_by_global(napt_entries* entries, uint32_t address, uint16_t port){

    for(int i = 0; i < NAPT_GLOBAL_PORT_SIZE; ++i){
        if(entries->tcp[i].global_address == address and entries->tcp[i].global_port == port){
            return &entries->tcp[i];
        }
    }
    return nullptr;
}

napt_entry* get_napt_tcp_entry_by_local(napt_entries* entries, uint32_t address, uint16_t port){

    for(int i = 0; i < NAPT_GLOBAL_PORT_SIZE; ++i){
        if(entries->tcp[i].local_address == address and entries->tcp[i].local_port == port){
            return &entries->tcp[i];
        }
    }
    return nullptr;
}


napt_entry* get_napt_udp_entry_by_global(napt_entries* entries, uint32_t address, uint16_t port){

    for(int i = 0; i < NAPT_GLOBAL_PORT_SIZE; ++i){
        if(entries->udp[i].global_address == address and entries->udp[i].global_port == port){
            return &entries->udp[i];
        }
    }
    return nullptr;
}

napt_entry* get_napt_udp_entry_by_local(napt_entries* entries, uint32_t address, uint16_t port){

    for(int i = 0; i < NAPT_GLOBAL_PORT_SIZE; ++i){
        if(entries->udp[i].local_address == address and entries->udp[i].local_port == port){
            return &entries->udp[i];
        }
    }
    return nullptr;
}

napt_entry* create_napt_icmp_entry(napt_entries* entries){
    for(int i = 0; i < NAPT_ICMP_ID_SIZE; ++i){
        if(entries->icmp[i].global_address == 0){
            entries->icmp[i].global_port = i;
            return &entries->icmp[i];
        }
    }
    return nullptr;
}

napt_entry* create_napt_tcp_entry(napt_entries* entries){
    for(int i = 0; i < NAPT_GLOBAL_PORT_SIZE; ++i){
        if(entries->tcp[i].global_address == 0){
            entries->tcp[i].global_port = NAPT_GLOBAL_PORT_MIN + i;
            return &entries->tcp[i];
        }
    }
    return nullptr;
}

napt_entry* create_napt_udp_entry(napt_entries* entries){
    for(int i = 0; i < NAPT_GLOBAL_PORT_SIZE; ++i){
        if(entries->udp[i].global_address == 0){
            entries->udp[i].global_port = NAPT_GLOBAL_PORT_MIN + i;
            return &entries->udp[i];
        }
    }
    return nullptr;
}