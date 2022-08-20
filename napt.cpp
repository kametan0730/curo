#include "napt.h"

#include "config.h"
#include "net.h"
#include "my_buf.h"

void dump_napt_tables(){
    printf("NAT Table\n");
    printf("|-PROTO-|--------SOURCE---------|------DESTINATION------|\n");
    net_device* a;
    for(a = net_dev_list; a; a = a->next){
        if(a->ip_dev != nullptr and a->ip_dev->napt_inside_dev != nullptr){

            for(int i = 0; i < NAPT_GLOBAL_PORT_SIZE; ++i){
                if(a->ip_dev->napt_inside_dev->entries->tcp[i].global_port != 0){
                    printf("|  TCP  | %15s:%05d | %15s:%05d |\n",
                           inet_htoa(a->ip_dev->napt_inside_dev->entries->tcp[i].local_address),
                           a->ip_dev->napt_inside_dev->entries->tcp[i].local_port,
                           inet_htoa(a->ip_dev->napt_inside_dev->entries->tcp[i].global_address),
                           a->ip_dev->napt_inside_dev->entries->tcp[i].global_port
                    );
                }
                if(a->ip_dev->napt_inside_dev->entries->udp[i].global_port != 0){
                    printf("|  UDP  | %15s:%05d | %15s:%05d |\n",
                           inet_htoa(a->ip_dev->napt_inside_dev->entries->udp[i].local_address),
                           a->ip_dev->napt_inside_dev->entries->udp[i].local_port,
                           inet_htoa(a->ip_dev->napt_inside_dev->entries->udp[i].global_address),
                           a->ip_dev->napt_inside_dev->entries->udp[i].global_port
                    );
                }
            }
            for(int i = 0; i < NAPT_ICMP_ID_SIZE; ++i){
                if(a->ip_dev->napt_inside_dev->entries->icmp[i].local_address != 0){
                    printf("|  ICMP | %15s:%05d | %15s:%05d |\n",
                           inet_htoa(a->ip_dev->napt_inside_dev->entries->icmp[i].local_address),
                           a->ip_dev->napt_inside_dev->entries->icmp[i].local_port,
                           inet_htoa(a->ip_dev->napt_inside_dev->entries->icmp[i].global_address),
                           a->ip_dev->napt_inside_dev->entries->icmp[i].global_port
                    );
                }
            }
        }
    }
    printf("|-------|-----------------------|-----------------------|\n");
}


bool napt_icmp(ip_header* ip_packet, size_t len, napt_inside_device* napt_dev, napt_direction direction){

    auto* napt_packet = (napt_packet_head*) ((uint8_t*) ip_packet + sizeof(ip_header));
    if(napt_packet->icmp.header.type != ICMP_TYPE_ECHO_REQUEST and
       napt_packet->icmp.header.type != ICMP_TYPE_ECHO_REPLY){
        return false;
    }
#if DEBUG_NAT > 0
    printf("[NAT] NAPT ICMP Destination packet arrived\n");
#endif
    napt_entry* entry;
    if(direction == napt_direction::incoming){
        entry = get_napt_icmp_entry_by_global(napt_dev->entries, ntohl(ip_packet->destination_address),
                                              ntohs(napt_packet->icmp.identify));
        if(entry == nullptr){
            return false;
        }
    }else{
        entry = get_napt_icmp_entry_by_local(napt_dev->entries, ntohl(ip_packet->source_address),
                                             ntohs(napt_packet->icmp.identify));
        if(entry == nullptr){
            entry = create_napt_icmp_entry(napt_dev->entries);
            if(entry == nullptr){
#if DEBUG_NAT > 0
                printf("[NAT] NAPT table is full!\n");
#endif
                return false;
            }
#if DEBUG_NAT > 0
            printf("[NAT] Created new nat table entry global id %d\n", entry->global_port);
#endif
            entry->global_address = napt_dev->outside_address;
            entry->local_address = ntohl(ip_packet->source_address);
            entry->local_port = ntohs(napt_packet->icmp.identify);
        }
    }

    uint32_t checksum = napt_packet->icmp.header.checksum;
    checksum = ~checksum;
    checksum -= napt_packet->icmp.identify;
    if(direction == napt_direction::incoming){
        checksum += htons(entry->local_port);
    }else{
        checksum += htons(entry->global_port);
    }
    checksum = ~checksum;

    if(checksum > 0xffff){
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }
    napt_packet->icmp.header.checksum = checksum;

    if(direction == napt_direction::incoming){
        ip_packet->destination_address = htonl(entry->local_address);
        napt_packet->icmp.identify = htons(entry->local_port);
    }else{
#if DEBUG_NAT > 0
        printf("[NAT] Address port translation executed %s:%d => %s:%d\n", inet_ntoa(ip_packet->source_address),
               ntohs(napt_packet->icmp.identify), inet_htoa(napt_dev->outside_address), entry->global_port);
#endif
        ip_packet->source_address = htonl(napt_dev->outside_address);
        napt_packet->icmp.identify = htons(entry->global_port);
    }

    ip_packet->header_checksum = 0;
    ip_packet->header_checksum = calc_checksum_16(reinterpret_cast<uint16_t*>(ip_packet), sizeof(ip_header));

    return true;
}

bool napt_udp(ip_header* ip_packet, size_t len, napt_inside_device* napt_dev, napt_direction direction){

    auto* napt_packet = (napt_packet_head*) ((uint8_t*) ip_packet + sizeof(ip_header));
#if DEBUG_NAT > 0
    printf("[NAT] NAPT Destination packet arrived\n");
#endif
    napt_entry* entry;
    if(direction == napt_direction::incoming){
        entry = get_napt_udp_entry_by_global(napt_dev->entries, ntohl(ip_packet->destination_address),
                                             ntohs(napt_packet->dest_port));
        if(entry == nullptr){
            return false;
        }
    }else{
        entry = get_napt_udp_entry_by_local(napt_dev->entries, ntohl(ip_packet->source_address),
                                            ntohs(napt_packet->src_port));
        if(entry == nullptr){
            entry = create_napt_udp_entry(napt_dev->entries);
            if(entry == nullptr){
#if DEBUG_NAT > 0
                printf("[NAT] NAPT table is full!\n");
#endif
                return false;
            }
#if DEBUG_NAT > 0
            printf("[NAT] Created new nat table entry global port %d\n", entry->global_port);
#endif
            entry->global_address = napt_dev->outside_address;
            entry->local_address = ntohl(ip_packet->source_address);
            entry->local_port = ntohs(napt_packet->src_port);

        }
    }

    uint32_t checksum = napt_packet->udp.checksum;
    checksum = ~checksum;

    if(direction == napt_direction::incoming){
        checksum -= ip_packet->destination_address & 0xffff;
        checksum -= ip_packet->destination_address >> 16;
        checksum -= napt_packet->dest_port;
        checksum += htonl(entry->local_address) & 0xffff;
        checksum += htonl(entry->local_address) >> 16;
        checksum += htons(entry->local_port);
    }else{
        checksum -= ip_packet->source_address & 0xffff;
        checksum -= ip_packet->source_address >> 16;
        checksum -= napt_packet->src_port;
        checksum += htonl(napt_dev->outside_address) & 0xffff;
        checksum += htonl(napt_dev->outside_address) >> 16;
        checksum += htons(entry->global_port);
    }

    checksum = ~checksum;
    if(checksum > 0xffff){
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }

    napt_packet->udp.checksum = checksum;

    if(direction == napt_direction::incoming){
        ip_packet->destination_address = htonl(entry->local_address);
        napt_packet->dest_port = htons(entry->local_port);
    }else{
        ip_packet->source_address = htonl(napt_dev->outside_address);
        napt_packet->src_port = htons(entry->global_port);
    }
    ip_packet->header_checksum = 0;
    ip_packet->header_checksum = calc_checksum_16(reinterpret_cast<uint16_t*>(ip_packet), sizeof(ip_header));
    return true;
}

bool napt_tcp(ip_header* ip_packet, size_t len, napt_inside_device* napt_dev, napt_direction direction){

    auto* napt_packet = (napt_packet_head*) ((uint8_t*) ip_packet + sizeof(ip_header));
#if DEBUG_NAT > 0
    printf("[NAT] NAPT Destination packet arrived\n");
#endif
    napt_entry* entry;
    if(direction == napt_direction::incoming){
        entry = get_napt_tcp_entry_by_global(napt_dev->entries, ntohl(ip_packet->destination_address),
                                             ntohs(napt_packet->dest_port));
        if(entry == nullptr){
            return false;
        }
    }else{
        entry = get_napt_tcp_entry_by_local(napt_dev->entries, ntohl(ip_packet->source_address),
                                            ntohs(napt_packet->src_port));
        if(entry == nullptr){
            entry = create_napt_tcp_entry(napt_dev->entries);
            if(entry == nullptr){
#if DEBUG_NAT > 0
                printf("[NAT] NAPT table is full!\n");
#endif
                return false;
            }
#if DEBUG_NAT > 0
            printf("[NAT] Created new nat table entry global port %d\n", entry->global_port);
#endif
            entry->global_address = napt_dev->outside_address;
            entry->local_address = ntohl(ip_packet->source_address);
            entry->local_port = ntohs(napt_packet->src_port);

        }
    }

    uint32_t checksum = napt_packet->tcp.checksum;
    checksum = ~checksum;

    if(direction == napt_direction::incoming){
        checksum -= ip_packet->destination_address & 0xffff;
        checksum -= ip_packet->destination_address >> 16;
        checksum -= napt_packet->dest_port;
        checksum += htonl(entry->local_address) & 0xffff;
        checksum += htonl(entry->local_address) >> 16;
        checksum += htons(entry->local_port);
    }else{
        checksum -= ip_packet->source_address & 0xffff;
        checksum -= ip_packet->source_address >> 16;
        checksum -= napt_packet->src_port;
        checksum += htonl(napt_dev->outside_address) & 0xffff;
        checksum += htonl(napt_dev->outside_address) >> 16;
        checksum += htons(entry->global_port);
    }

    checksum = ~checksum;
    if(checksum > 0xffff){
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }

    napt_packet->tcp.checksum = checksum;

    if(direction == napt_direction::incoming){
        ip_packet->destination_address = htonl(entry->local_address);
        napt_packet->dest_port = htons(entry->local_port);
    }else{
        ip_packet->source_address = htonl(napt_dev->outside_address);
        napt_packet->src_port = htons(entry->global_port);
    }
    ip_packet->header_checksum = 0;
    ip_packet->header_checksum = calc_checksum_16(reinterpret_cast<uint16_t*>(ip_packet), sizeof(ip_header));
    return true;
}

napt_entry* get_napt_icmp_entry_by_global(napt_entries* entries, uint32_t address, uint16_t id){

        if(entries->icmp[id].global_address == address and entries->icmp[id].global_port == id){
            return &entries->icmp[id];
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

    if(entries->tcp[port - NAPT_GLOBAL_PORT_MIN].global_address == address and entries->tcp[port - NAPT_GLOBAL_PORT_MIN].global_port == port){
        return &entries->tcp[port - NAPT_GLOBAL_PORT_MIN];
    }
    return nullptr;
}

napt_entry* get_napt_tcp_entry_by_local(napt_entries* entries, uint32_t address, uint16_t port){

    for(int i = 0; i < NAPT_GLOBAL_PORT_SIZE; ++i){
        if(entries->tcp[i].local_address == address and entries->tcp[i].local_port == port){
            printf("Matched %d!\n", i);
            return &entries->tcp[i];
        }
    }
    return nullptr;
}


napt_entry* get_napt_udp_entry_by_global(napt_entries* entries, uint32_t address, uint16_t port){
    if(entries->udp[port - NAPT_GLOBAL_PORT_MIN].global_address == address and entries->udp[port - NAPT_GLOBAL_PORT_MIN].global_port == port){
        return &entries->udp[port] - NAPT_GLOBAL_PORT_MIN;
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