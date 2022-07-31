#include "ip.h"

#include "utils.h"

#include "napt.h"
#include "icmp.h"
#include "my_buf.h"
#include "ethernet.h"
#include "binary_trie.h"
#include "arp.h"
#include "config.h"

binary_trie_node<ip_route_entry>* ip_fib;

void ip_input_to_ours(net_device* source_device, ip_header* ip_packet, size_t len){

    if((ntohs(ip_packet->frags_and_offset) & IP_FRAG_AND_OFFSET_FIELD_MASK_OFFSET) != 0 or
       (ntohs(ip_packet->frags_and_offset) &
        IP_FRAG_AND_OFFSET_FIELD_MASK_MORE_FRAGMENT_FLAG)){
#if DEBUG_IP > 0
        printf("[IP] IP fragment is not supported (offset:%d, more_fragment:%d)",
               ip_packet->frags_and_offset & IP_FRAG_AND_OFFSET_FIELD_MASK_OFFSET,
               ip_packet->frags_and_offset & IP_FRAG_AND_OFFSET_FIELD_MASK_MORE_FRAGMENT_FLAG
        );
#endif
        return;
    }

    net_device* a;
    for(a = net_dev; a; a = a->next){
        if(a->ip_dev != nullptr and a->ip_dev->napt_inside_dev != nullptr and a->ip_dev->napt_inside_dev->outside_address == ntohl(ip_packet->destination_address)){
            switch(ip_packet->protocol){
                case IP_PROTOCOL_TYPE_ICMP:{
                    auto* napt_packet = (napt_packet_head*) ((uint8_t*) ip_packet + sizeof(ip_header));
                    if(napt_packet->icmp.header.type == ICMP_TYPE_ECHO_REQUEST or napt_packet->icmp.header.type == ICMP_TYPE_ECHO_REPLY){
                        printf("[IP] NAPT ICMP Destination packet arrived\n");
                        napt_entry* entry;
                        entry = get_napt_icmp_entry_by_global(a->ip_dev->napt_inside_dev->entries, ntohl(ip_packet->destination_address), ntohs(napt_packet->icmp.identify));
                        if(entry == nullptr){ // エントリにない外側アドレスへの通信
                            // Drop
                            continue;
                        }

                        uint32_t icmp_checksum = napt_packet->icmp.header.checksum;
                        icmp_checksum = ~icmp_checksum;
                        icmp_checksum -= napt_packet->icmp.identify;
                        icmp_checksum += htons(entry->local_port);
                        icmp_checksum = ~icmp_checksum;

                        if(icmp_checksum > 0xffff){
                            icmp_checksum = (icmp_checksum & 0xffff) + (icmp_checksum >> 16);
                        }
                        napt_packet->icmp.header.checksum = icmp_checksum;

                        ip_packet->destination_address = htonl(entry->local_address);
                        napt_packet->icmp.identify = htons(entry->local_port);

                        ip_packet->header_checksum = 0;
                        ip_packet->header_checksum = calc_checksum_16(reinterpret_cast<uint16_t*>(ip_packet), sizeof(ip_header));

                        my_buf* nat_fwd_buf = my_buf::create(0);
                        nat_fwd_buf->buf_ptr = (uint8_t*) ip_packet;
                        nat_fwd_buf->len = len;
                        ip_output(entry->local_address, nat_fwd_buf);
                        return;
                    }
                }
                    break;
                case IP_PROTOCOL_TYPE_UDP:
                case IP_PROTOCOL_TYPE_TCP:{
                    auto* napt_packet = (napt_packet_head*) ((uint8_t*) ip_packet + sizeof(ip_header));

                    net_device* a;
                    for(a = net_dev; a; a = a->next){
                        if(a->ip_dev != nullptr and a->ip_dev->napt_inside_dev != nullptr and a->ip_dev->napt_inside_dev->outside_address == ntohl(ip_packet->destination_address)){
                            printf("[IP] NAPT Destination packet arrived\n");
                            napt_entry* entry;
                            if(ip_packet->protocol == IP_PROTOCOL_TYPE_TCP){
                                entry = get_napt_tcp_entry_by_global(a->ip_dev->napt_inside_dev->entries, ntohl(ip_packet->destination_address), ntohs(napt_packet->dest_port));
                            }else{
                                entry = get_napt_udp_entry_by_global(a->ip_dev->napt_inside_dev->entries, ntohl(ip_packet->destination_address), ntohs(napt_packet->dest_port));

                            }
                            if(entry == nullptr){ // エントリにない外側アドレスへの通信
                                // Drop
                                continue;
                            }

                            if(ip_packet->protocol == IP_PROTOCOL_TYPE_UDP){
                                uint32_t exs_sum = napt_packet->udp.checksum;
                                exs_sum = ~exs_sum;
                                exs_sum -= ip_packet->destination_address & 0xffff;
                                exs_sum -= ip_packet->destination_address >> 16;
                                exs_sum -= napt_packet->dest_port;
                                exs_sum += htonl(entry->local_address) & 0xffff;
                                exs_sum += htonl(entry->local_address) >> 16;
                                exs_sum += htons(entry->local_port);
                                exs_sum = ~exs_sum;
                                if(exs_sum > 0xffff){
                                    exs_sum = (exs_sum & 0xffff) + (exs_sum >> 16);
                                }

                                napt_packet->udp.checksum = exs_sum;
                            }else if(ip_packet->protocol == IP_PROTOCOL_TYPE_TCP){
                                uint32_t exs_sum = napt_packet->tcp.checksum;
                                exs_sum = ~exs_sum;
                                exs_sum -= ip_packet->destination_address & 0xffff;
                                exs_sum -= ip_packet->destination_address >> 16;
                                exs_sum -= napt_packet->dest_port;
                                exs_sum += htonl(entry->local_address) & 0xffff;
                                exs_sum += htonl(entry->local_address) >> 16;
                                exs_sum += htons(entry->local_port);
                                exs_sum = ~exs_sum;
                                if(exs_sum > 0xffff){
                                    exs_sum = (exs_sum & 0xffff) + (exs_sum >> 16);
                                }

                                napt_packet->tcp.checksum = exs_sum;
                            }

                            ip_packet->destination_address = htonl(entry->local_address);
                            napt_packet->dest_port = htons(entry->local_port);

                            ip_packet->header_checksum = 0;
                            ip_packet->header_checksum = calc_checksum_16(reinterpret_cast<uint16_t*>(ip_packet), sizeof(ip_header));

                            my_buf* nat_fwd_buf = my_buf::create(0);
                            nat_fwd_buf->buf_ptr = (uint8_t*) ip_packet;
                            nat_fwd_buf->len = len;
                            ip_output(entry->local_address, nat_fwd_buf);
                            return;
                        }
                    }

                }
                    break;
            }
        }
    }


    switch(ip_packet->protocol){

        case IP_PROTOCOL_TYPE_ICMP:

            return icmp_input(ntohl(ip_packet->source_address),
                              ntohl(ip_packet->destination_address),
                              ((uint8_t*) ip_packet) + IP_HEADER_SIZE, len - IP_HEADER_SIZE);

        case IP_PROTOCOL_TYPE_UDP:
        case IP_PROTOCOL_TYPE_TCP:{
            // NAPTの判定

            break;
        }

        default:
#if DEBUG_IP > 0
            printf("[IP] Unhandled ours ip packet from %s to %s protocol %d",
                   inet_ntoa(ip_packet->source_address),
                   inet_ntoa(ip_packet->destination_address),
                   ip_packet->protocol);
#endif
            return;
    }
}

void ip_input(net_device* source_device, uint8_t* buffer, ssize_t len){
    bool has_header_option = false;

    if(source_device->ip_dev == nullptr){
#if DEBUG_IP > 0
        printf("[IP] Illegal ip interface\n");
#endif
        return;
    }

    if(source_device->ip_dev->address == IP_ADDRESS_FROM_NETWORK(0, 0, 0, 0)){
#if DEBUG_IP > 0
        printf("[IP] Illegal ip interface\n");
#endif
        return;
    }

    if(len < sizeof(ip_header) + 8){
#if DEBUG_IP > 0
        printf("[IP] Illegal ip packet length\n");
#endif
        return;
    }

    auto* ip_packet = reinterpret_cast<ip_header*>(buffer);
#if DEBUG_IP > 0
    printf("[IP] Received IPv4 type %d from %s to %s\n", ip_packet->protocol, inet_ntoa(ip_packet->source_address),
           inet_ntoa(ip_packet->destination_address));
#endif

    if(ip_packet->version != 4){
#if DEBUG_IP > 0
        printf("[IP] Unknown ip version\n");
#endif
        return;
    }

    if(ip_packet->header_len != (sizeof(ip_header) >> 2)){
#if DEBUG_IP > 0
        printf("[IP] IP header option is not supported\n");
#endif
        has_header_option = true;
        return; // TODO support
    }

    if(ip_packet->destination_address == IP_ADDRESS_FROM_HOST(255, 255, 255, 255)){
#if DEBUG_IP > 0
        printf("[IP] Broadcast ip packet received\n");
#endif
        return ip_input_to_ours(source_device, ip_packet, len);
    }

    for(net_device* dev = net_dev; dev; dev = dev->next){
        if(dev->ip_dev->address != IP_ADDRESS_FROM_NETWORK(0, 0, 0, 0)){
            if(htonl(dev->ip_dev->address) == ip_packet->destination_address){ // TODO ブロードキャストを考慮
                // go to ours
                return ip_input_to_ours(dev, ip_packet, len);

            }
        }
    }

    // go to forward

    if(source_device->ip_dev->napt_inside_dev != nullptr){

        if(ip_packet->protocol == IP_PROTOCOL_TYPE_UDP or ip_packet->protocol == IP_PROTOCOL_TYPE_TCP){ // NAPTの対象
            printf("[IP] Nat execution\n");
            auto* napt_packet = (napt_packet_head*) ((uint8_t*) ip_packet + sizeof(ip_header));

            napt_entry* e;
            if(ip_packet->protocol == IP_PROTOCOL_TYPE_TCP){
                e = get_napt_tcp_entry_by_local(source_device->ip_dev->napt_inside_dev->entries, ntohl(ip_packet->source_address), ntohs(napt_packet->src_port));
            }else{
                e = get_napt_udp_entry_by_local(source_device->ip_dev->napt_inside_dev->entries, ntohl(ip_packet->source_address), ntohs(napt_packet->src_port));
            }
            if(e == nullptr){ // 同一フローのNAPTエントリーが無かったら
                if(ip_packet->protocol == IP_PROTOCOL_TYPE_TCP){

                    e = create_napt_tcp_entry(source_device->ip_dev->napt_inside_dev->entries);
                }else{
                    e = create_napt_udp_entry(source_device->ip_dev->napt_inside_dev->entries);
                }
                if(e == nullptr){
#if DEBUG_IP > 0
                    printf("[IP] NAPT table is full!\n");
#endif
                    return;
                }else{
#if DEBUG_IP > 0
                    printf("[IP] Created new nat table entry global port %d\n", e->global_port);
#endif
                }
            }

            printf("[IP] Address port translation executed %s:%d translated to %s:%d\n", inet_ntoa(ip_packet->source_address), ntohs(napt_packet->src_port), inet_htoa(source_device->ip_dev->napt_inside_dev->outside_address), e->global_port);

            e->global_address = source_device->ip_dev->napt_inside_dev->outside_address;
            e->local_address = ntohl(ip_packet->source_address);
            e->local_port = ntohs(napt_packet->src_port);


            // パケットの書き換え

            if(ip_packet->protocol == IP_PROTOCOL_TYPE_UDP){
                uint32_t exs_sum = napt_packet->udp.checksum;
                exs_sum = ~exs_sum;
                exs_sum -= ip_packet->source_address & 0xffff;
                exs_sum -= ip_packet->source_address >> 16;
                exs_sum -= napt_packet->src_port;
                exs_sum += htonl(source_device->ip_dev->napt_inside_dev->outside_address) & 0xffff;
                exs_sum += htonl(source_device->ip_dev->napt_inside_dev->outside_address) >> 16;
                exs_sum += htons(e->global_port);

                exs_sum = ~exs_sum;


                if(exs_sum > 0xffff){
                    exs_sum = (exs_sum & 0xffff) + (exs_sum >> 16);
                }

                napt_packet->udp.checksum = exs_sum;
            }else if(ip_packet->protocol == IP_PROTOCOL_TYPE_TCP){

                uint32_t exs_sum = napt_packet->tcp.checksum;
                exs_sum = ~exs_sum;
                exs_sum -= ip_packet->source_address & 0xffff;
                exs_sum -= ip_packet->source_address >> 16;
                exs_sum -= napt_packet->src_port;
                exs_sum += htonl(source_device->ip_dev->napt_inside_dev->outside_address) & 0xffff;
                exs_sum += htonl(source_device->ip_dev->napt_inside_dev->outside_address) >> 16;
                exs_sum += htons(e->global_port);

                exs_sum = ~exs_sum;


                if(exs_sum > 0xffff){
                    exs_sum = (exs_sum & 0xffff) + (exs_sum >> 16);
                }

                napt_packet->tcp.checksum = exs_sum;

            }

            ip_packet->source_address = htonl(source_device->ip_dev->napt_inside_dev->outside_address);
            napt_packet->src_port = htons(e->global_port);

            ip_packet->header_checksum = 0;
            ip_packet->header_checksum = calc_checksum_16(reinterpret_cast<uint16_t*>(buffer), sizeof(ip_header));

        }else if(ip_packet->protocol == IP_PROTOCOL_TYPE_ICMP){

            auto* napt_packet = (napt_packet_head*) ((uint8_t*) ip_packet + sizeof(ip_header));
            if(napt_packet->icmp.header.type == ICMP_TYPE_ECHO_REQUEST or napt_packet->icmp.header.type == ICMP_TYPE_ECHO_REPLY){

                napt_entry* e;
                e = get_napt_icmp_entry_by_local(source_device->ip_dev->napt_inside_dev->entries, ntohl(ip_packet->source_address), ntohs(napt_packet->icmp.identify));

                if(e == nullptr){ // 同一フローのNAPTエントリーが無かったら

                    e = create_napt_icmp_entry(source_device->ip_dev->napt_inside_dev->entries);

                    if(e == nullptr){
#if DEBUG_IP > 0
                        printf("[IP] NAPT table is full!\n");
#endif
                        return;
                    }else{
#if DEBUG_IP > 0
                        printf("[IP] Created new nat table entry global id %d\n", e->global_port);
#endif
                    }
                }

                printf("[IP] Address port translation executed %s:%d translated to %s:%d\n", inet_ntoa(ip_packet->source_address), ntohs(napt_packet->icmp.identify), inet_htoa(source_device->ip_dev->napt_inside_dev->outside_address), e->global_port);

                e->global_address = source_device->ip_dev->napt_inside_dev->outside_address;
                e->local_address = ntohl(ip_packet->source_address);
                e->local_port = ntohs(napt_packet->icmp.identify);

                uint32_t icmp_checksum = napt_packet->icmp.header.checksum;
                icmp_checksum = ~icmp_checksum;
                icmp_checksum -= napt_packet->icmp.identify;
                icmp_checksum += htons(e->global_port);
                icmp_checksum = ~icmp_checksum;

                if(icmp_checksum > 0xffff){
                    icmp_checksum = (icmp_checksum & 0xffff) + (icmp_checksum >> 16);
                }

                napt_packet->icmp.header.checksum = icmp_checksum;

                ip_packet->source_address = htonl(source_device->ip_dev->napt_inside_dev->outside_address);
                napt_packet->icmp.identify = htons(e->global_port);

#if DEBUG_IP > 0
                printf("[IP] ICMP Nat\n");
#endif

                //napt_packet->src_port = htons(e->global_port);


                ip_packet->header_checksum = 0;
                ip_packet->header_checksum = calc_checksum_16(reinterpret_cast<uint16_t*>(buffer), sizeof(ip_header));

            }else{ // ICMP error packet or else
                return;
            }


        }else{

#if DEBUG_IP > 0
            printf("[IP] NAPT unimplemented packet dropped type=%d\n", ip_packet->protocol);
#endif
            return;

        }
    }


    ip_route_entry* route = binary_trie_search(ip_fib, ntohl(ip_packet->destination_address));
    if(route == nullptr){
#if DEBUG_IP > 0
        printf("[IP] No route to %s\n", inet_htoa(ntohl(ip_packet->destination_address)));
#endif
        // Drop packet
        return;
    }

    my_buf* ip_forward_buf = my_buf::create(0);
    ip_forward_buf->buf_ptr = buffer;
    ip_forward_buf->len = len;


    if(route->type == host){
#if DEBUG_IP > 0
        printf("[IP] Fwd to host\n");
#endif
        ip_output_to_host(route->device, ntohl(ip_packet->destination_address), ip_forward_buf);
        return;
    }

    if(route->type == network){
#if DEBUG_IP > 0
        printf("[IP] Fwd to net\n");
#endif
        ip_output_to_next_hop(route->next_hop, ip_forward_buf);
        return;
    }
}

void ip_output_to_host(net_device* dev, uint32_t dest_address, my_buf* buffer){

    arp_table_entry* entry = search_arp_table_entry(dest_address);

    if(!entry){
#if DEBUG_IP > 0
        printf("[IP] Trying ip output to host, but no arp record to %s\n", inet_htoa(dest_address));
#endif
        my_buf::my_buf_free(buffer, true);
        // : Drop packet

        issue_arp_request(dev, dest_address);
    }else{
        ethernet_output(entry->device, entry->mac_address, buffer, ETHERNET_PROTOCOL_TYPE_IP);
    }
}

void ip_output_to_next_hop(uint32_t next_hop, my_buf* buffer){
    arp_table_entry* entry = search_arp_table_entry(next_hop);

    if(!entry){
#if DEBUG_IP > 0
        printf("[IP] Trying ip output to next hop, but no arp record to %s\n", inet_htoa(next_hop));
#endif
        my_buf::my_buf_free(buffer, true);

        ip_route_entry* route_to_next_hop = binary_trie_search(ip_fib, next_hop);

        if(route_to_next_hop == nullptr or route_to_next_hop->type != host){
#if DEBUG_IP > 0
            printf("[IP] Next hop %s is not reachable\n", inet_htoa(next_hop));
#endif
            my_buf::my_buf_free(buffer, true);


        }else{
            issue_arp_request(route_to_next_hop->device, next_hop);
        }

    }else{
        ethernet_output(entry->device, entry->mac_address, buffer, ETHERNET_PROTOCOL_TYPE_IP);
    }
}

void ip_output(uint32_t dest, my_buf* buffer){

    ip_route_entry* route = binary_trie_search(ip_fib, dest);
    if(route == nullptr){
#if DEBUG_IP > 0
        printf("[IP] No route to %s\n", inet_htoa(dest));
#endif
        return;
    }

    if(route->type == host){
#if DEBUG_IP > 0
        printf("[IP] Fwd to host\n");
#endif
        ip_output_to_host(route->device, dest, buffer);
        return;
    }

    if(route->type == network){
#if DEBUG_IP > 0
        printf("[IP] Fwd to net\n");
#endif
        ip_output_to_next_hop(route->next_hop, buffer);
        return;
    }

}


void ip_encapsulate_output(uint32_t destination_address, uint32_t source_address, my_buf* buffer, uint8_t protocol_type){
    uint16_t total_len = 0;

    my_buf* current_buffer = buffer;
    while(current_buffer != nullptr){

        total_len += current_buffer->len;
        current_buffer = current_buffer->next_my_buf;
    }

    my_buf* buf = my_buf::create(IP_HEADER_SIZE);
    buffer->add_header(buf); // 連結

    auto* ip_buf = reinterpret_cast<ip_header*>(buf->buffer);
    // ip_buf->vhl = (4 << 4) | (sizeof(ip_header) >> 2);
    ip_buf->version = 4;
    ip_buf->header_len = sizeof(ip_header) >> 2;
    ip_buf->tos = 0;
    ip_buf->tlen = htons(sizeof(ip_header) + total_len);
    ip_buf->protocol = protocol_type; // 8bit

    static uint64_t id = 0;
    ip_buf->identify = id++;
    ip_buf->frags_and_offset = 0;
    ip_buf->ttl = 0xff;
    ip_buf->header_checksum = 0;
    ip_buf->destination_address = htonl(destination_address);
    ip_buf->source_address = htonl(source_address);
    ip_buf->header_checksum = calc_checksum_16_my_buf(buf);

    ip_output(destination_address, buf);
}
