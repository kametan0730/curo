#include "ip.h"

#include "utils.h"

#include "icmp.h"
#include "my_buf.h"
#include "ethernet.h"
#include "binary_trie.h"
#include "arp.h"

binary_trie_node<ip_route_entry>* ip_fib;

void ip_input_to_ours(net_device *source_device, ip_header *ip_packet, size_t len) {

    if ((ntohs(ip_packet->frags_and_offset) & IP_FRAG_AND_OFFSET_FIELD_MASK_OFFSET) != 0 or
        (ntohs(ip_packet->frags_and_offset) &
         IP_FRAG_AND_OFFSET_FIELD_MASK_MORE_FRAGMENT_FLAG)) {
        printf("IP fragment is not supported (offset:%d, more_fragment:%d)",
               ip_packet->frags_and_offset & IP_FRAG_AND_OFFSET_FIELD_MASK_OFFSET,
               ip_packet->frags_and_offset & IP_FRAG_AND_OFFSET_FIELD_MASK_MORE_FRAGMENT_FLAG
        );
        return;
    }

    switch (ip_packet->protocol) {

        case IP_PROTOCOL_TYPE_ICMP:

            return icmp_input(ntohl(ip_packet->source_address),
                              ntohl(ip_packet->destination_address),
                              ((uint8_t *) ip_packet) + IP_HEADER_SIZE, len - IP_HEADER_SIZE);

        default:
            printf("Unhandled ours ip packet from %s to %s protocol %d",
                   inet_ntoa(ip_packet->source_address),
                   inet_ntoa(ip_packet->destination_address),
                   ip_packet->protocol);
            return;
    }
}

void ip_input(net_device *source_device, uint8_t *buffer, ssize_t len) {
    bool has_header_option = false;

    if(source_device->ip_dev == nullptr){
        printf("Illegal ip interface\n");
        return;
    }

    if (source_device->ip_dev->address == IP_ADDRESS_FROM_NETWORK(0, 0, 0, 0)) {
        printf("Illegal ip interface\n");
        return;

    }

    if (len < sizeof(ip_header) + 8) {
        printf("Illegal ip packet length\n");
        return;
    }

    auto *ip_packet = reinterpret_cast<ip_header *>(buffer);
    printf("Received IPv4 type %d from %s to %s\n", ip_packet->protocol, inet_ntoa(ip_packet->source_address),
           inet_ntoa(ip_packet->destination_address));

    if (ip_packet->version != 4) {
        printf("Unknown ip version\n");
        return;
    }

    if (ip_packet->header_len != (sizeof(ip_header) >> 2)) {
        printf("IP header option is not supported\n");
        has_header_option = true;
        return; // TODO support
    }

    if (ip_packet->destination_address == IP_ADDRESS_FROM_HOST(255, 255, 255, 255)) {
        printf("Broadcast ip packet received\n");
        return ip_input_to_ours(source_device, ip_packet, len);
    }

    for (net_device *dev = net_dev; dev; dev = dev->next) {
        if (dev->ip_dev->address != IP_ADDRESS_FROM_NETWORK(0, 0, 0, 0)) {
            if (htonl(dev->ip_dev->address) == ip_packet->destination_address) { // TODO ブロードキャストを考慮
                // go to ours
                return ip_input_to_ours(dev, ip_packet, len);

            }
        }
    }


    ip_route_entry* route = binary_trie_search(ip_fib, ntohl(ip_packet->destination_address));
    if(route == nullptr){
        printf("No route to %s\n", inet_htoa(ntohl(ip_packet->destination_address)));
        return;
    }

    my_buf* ip_forward_buf = my_buf::create(0);
    ip_forward_buf->buf_ptr = buffer;
    ip_forward_buf->len = len;


    if(route->type == host){
        ip_output_to_host(route->device, ntohl(ip_packet->destination_address), ip_forward_buf);
        return;
    }

    if(route->type == network){
        ip_output_to_next_hop(route->next_hop, ip_forward_buf);
        return;
    }
}

void ip_output_to_host(net_device* dev, uint32_t dest_address, my_buf* buffer){
    arp_table_entry* entry = search_arp_table_entry(dest_address);

    if(!entry) {
        printf("Trying ip output to host, but no arp record to %s\n", inet_htoa(dest_address));

        issue_arp_request(dev, dest_address);
    }else{
        ethernet_output(entry->device, entry->mac_address, buffer, ETHERNET_PROTOCOL_TYPE_IP);
    }
}

void ip_output_to_next_hop(uint32_t next_hop, my_buf* buffer){
    arp_table_entry* entry = search_arp_table_entry(next_hop);

    if(!entry) {
        printf("Trying ip output to next hop, but no arp record to %s\n", inet_htoa(next_hop));

        ip_route_entry* route_to_next_hop = binary_trie_search(ip_fib, next_hop);

        if(route_to_next_hop == nullptr or route_to_next_hop->type != host) {
            printf("Next hop %s is not reachable\n", inet_htoa(next_hop));
        }else{
            issue_arp_request(route_to_next_hop->device, next_hop);
        }

    }else{
        ethernet_output(entry->device, entry->mac_address, buffer, ETHERNET_PROTOCOL_TYPE_IP);
    }
}

void ip_output(uint32_t destination_address, uint32_t source_address, my_buf* buffer, uint16_t protocol_type){


    dump_arp_table_entry();
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

    ip_route_entry* route = binary_trie_search(ip_fib, destination_address);
    if(route == nullptr){
        printf("No route to %s\n", inet_htoa(destination_address));
        return;
    }

    if(route->type == host){
        ip_output_to_host(route->device, destination_address, buf);
        return;
    }

    if(route->type == network){
        ip_output_to_next_hop(route->next_hop, buf);
        return;
    }

}
