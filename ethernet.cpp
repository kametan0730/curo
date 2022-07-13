#include "ethernet.h"


#include <cstring>

#include "arp.h"
#include "ip.h"
#include "utils.h"
#include "my_buf.h"
#include "config.h"

uint8_t broadcast_address[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void ethernet_input(net_device* dev, uint8_t* buffer, ssize_t len){

    auto* header = reinterpret_cast<ethernet_header*>(buffer);
    uint16_t ethernet_type = ntohs(header->type);

    if(memcmp(header->dest_address, dev->mac_address, 6) != 0 and
        memcmp(header->dest_address, broadcast_address, 6) != 0){
        return;
    }

#ifdef DEBUG_IP
    printf("Received ethernet frame type %04x from %s to %s\n",
           ethernet_type, mac_addr_toa(header->src_address),
           mac_addr_toa(header->dest_address));
#endif

    switch(ethernet_type){
        case ETHERNET_PROTOCOL_TYPE_ARP:
            return arp_input(
                    dev,
                    buffer + ETHERNET_HEADER_SIZE,
                    len - ETHERNET_HEADER_SIZE);
        case ETHERNET_PROTOCOL_TYPE_IP:
            return ip_input(
                    dev,
                    buffer + ETHERNET_HEADER_SIZE,
                    len - ETHERNET_HEADER_SIZE);
        default:
#ifdef DEBUG_IP
            printf("Received unhandled ethernet type %04x\n", ethernet_type);
#endif
            return;
    }
}


void ethernet_output_broadcast(net_device* device, my_buf* buffer, uint16_t protocol_type){

    my_buf* new_buffer = my_buf::create(ETHERNET_HEADER_SIZE);
    auto* header = reinterpret_cast<ethernet_header*>(new_buffer->buffer);

    memcpy(&header->src_address, &device->mac_address, 6);
    memset(&header->dest_address, 0xff, 6);
    header->type = htons(protocol_type);

    buffer->add_header(new_buffer);

    net_device_send_my_buf(device, buffer);
}

void ethernet_output(net_device* device, uint8_t destination_mac_address[], my_buf* buffer, uint16_t protocol_type){

    printf("Sent ethernet frame type %04x from %s to %s\n",
           protocol_type, mac_addr_toa(device->mac_address),
           mac_addr_toa(destination_mac_address));

    my_buf* ethernet_header_my_buf = my_buf::create(ETHERNET_HEADER_SIZE);
    auto* ether_header = reinterpret_cast<ethernet_header*>(ethernet_header_my_buf->buffer);

    memcpy(ether_header->src_address, device->mac_address, 6);
    memcpy(ether_header->dest_address, destination_mac_address, 6);
    ether_header->type = htons(protocol_type);

    buffer->add_header(ethernet_header_my_buf);

#ifdef DEBUG_IP
#if DEBUG_IP > 1
    for (int i = 0; i < ethernet_header_my_buf->len; ++i) {
        printf("%02x", ethernet_header_my_buf->buffer[i]);
    }
#endif
#endif
    printf("\n");

    net_device_send_my_buf(device, ethernet_header_my_buf);
}
