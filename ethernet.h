#ifndef CURO_ETHERNET_H
#define CURO_ETHERNET_H

#include <iostream>
#include "net.h"

#define ETHERNET_HEADER_SIZE 14

#define ETHERNET_PROTOCOL_TYPE_IP 0x0800
#define ETHERNET_PROTOCOL_TYPE_ARP 0x0806
#define ETHERNET_PROTOCOL_TYPE_IPv6 0x86dd

const uint8_t ETHERNET_ADDRESS_BROADCAST[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

struct ethernet_header{
    uint8_t dest_address[6];
    uint8_t src_address[6];
    uint16_t type;
} __attribute__((packed));

void ethernet_input(net_device* dev, uint8_t* buffer, ssize_t n);

// void ethernet_output_broadcast(net_device* device, my_buf* buffer, uint16_t protocol_type);
void ethernet_encapsulate_output(net_device* device, const uint8_t* dest_addr, my_buf* buffer, uint16_t protocol_type);

#endif //CURO_ETHERNET_H
