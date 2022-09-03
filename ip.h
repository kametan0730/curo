#ifndef CURO_IP_H
#define CURO_IP_H

#include <iostream>
#include <queue>
#include "config.h"

#define IP_ADDRESS_LEN 4
#define IP_ADDRESS(A, B, C, D) (A * 0x1000000u + B * 0x10000 + C * 0x100 + D)
#define IP_ADDRESS_LIMITED_BROADCAST IP_ADDRESS(255, 255, 255, 255)

#define IP_HEADER_SIZE 20

#define IP_PROTOCOL_TYPE_ICMP 0x01
#define IP_PROTOCOL_TYPE_TCP 0x06
#define IP_PROTOCOL_TYPE_UDP 0x11

#define IP_FRAG_OFFSET_MASK_RESERVED_FLAG         0b1000000000000000
#define IP_FRAG_OFFSET_MASK_DF_FLAG    0b0100000000000000
#define IP_FRAG_OFFSET_MASK_MF_FLAG    0b0010000000000000
#define IP_FRAG_OFFSET_MASK_OFFSET                0b0001111111111111

struct ip_header{
    uint8_t header_len: 4;
    uint8_t version: 4;
    uint8_t tos;
    uint16_t total_len;
    uint16_t identify;
    uint16_t frag_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t src_addr;
    uint32_t dest_addr;
} __attribute__((packed));

struct napt_inside_device;

struct ip_device{
    uint32_t address = 0;
    uint32_t netmask = 0;
#ifdef ENABLE_NAPT
    napt_inside_device *napt_inside_dev = nullptr;
#endif
};

enum ip_route_type{
    connected, // 直接接続されているネットワークの経路　
    network
};

struct net_device;

struct ip_route_entry{
    ip_route_type type;
    union{
        net_device *device;
        uint32_t next_hop;
    };
};

template<typename DATA_TYPE>
struct binary_trie_node;

extern binary_trie_node<ip_route_entry> *ip_fib;

void dump_ip_fib();

struct net_device;

void ip_input(net_device *input_dev, uint8_t *buffer, ssize_t len);

struct my_buf;

void ip_output_to_host(net_device *dev, uint32_t src_address, uint32_t dest_address, my_buf *buffer);
void ip_output_to_next_hop(uint32_t next_hop, my_buf *buffer);
void ip_output(uint32_t src_addr, uint32_t dest_addr, my_buf *buffer);
void ip_encapsulate_output(uint32_t dest_addr, uint32_t src_addr, my_buf *buffer, uint8_t protocol_type);

#endif //CURO_IP_H
