#ifndef RAW_SOCKET_IP_H
#define RAW_SOCKET_IP_H

#include <iostream>
#include <queue>

#define IP_ADDRESS_FROM_HOST(A, B, C, D) (A * 0x1000000u + B * 0x10000 + C * 0x100 + D)
#define IP_ADDRESS_FROM_NETWORK(D, C, B, A) (A * 0x1000000u + B * 0x10000 + C * 0x100 + D)

#define IP_HEADER_SIZE 20

#define IP_ADDRESS_LIMITED_BROADCAST IP_ADDRESS_FROM_HOST(255, 255, 255, 255)

#define IP_PROTOCOL_TYPE_ICMP 0x01
#define IP_PROTOCOL_TYPE_TCP 0x06
#define IP_PROTOCOL_TYPE_UDP 0x11

#define IP_FRAG_AND_OFFSET_FIELD_MASK_RESERVED_FLAG         0b1000000000000000
#define IP_FRAG_AND_OFFSET_FIELD_MASK_DONT_FRAGMENT_FLAG    0b0100000000000000
#define IP_FRAG_AND_OFFSET_FIELD_MASK_MORE_FRAGMENT_FLAG    0b0010000000000000
#define IP_FRAG_AND_OFFSET_FIELD_MASK_OFFSET                0b0001111111111111

struct ip_header {
    uint8_t header_len: 4;
    uint8_t version: 4;
    uint8_t tos;
    uint16_t tlen;
    uint16_t identify;
    uint16_t frags_and_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t source_address;
    uint32_t destination_address;
} __attribute__((packed));


struct ip_device {
    uint32_t address = 0;
    uint32_t netmask = 0;
    uint32_t gateway = 0;
};

enum ip_route_type{
    host, network
};

struct ip_route_entry{
    ip_route_type type;
    union{
        uint32_t if_index;
        uint32_t next_hop;
    };
};

template<typename DATA_TYPE>
struct binary_trie_node;

extern binary_trie_node<ip_route_entry>* ip_fib;

struct net_device;

void ip_input(net_device *dev, uint8_t *buffer, ssize_t len);

struct my_buf;
void ip_output(uint32_t destination_address, uint32_t source_address, my_buf* buffer, uint16_t protocol_type);

#endif //RAW_SOCKET_IP_H