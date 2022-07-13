#ifndef RAW_SOCKET_ICMP_H
#define RAW_SOCKET_ICMP_H

#include <iostream>

struct icmp_header{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
} __attribute__((packed));

struct icmp_echo{
    icmp_header header;
    uint16_t identify;
    uint16_t sequence;
    uint8_t data[];
} __attribute__((packed));


void icmp_input(uint32_t source, uint32_t destination, void* buffer, size_t len);


#endif //RAW_SOCKET_ICMP_H