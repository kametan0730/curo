#ifndef CURO_ICMPV6_H
#define CURO_ICMPV6_H

#include <iostream>
#include "ipv6.h"

#define ICMPV6_TYPE_ECHO_REQUEST 128
#define ICMPV6_TYPE_ECHO_REPLY 129

#define ICMPV6_TYPE_ROUTER_SOLICIATION 133
#define ICMPV6_TYPE_NEIGHBOR_SOLICIATION 135
#define ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT 136

#define ICMPV6_NA_FLAG_ROUTER    0b10000000
#define ICMPV6_NA_FLAG_SOLICITED 0b01000000
#define ICMPV6_NA_FLAG_OVERRIDE  0b00100000

struct icmpv6_hdr{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
} __attribute__((packed));

struct icmpv6_echo{
    icmpv6_hdr hdr;
    uint16_t id;
    uint16_t seq;
    uint8_t data[];
} __attribute__((packed));

struct icmpv6_na{
    icmpv6_hdr hdr;
    uint8_t flags;
    uint8_t reserved1;
    uint16_t reserved2;
    ipv6_addr target_addr;
    // options area
    uint8_t opt_type;
    uint8_t opt_length;
    uint8_t opt_mac_addr[6];
} __attribute__((packed));

void icmpv6_input(ipv6_device* v6dev, ipv6_addr source, ipv6_addr destination, void *buffer, size_t len);

#endif // CURO_ICMPV6_H
