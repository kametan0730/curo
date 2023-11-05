#ifndef CURO_ND_H
#define CURO_ND_H

#include <cstdint>
#include "ipv6.h"

#define ND_TABLE_SIZE 1111

struct net_device;

struct nd_table_entry {
    uint8_t mac_addr[6];
    ipv6_addr v6addr;
    net_device *dev;
    nd_table_entry *next;
};

void add_nd_table_entry(net_device *dev, uint8_t *mac_addr, ipv6_addr v6_addr);

nd_table_entry *search_nd_table_entry(ipv6_addr v6_addr);

void dump_nd_table_entry();


#endif