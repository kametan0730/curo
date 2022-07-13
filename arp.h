#ifndef RAW_SOCKET_ARP_H
#define RAW_SOCKET_ARP_H

#include <iostream>

#define GOLDEN_RATIO_32 0x61C88647
#define GOLDEN_RATIO_64 0x61C8864680B583EBull

#define ARP_HTYPE_ETHERNET 0x0001

#define ARP_OPERATION_CODE_REQUEST  0x0001
#define ARP_OPERATION_CODE_REPLY    0x0002

#define ARP_TABLE_SIZE 5555

struct net_device;

struct arp_table_entry{
    uint8_t mac_address[6];
    uint32_t ip_address;
    net_device* device;
    bool is_expired;
    uint64_t expired_at;
    arp_table_entry* next;
};

bool add_arp_table_entry(net_device* device, uint8_t mac_address[], uint32_t ip_address);

arp_table_entry* search_arp_table_entry(uint32_t ip_address);

void dump_arp_table_entry();

void issue_arp_request(net_device* device, uint32_t ip);

struct arp_ip_to_ethernet{
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sha[6];
    uint32_t spa;
    uint8_t tha[6];
    uint32_t tpa;
} __attribute__((packed));



void arp_input(net_device *source_interface,  uint8_t* buffer, ssize_t len);
#endif //RAW_SOCKET_ARP_H
