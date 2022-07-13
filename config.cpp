#include "config.h"

#include "net.h"
#include "ip.h"
#include "binary_trie.h"
#include "utils.h"

void configure_ip(const char* interface, uint32_t address, uint32_t netmask){

    for (net_device *a = net_dev; a; a = a->next) {
        if (strcmp(a->ifname, interface) == 0) {
            printf("Set ip address to %s\n", a->ifname);
            a->ip_dev = (ip_device *) calloc(1, sizeof(ip_device));
            a->ip_dev->address = address;
            a->ip_dev->netmask = netmask;
        }
    }

    ip_route_entry *ire = (ip_route_entry *) calloc(1, sizeof(ip_route_entry));
    ire->type = host;

    int len = 0; // サブネットマスクとプレフィックス長の変換
    for (; len < 32; ++len) {
        if(!(netmask >> (31 - len) & 0b01)){
            break;
        }
    }

    add(ip_fib, address & netmask, len, ire);

    printf("Set host route %s/%d via %s\n", inet_htoa(address & netmask), len, interface);

}

void configure(){

    configure_ip("router-to-host0", IP_ADDRESS_FROM_HOST(192, 168, 111, 1), IP_ADDRESS_FROM_HOST(255, 255, 255, 0));
    configure_ip("router-to-host1", IP_ADDRESS_FROM_HOST(192, 168, 222, 1), IP_ADDRESS_FROM_HOST(255, 255, 255, 0));

}