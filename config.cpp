#include "config.h"

#include "net.h"
#include "ip.h"
#include "napt.h"
#include "binary_trie.h"
#include "utils.h"

void configure_net_route(uint32_t prefix, uint32_t prefix_len, uint32_t next_hop){

    uint32_t mask = 0xffffffff;
    mask <<= (32 - prefix_len);

    ip_route_entry *ire = (ip_route_entry *) calloc(1, sizeof(ip_route_entry));
    ire->type = network;
    ire->next_hop = next_hop;

    binary_trie_add(ip_fib, prefix & mask, prefix_len, ire);

}


void configure_ip(const char* interface, uint32_t address, uint32_t netmask){

    net_device *a;
    for (a = net_dev; a; a = a->next) {
        if (strcmp(a->ifname, interface) == 0) {
            printf("Set ip address to %s\n", a->ifname);
            a->ip_dev = (ip_device *) calloc(1, sizeof(ip_device));
            a->ip_dev->address = address;
            a->ip_dev->netmask = netmask;
            break;
        }else{
            if(a->next == nullptr){
                printf("Configure interface not found %s\n", interface);
                return;
            }
        }
    }


    ip_route_entry *ire = (ip_route_entry *) calloc(1, sizeof(ip_route_entry));
    ire->type = host;
    ire->device = a;

    int len = 0; // サブネットマスクとプレフィックス長の変換
    for (; len < 32; ++len) {
        if(!(netmask >> (31 - len) & 0b01)){
            break;
        }
    }

    binary_trie_add(ip_fib, address & netmask, len, ire);

    printf("Set host route %s/%d via %s\n", inet_htoa(address & netmask), len, interface);

}

void configure_ip_napt(const char* inside_interface, const char* outside_interface, uint32_t address){

    net_device *a;
    for (a = net_dev; a; a = a->next) {
        if (strcmp(a->ifname, inside_interface) == 0) {
            a->ip_dev->napt_inside_dev = (napt_inside_device *) calloc(1, sizeof(napt_inside_device));
            a->ip_dev->napt_inside_dev->entries = (napt_entries*) calloc(1, sizeof(napt_entries));;
        }else if(strcmp(a->ifname, outside_interface) == 0){
            a->ip_dev->napt_outside_dev = (napt_outside_device *) calloc(1, sizeof(napt_outside_device));
            a->ip_dev->napt_outside_dev->entries = (napt_entries*) calloc(1, sizeof(napt_entries));
        }else{
            if(a->next == nullptr){
                //printf("Configure interface not found \n");
                //return;
            }
        }
    }

}

void configure(){

    configure_ip("router-to-host0", IP_ADDRESS_FROM_HOST(192, 168, 111, 1), IP_ADDRESS_FROM_HOST(255, 255, 255, 0));
    configure_ip("router-to-host1", IP_ADDRESS_FROM_HOST(192, 168, 222, 1), IP_ADDRESS_FROM_HOST(255, 255, 255, 0));

    configure_ip_napt("router-to-host1", "router-to-host0", IP_ADDRESS_FROM_HOST(192, 168, 111, 1));


    configure_net_route(IP_ADDRESS_FROM_HOST(192, 168, 55, 0), 24, IP_ADDRESS_FROM_HOST(192, 168, 222, 2));

}