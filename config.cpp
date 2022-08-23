#include <net/if.h>
#include "config.h"

#include "binary_trie.h"
#include "ip.h"
#include "napt.h"
#include "net.h"
#include "utils.h"

net_device* get_net_device_by_name(const char* interface){
    net_device* dev;
    for(dev = net_dev_list; dev; dev = dev->next){
        if(strcmp(dev->ifname, interface) == 0){
            return dev;
        }
    }
    return nullptr;
}


void configure_net_route(uint32_t prefix, uint32_t prefix_len, uint32_t next_hop){

    uint32_t mask = 0xffffffff;
    mask <<= (32 - prefix_len);

    ip_route_entry* ire = static_cast<ip_route_entry*>(calloc(1, sizeof(ip_route_entry)));
    ire->type = network;
    ire->next_hop = next_hop;

    binary_trie_add(ip_fib, prefix & mask, prefix_len, ire);

}


void configure_ip(const char* interface, uint32_t address, uint32_t netmask){

    net_device* dev;
    for(dev = net_dev_list; dev; dev = dev->next){
        if(strcmp(dev->ifname, interface) == 0){
            printf("Set ip address to %s\n", dev->ifname);
            dev->ip_dev = (ip_device*) calloc(1, sizeof(ip_device));
            dev->ip_dev->address = address;
            dev->ip_dev->netmask = netmask;
            break;
        }else{
            if(dev->next == nullptr){
                printf("Configure interface not found %s\n", interface);
                return;
            }
        }
    }

    // IPアドレスを設定すると同時に直接接続ルートを設定する
    ip_route_entry* ire = (ip_route_entry*) calloc(1, sizeof(ip_route_entry));
    ire->type = connected;
    ire->device = dev;

    int len = 0; // サブネットマスクとプレフィックス長の変換
    for(; len < 32; ++len){
        if(!(netmask >> (31 - len) & 0b01)){
            break;
        }
    }

    binary_trie_add(ip_fib, address & netmask, len, ire);

    printf("Set host route %s/%d via %s\n", inet_htoa(address & netmask), len, interface);

}

void configure_ip_napt(const char* inside_interface, const char* outside_interface){

#ifdef ENABLE_NAPT
    net_device* inside = get_net_device_by_name(inside_interface);
    net_device* outside = get_net_device_by_name(outside_interface);

    if(inside == nullptr or outside == nullptr){
        printf("Failed to configure NAPT %s => %s\n", inside_interface, outside_interface);
        return;
    }

    if(inside->ip_dev == nullptr or outside->ip_dev == nullptr){
        printf("Failed to configure NAPT %s => %s\n", inside_interface, outside_interface);
        return;
    }

    inside->ip_dev->napt_inside_dev = (napt_inside_device*) calloc(1, sizeof(napt_inside_device));
    inside->ip_dev->napt_inside_dev->entries = (napt_entries*) calloc(1, sizeof(napt_entries));
    inside->ip_dev->napt_inside_dev->outside_address = outside->ip_dev->address;

#else
    printf("NAPT has not been enabled for this build\n");
#endif

}