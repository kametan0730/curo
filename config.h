#ifndef CURO_CONFIG_H
#define CURO_CONFIG_H


#include <cstdint>
/*
 * 各プロトコルについてデバッグレベルを設定できます
 *
 * 0 No debug
 * 1 Print debug message
 */

#define DEBUG_ETHERNET  1
#define DEBUG_IP        1
#define DEBUG_ARP       1
#define DEBUG_ICMP      1
#define DEBUG_NAT       1


#define MYBUF_NON_COPY_MODE_ENABLE

#define ENABLE_NAPT

/*
#define DEBUG_ETHERNET  0
#define DEBUG_IP        0
#define DEBUG_ARP       0
#define DEBUG_ICMP      0
*/

#if DEBUG_ETHERNET > 0
#define LOG_ETHERNET(...) printf(__VA_ARGS__)
#else
#define LOG_ETHERNET(...)
#endif

#if DEBUG_IP > 0
#define LOG_IP(...) printf("[IP] ");printf(__VA_ARGS__);
#else
#define LOG_IP(...)
#endif

struct net_device;

net_device* get_net_device_by_name(const char* interface);

void configure_net_route(uint32_t prefix, uint32_t prefix_len, uint32_t next_hop);

void configure_ip(const char* interface, uint32_t address, uint32_t netmask);
void configure_ip_napt(const char* inside_interface, const char* outside_interface);


#endif //CURO_CONFIG_H
