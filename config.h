#ifndef CURO_CONFIG_H
#define CURO_CONFIG_H

#include <cstdint>
#include <cstdio>

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


#define ENABLE_MYBUF_NON_COPY_MODE // パケット転送時にバッファのコピーを削減するか

#define ENABLE_NAPT // NAPTを有効にするか

#define ENABLE_ICMP_ERROR // ICMPエラーを送信するか


#define ENABLE_COMMAND // 対話的なコマンドを有効化するか
/*
#define DEBUG_ETHERNET  0
#define DEBUG_IP        0
#define DEBUG_ARP       0
#define DEBUG_ICMP      0
*/

#if DEBUG_ETHERNET > 0
#define LOG_ETHERNET(...) printf("[ETHER] ");printf(__VA_ARGS__)
#else
#define LOG_ETHERNET(...)
#endif

#if DEBUG_IP > 0
#define LOG_IP(...) printf("[IP] ");printf(__VA_ARGS__);
#else
#define LOG_IP(...)
#endif

#if DEBUG_ARP > 0
#define LOG_ARP(...) printf("[ARP] ");printf(__VA_ARGS__);
#else
#define LOG_ARP(...)
#endif

#if DEBUG_ICMP > 0
#define LOG_ICMP(...) printf("[ICMP] ");printf(__VA_ARGS__);
#else
#define LOG_ICMP(...)
#endif

#if DEBUG_NAT > 0
#define LOG_NAT(...) printf("[NAT] ");printf(__VA_ARGS__);
#else
#define LOG_NAT(...)
#endif

#define LOG_ERROR(...) printf("[ERROR %s:%d] ", __FILE__, __LINE__);printf(__VA_ARGS__);

struct net_device;

void configure_net_route(uint32_t prefix, uint32_t prefix_len, uint32_t next_hop);

void configure_ip(net_device *dev, uint32_t address, uint32_t netmask);
void configure_ip_napt(net_device *inside_interface, net_device *outside_interface);

#endif //CURO_CONFIG_H
