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
#define DEBUG_IPV6      1

// #define ENABLE_MYBUF_NON_COPY_MODE // パケット転送時にバッファのコピーを削減するか
#define ENABLE_NAT        // NATを有効にするか
#define ENABLE_ICMP_ERROR // ICMPエラーを送信するか
#define ENABLE_COMMAND    // 対話的なコマンドを有効化するか
#define ENABLE_IPV6       // IPv6を有効にするか
/*
#define DEBUG_ETHERNET  0
#define DEBUG_IP        0
#define DEBUG_ARP       0
#define DEBUG_ICMP      0
*/

struct net_device;

void configure_ip_net_route(uint32_t prefix, uint32_t prefix_len,
                            uint32_t next_hop);

void configure_ip_address(net_device *dev, uint32_t address, uint32_t netmask);
void configure_ip_nat(net_device *inside, net_device *outside);

struct ipv6_addr;

void configure_ipv6_address(net_device *dev, ipv6_addr address, uint32_t prefix_len);

#endif // CURO_CONFIG_H
