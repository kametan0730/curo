#ifndef RAW_SOCKET_CONFIG_H
#define RAW_SOCKET_CONFIG_H

/*
 * 各プロトコルについてデバッグレベルを設定できます
 *
 * 0 No debug
 * 1 Print debug message
 * 2 Print packet bytes
 */

#define DEBUG_ETHERNET  1
#define DEBUG_IP        1
#define DEBUG_ARP       1
#define DEBUG_ICMP      1

/*
#define DEBUG_ETHERNET  0
#define DEBUG_IP        0
#define DEBUG_ARP       0
#define DEBUG_ICMP      0
*/

#define LINK_TO_HOST0 "router-to-host0"
#define LINK_TO_HOST1 "router-to-br0"

#define ENABLE_INTERFACES {LINK_TO_HOST0, LINK_TO_HOST1}

void configure();

#endif //RAW_SOCKET_CONFIG_H
