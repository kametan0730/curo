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
#define DEBUG_ICP       1
#define DEBUG_ICMP      1

#define ENABLE_INTERFACES {"router-to-host0", "router-to-host1"}


void configure();

#endif //RAW_SOCKET_CONFIG_H
