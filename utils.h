#ifndef RAW_SOCKET_UTILS_H
#define RAW_SOCKET_UTILS_H

#include <cstdint>

uint16_t ntohs(uint16_t v);
uint16_t htons(uint16_t v);

uint32_t ntohl(uint32_t v);
uint32_t htonl(uint32_t v);

const char* inet_ntoa(uint32_t in);
const char* inet_htoa(uint32_t in);

const char* mac_addr_toa(uint8_t * addr);

#endif //RAW_SOCKET_UTILS_H
