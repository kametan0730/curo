#ifndef CURO_UTILS_H
#define CURO_UTILS_H

#include <cstdint>
#include <cstdio>

uint16_t ntohs(uint16_t v);
uint16_t htons(uint16_t v);

uint32_t ntohl(uint32_t v);
uint32_t htonl(uint32_t v);

const char *ip_ntoa(uint32_t in);
const char *ip_htoa(uint32_t in);
const char *mac_addr_toa(const uint8_t *addr);

uint16_t checksum_16(uint16_t *buffer, size_t count, uint16_t start = 0);

#endif //CURO_UTILS_H
