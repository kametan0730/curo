#ifndef CURO_UTILS_H
#define CURO_UTILS_H

#include <cstdint>

uint16_t ntohs(uint16_t v);
uint16_t htons(uint16_t v);

uint32_t ntohl(uint32_t v);
uint32_t htonl(uint32_t v);

const char* inet_ntoa(uint32_t in);
const char* inet_htoa(uint32_t in);

const char* mac_addr_toa(const uint8_t * addr);

bool in_subnet(uint32_t subnet_prefix, uint8_t subnet_prefix_len, uint32_t target_address);

#endif //CURO_UTILS_H
