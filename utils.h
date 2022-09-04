#ifndef CURO_UTILS_H
#define CURO_UTILS_H

#include <cstdint>
#include <cstdio>

uint16_t swap_byte_order_16(uint16_t v);
uint32_t swap_byte_order_32(uint32_t v);

#define ntohs swap_byte_order_16
#define htons swap_byte_order_16
#define ntohl swap_byte_order_32
#define htonl swap_byte_order_32

const char *ip_ntoa(uint32_t in);
const char *ip_htoa(uint32_t in);
const char *mac_addr_toa(const uint8_t *addr);

uint16_t checksum_16(uint16_t *buffer, size_t count, uint16_t start = 0);

#endif //CURO_UTILS_H
