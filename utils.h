#ifndef CURO_UTILS_H
#define CURO_UTILS_H

#include <cstdint>

uint16_t swap_byte_order_16(uint16_t v);
uint32_t swap_byte_order_32(uint32_t v);

#define ntohs swap_byte_order_16
#define htons swap_byte_order_16
#define ntohl swap_byte_order_32
#define htonl swap_byte_order_32

const char *inet_ntoa(uint32_t in);
const char *inet_htoa(uint32_t in);
const char *mac_addr_toa(const uint8_t *addr);

bool in_subnet(uint32_t subnet_prefix, uint8_t subnet_prefix_len, uint32_t target_address);
bool in_subnet_with_mask(uint32_t subnet_prefix, uint32_t subnet_mask, uint32_t target_address);

#endif //CURO_UTILS_H
