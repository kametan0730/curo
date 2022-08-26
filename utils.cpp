#include "utils.h"

#include <iostream>

inline uint16_t swap_byte_order_16(uint16_t v){
    return (v & 0x00ff) << 8 |
    (v & 0xff00) >> 8;
}

inline uint32_t swap_byte_order_32(uint32_t v){
    return (v & 0x000000ff) << 24 |
    (v & 0x0000ff00) << 8 |
    (v & 0x00ff0000) >> 8 |
    (v & 0xff000000) >> 24;
}

 uint16_t ntohs(uint16_t v){
    return swap_byte_order_16(v);
}

 uint16_t htons(uint16_t v){
    return swap_byte_order_16(v);
}

 uint32_t ntohl(uint32_t v){
    return swap_byte_order_32(v);
}

 uint32_t htonl(uint32_t v){
    return swap_byte_order_32(v);
}

#define INET_XTOA_STRING_POOL_SIZE 4

uint8_t inet_xtoa_string_pool_index = 0;
char inet_xtoa_string_pool[INET_XTOA_STRING_POOL_SIZE][16];

const char* inet_ntoa(uint32_t in){
    uint8_t a = in & 0x000000ff;
    uint8_t b = in >> 8 & 0x000000ff;
    uint8_t c = in >> 16 & 0x000000ff;
    uint8_t d = in >> 24 & 0x000000ff;
    inet_xtoa_string_pool_index = (inet_xtoa_string_pool_index + 1) % INET_XTOA_STRING_POOL_SIZE;
    sprintf(inet_xtoa_string_pool[inet_xtoa_string_pool_index], "%d.%d.%d.%d", a, b, c, d);
    return inet_xtoa_string_pool[inet_xtoa_string_pool_index];
}

const char* inet_htoa(uint32_t in){
    uint8_t a = in >> 24 & 0x000000ff;
    uint8_t b = in >> 16 & 0x000000ff;
    uint8_t c = in >> 8 & 0x000000ff;
    uint8_t d = in & 0x000000ff;
    inet_xtoa_string_pool_index = (inet_xtoa_string_pool_index + 1) % INET_XTOA_STRING_POOL_SIZE;
    sprintf(inet_xtoa_string_pool[inet_xtoa_string_pool_index], "%d.%d.%d.%d", a, b, c, d);
    return inet_xtoa_string_pool[inet_xtoa_string_pool_index];
}

#define MAC_ADDR_TOA_STRING_POOL_SIZE 4

uint8_t mac_addr_toa_string_pool_index = 0;
char mac_addr_toa_string_pool[MAC_ADDR_TOA_STRING_POOL_SIZE][20];

const char* mac_addr_toa(const uint8_t* addr){
    mac_addr_toa_string_pool_index = (mac_addr_toa_string_pool_index + 1) % MAC_ADDR_TOA_STRING_POOL_SIZE;
    sprintf(mac_addr_toa_string_pool[mac_addr_toa_string_pool_index], "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return mac_addr_toa_string_pool[mac_addr_toa_string_pool_index];
}

bool in_subnet(uint32_t subnet_prefix, uint8_t subnet_prefix_len, uint32_t target_address){
    subnet_prefix >>= 32 - subnet_prefix_len;
    subnet_prefix <<= 32 - subnet_prefix_len;
    target_address >>= 32 - subnet_prefix_len;
    target_address <<= 32 - subnet_prefix_len;
    return (target_address == subnet_prefix);
}

bool in_subnet_with_mask(uint32_t subnet_prefix, uint32_t subnet_mask, uint32_t target_address){
    return ((target_address | subnet_mask) == (subnet_prefix | subnet_mask));
}

