#include "utils.h"

#include <iostream>

uint16_t swap_byte_order_16(uint16_t v){ // 16bitのバイトオーダーの入れ替え
    return (v & 0x00ff) << 8 |
           (v & 0xff00) >> 8;
}

uint32_t swap_byte_order_32(uint32_t v){ // 32ビットのバイトオーダーの入れ替え
    return (v & 0x000000ff) << 24 |
           (v & 0x0000ff00) << 8 |
           (v & 0x00ff0000) >> 8 |
           (v & 0xff000000) >> 24;
}

uint8_t inet_ntoa_string_pool_index = 0;
char inet_xtoa_string_pool[4][16]; // 16バイト(xxx.xxx.xxx.xxxの文字数+1)の領域を4つ確保

/**
 * IPアドレスから文字列に変換
 * @param in
 * @return
 */
const char *inet_ntoa(uint32_t in){ // ネットワークバイトオーダーのIPアドレスから文字列に変換
    uint8_t a = in & 0x000000ff;
    uint8_t b = in >> 8 & 0x000000ff;
    uint8_t c = in >> 16 & 0x000000ff;
    uint8_t d = in >> 24 & 0x000000ff;
    inet_ntoa_string_pool_index++;
    inet_ntoa_string_pool_index %= 4;
    sprintf(inet_xtoa_string_pool[inet_ntoa_string_pool_index], "%d.%d.%d.%d", a, b, c, d); //
    return inet_xtoa_string_pool[inet_ntoa_string_pool_index];
}

const char *inet_htoa(uint32_t in){ // ホストバイトオーダーのIPアドレスから文字列に変換
    return inet_ntoa(htonl(in));
}

uint8_t mac_addr_toa_string_pool_index = 0;
char mac_addr_toa_string_pool[4][18]; // 18バイト(xxx.xxx.xxx.xxxの文字数+1)の領域を4つ確保

/**
 * MACアドレスから文字列に変換
 * @param addr
 * @return
 */
const char *mac_addr_toa(const uint8_t *addr){
    mac_addr_toa_string_pool_index++;
    mac_addr_toa_string_pool_index %= 4;
    sprintf(mac_addr_toa_string_pool[mac_addr_toa_string_pool_index], "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return mac_addr_toa_string_pool[mac_addr_toa_string_pool_index];
}

/**
 * サブネットにIPアドレスが含まれているか比較
 * @param subnet_prefix
 * @param subnet_prefix_len
 * @param target_address
 * @return
 */
bool in_subnet(uint32_t subnet_prefix, uint8_t subnet_prefix_len, uint32_t target_address){
    subnet_prefix >>= 32 - subnet_prefix_len;
    subnet_prefix <<= 32 - subnet_prefix_len;
    target_address >>= 32 - subnet_prefix_len;
    target_address <<= 32 - subnet_prefix_len;
    return (target_address == subnet_prefix);
}

/**
 * サブネットにIPアドレスが含まれているか比較
 * @param subnet_prefix
 * @param subnet_mask
 * @param target_address
 * @return
 */
bool in_subnet_with_mask(uint32_t subnet_prefix, uint32_t subnet_mask, uint32_t target_address){
    return ((target_address | subnet_mask) == (subnet_prefix | subnet_mask));
}

