#ifndef CURO_IPV6_H
#define CURO_IPV6_H

#include "config.h"
#include <iostream>
#include <queue>

#define IPV6_PROTOCOL_NUM_ICMP 0x3a
#define IPV6_PROTOCOL_NUM_NONXT 0x3b
#define IPV6_PROTOCOL_NUM_OPTS 0x3c

struct ipv6_addr {
    union{
        struct{
            uint64_t int1;
            uint64_t int2;
        } __attribute__((packed)) per_64;
    
        struct{
            uint32_t int1;
            uint32_t int2;
            uint32_t int3;
            uint32_t int4;
        } __attribute__((packed)) per_32;
    
        struct{
            uint16_t int1;
            uint16_t int2;
            uint16_t int3;
            uint16_t int4;
            uint16_t int5;
            uint16_t int6;
            uint16_t int7;
            uint16_t int8;
        } __attribute__((packed)) per_16;

        unsigned char chars[16];
    };

} __attribute__((packed));

#define IPV6_ADDRESS(A, B, C, D, E, F, G, H) ()

struct ipv6_device{
    ipv6_addr address; // IPv6アドレス
    uint32_t prefix_len; // プレフィックス長(0~128)
    uint8_t scope; // スコープ
    net_device* net_dev; // ネットワークデバイスへのポインタ
};

struct ipv6_header {
    uint32_t ver_tc_fl;
    uint16_t payload_len;
    uint8_t next_hdr;
    uint8_t hop_limit;
    ipv6_addr src_addr;
    ipv6_addr dest_addr;
} __attribute__((packed));

struct ipv6_pseudo_header{
    ipv6_addr src_addr;
    ipv6_addr dest_addr;
    uint32_t packet_length;
    uint16_t zero1;
    uint8_t zero2;
    uint8_t next_header;

};

char *ipv6toascii(ipv6_addr addr);

void ipv6_input(net_device * input_dev, uint8_t * buffer, ssize_t len);

struct my_buf;

void ipv6_encap_dev_output(net_device* output_dev, const uint8_t* dest_mac_addr, ipv6_addr dest_addr, my_buf* buffer, uint8_t next_hdr_num);

void ipv6_encap_output(ipv6_addr dest_addr, ipv6_addr src_addr, my_buf* buffer, uint8_t next_hdr_num);

#endif // CURO_IPV6_H
