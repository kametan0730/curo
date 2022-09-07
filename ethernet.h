#ifndef CURO_ETHERNET_H
#define CURO_ETHERNET_H

#include <cstdio>
#include "net.h"

#define ETHER_TYPE_IP 0x0800
#define ETHER_TYPE_ARP 0x0806
#define ETHER_TYPE_IPV6 0x86dd

#define ETHERNET_HEADER_SIZE 14
#define ETHERNET_ADDRESS_LEN 6

const uint8_t ETHERNET_ADDRESS_BROADCAST[] =
        {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

struct ethernet_header{
    uint8_t dest_addr[6]; // 宛先アドレス
    uint8_t src_addr[6]; // 送信元アドレス
    uint16_t type; // イーサタイプ
} __attribute__((packed));

void ethernet_input(net_device *dev,
                    uint8_t *buffer, ssize_t len);

struct my_buf;

void ethernet_encapsulate_output(
        net_device *dev, const uint8_t *dest_addr,
        my_buf *payload_mybuf, uint16_t ether_type);

#endif //CURO_ETHERNET_H
