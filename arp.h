#ifndef CURO_ARP_H
#define CURO_ARP_H

#include <iostream>

#define GOLDEN_RATIO_32 0x61C88647
#define GOLDEN_RATIO_64 0x61C8864680B583EBull

#define ARP_HTYPE_ETHERNET 0x0001

#define ARP_OPERATION_CODE_REQUEST  0x0001
#define ARP_OPERATION_CODE_REPLY    0x0002

#define ARP_ETHERNET_PACKET_LEN 46

struct arp_ip_to_ethernet{
  uint16_t htype; // ハードウェアタイプ
  uint16_t ptype; // プロトコルタイプ
  uint8_t hlen; //ハードウェアアドレス帳
  uint8_t plen; // プロトコルアドレス帳
  uint16_t op; // オペレーションコード
  uint8_t sha[6]; // 送信者のハードウェアアドレス
  uint32_t spa; // 送信者のプロトコルアドレス
  uint8_t tha[6]; // ターゲットのハードウェアアドレス
  uint32_t tpa; // ターゲットのプロトコルアドレス
} __attribute__((packed));


#define ARP_TABLE_SIZE 1111

struct net_device;

struct arp_table_entry{
  uint8_t mac_addr[6];
  uint32_t ip_addr;
  net_device *dev;
  arp_table_entry *next;
};

void add_arp_table_entry(net_device *dev, uint8_t *mac_addr, uint32_t ip_addr);

arp_table_entry *search_arp_table_entry(uint32_t ip_addr);

void dump_arp_table_entry();

void send_arp_request(net_device *dev, uint32_t ip_addr);

void arp_input(net_device *input_dev, uint8_t *buffer, ssize_t len);

#endif //CURO_ARP_H
