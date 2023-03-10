#include "config.h"

#include "binary_trie.h"
#include "ip.h"
#include "log.h"
#include "nat.h"
#include "net.h"
#include "utils.h"

/**
 * 経路を設定
 * @param prefix 宛先ネットワークのプレフィックス
 * @param prefix_len プレフィックス長
 * @param next_hop 転送先
 */
void configure_ip_net_route(uint32_t prefix, uint32_t prefix_len,
                            uint32_t next_hop) {
    // プレフィックス長とネットマスクの変換
    uint32_t mask = 0xffffffff;
    mask <<= (32 - prefix_len);

    // 経路エントリの生成
    ip_route_entry *entry;
    entry = (ip_route_entry *)(calloc(1, sizeof(ip_route_entry)));
    entry->type = network;
    entry->next_hop = next_hop;

    // 経路の登録
    binary_trie_add(ip_fib, prefix & mask, prefix_len, entry);
}

/**
 * デバイスにIPアドレスを設定
 * @param dev
 * @param address
 * @param netmask
 */
void configure_ip_address(net_device *dev, uint32_t address, uint32_t netmask) {
    if (dev == nullptr) {
        LOG_ERROR("Configure net dev not found\n");
        exit(EXIT_FAILURE);
    }

    // IPアドレスの登録
    dev->ip_dev = (ip_device *)calloc(1, sizeof(ip_device));
    dev->ip_dev->address = address;
    dev->ip_dev->netmask = netmask;
    dev->ip_dev->broadcast = (address & netmask) | (~netmask);

    printf("Set ip address to %s\n", dev->name);

    // IPアドレスを設定すると同時に直接接続ルートを設定する
    ip_route_entry *entry;
    entry = (ip_route_entry *)calloc(1, sizeof(ip_route_entry));
    entry->type = connected;
    entry->dev = dev;

    int len = 0; // サブネットマスクとプレフィックス長の変換
    for (; len < 32; ++len) {
        if (!(netmask >> (31 - len) & 0b01)) {
            break;
        }
    }

    // 直接接続ネットワークの経路を設定
    binary_trie_add(ip_fib, address & netmask, len, entry);

    printf("Set directly connected route %s/%d device %s\n",
           ip_htoa(address & netmask), len, dev->name);
}

/**
 * デバイスにNATを設定
 * @param inside NATの内側のデバイス
 * @param outside NATの外側のデバイス
 */
void configure_ip_nat(net_device *inside, net_device *outside) {
#ifdef ENABLE_NAT
    if (inside == nullptr or outside == nullptr or inside->ip_dev == nullptr or
        outside->ip_dev == nullptr) {
        LOG_ERROR("Failed to configure NAT %s => %s\n", inside->name,
                  outside->name);
        exit(EXIT_FAILURE); // プログラムを終了
    }

    inside->ip_dev->nat_dev = (nat_device *)calloc(1, sizeof(nat_device));
    inside->ip_dev->nat_dev->entries =
        (nat_entries *)calloc(1, sizeof(nat_entries));
    inside->ip_dev->nat_dev->outside_addr = outside->ip_dev->address;
#else
    LOG_ERROR("NAT has not been enabled for this build\n");
    exit(EXIT_FAILURE);
#endif
}