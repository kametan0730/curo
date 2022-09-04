#include "arp.h"

#include <cstring>
#include "config.h"
#include "ethernet.h"
#include "ip.h"
#include "log.h"
#include "my_buf.h"
#include "net.h"
#include "utils.h"

arp_table_entry arp_table[ARP_TABLE_SIZE]; // グローバル変数にテーブルを保持

/**
 * ARPテーブルにエントリの追加と更新
 * @param device
 * @param mac_address
 * @param ip_address
 */
void add_arp_table_entry(net_device *device, uint8_t *mac_address, uint32_t ip_address){
    // 初めの候補の場所は、HashテーブルのIPアドレスのハッシュがindexのもの
    arp_table_entry *candidate = &arp_table[ip_address % ARP_TABLE_SIZE];

    // テーブルに入れられるか確認
    if(candidate->ip_address == 0 or candidate->ip_address == ip_address){ // 初めの候補の場所に入れられるとき
        // エントリをセット
        memcpy(candidate->mac_address, mac_address, 6);
        candidate->ip_address = ip_address;
        candidate->device = device;
        return;
    }

    // 入れられなかった場合は、その候補にあるエントリに連結する
    while(candidate->next != nullptr){ // 連結リストの末尾までたどる
        candidate = candidate->next;
        if(candidate->ip_address == ip_address){ // 途中で同じIPアドレスのエントリがあったら、そのエントリを更新する
            memcpy(candidate->mac_address, mac_address, 6);
            candidate->ip_address = ip_address;
            candidate->device = device;
            return;
        }
    }

    // 連結リストの末尾に新しくエントリを作成
    candidate->next = (arp_table_entry *) calloc(1, sizeof(arp_table_entry));
    memcpy(candidate->next->mac_address, mac_address, 6);
    candidate->next->ip_address = ip_address;
    candidate->next->device = device;
}

/**
 * ARPテーブルの検索
 * @param ip_address
 * @return
 */
arp_table_entry *search_arp_table_entry(uint32_t ip_address){
    // 初めの候補の場所は、HashテーブルのIPアドレスのハッシュがindexのもの
    arp_table_entry *candidate = &arp_table[ip_address % ARP_TABLE_SIZE];

    if(candidate->ip_address == ip_address){ // 候補のエントリが検索しているIPアドレスの物だったら
        return candidate;
    }else if(candidate->ip_address == 0){ // 候補のエントリが登録されていなかったら
        return nullptr;
    }

    // 候補のエントリが検索しているIPアドレスの物でなかった場合、そのエントリの連結リストを調べる
    while(candidate->next != nullptr){
        candidate = candidate->next;
        if(candidate->ip_address == ip_address){ // 連結リストの中に検索しているIPアドレスの物があったら
            return candidate;
        }
    }

    // 連結リストの中に見つからなかったら
    return nullptr;
}

/**
 * ARPテーブルの出力
 */
void dump_arp_table_entry(){
    printf("|---IP ADDRESS----|----MAC ADDRESS----|------DEVICE-------|-INDEX-|\n");
    for(int i = 0; i < ARP_TABLE_SIZE; ++i){
        if(arp_table[i].ip_address == 0){
            continue;
        }

        // エントリの連結リストを順に出力する
        for(arp_table_entry *entry = &arp_table[i]; entry; entry = entry->next){
            printf("| %15s | %14s | %17s |  %04d |\n",
                   ip_htoa(entry->ip_address),
                   mac_addr_toa(entry->mac_address),
                   entry->device->ifname, i);
        }
    }
    printf("|-----------------|-------------------|-------------------|-------|\n");
}

/**
 * ARPリクエストの送信
 * @param device
 * @param search_ip
 */
void send_arp_request(net_device *device, uint32_t ip_address){
    LOG_ARP("Sending arp request via %s for %s\n", device->ifname, ip_htoa(ip_address));

    auto *arp_my_buf = my_buf::create(ARP_ETHERNET_PACKET_LEN);
    auto *arp_buf = reinterpret_cast<arp_ip_to_ethernet *>(arp_my_buf->buffer);
    arp_buf->htype = htons(ARP_HTYPE_ETHERNET);
    arp_buf->ptype = htons(ETHERNET_TYPE_IP);
    arp_buf->hlen = ETHERNET_ADDRESS_LEN;
    arp_buf->plen = IP_ADDRESS_LEN;
    arp_buf->op = htons(ARP_OPERATION_CODE_REQUEST);
    memcpy(arp_buf->sha, device->mac_address, 6);
    arp_buf->spa = htonl(device->ip_dev->address);
    arp_buf->tpa = htonl(ip_address);

    ethernet_encapsulate_output(device, ETHERNET_ADDRESS_BROADCAST, arp_my_buf, ETHERNET_TYPE_ARP);
}

void arp_request_arrives(net_device *dev, arp_ip_to_ethernet *packet); // 宣言のみ
void arp_reply_arrives(net_device *dev, arp_ip_to_ethernet *packet); // 宣言のみ

/**
 * ARPパケットの受信処理
 * @param input_dev
 * @param buffer
 * @param len
 */
void arp_input(net_device *input_dev, uint8_t *buffer, ssize_t len){
    auto *packet = reinterpret_cast<arp_ip_to_ethernet *>(buffer);
    uint16_t op = ntohs(packet->op);

    switch(ntohs(packet->ptype)){
        case ETHERNET_TYPE_IP:

            if(len < sizeof(arp_ip_to_ethernet)){
                LOG_ARP("Illegal arp packet length\n");
                return;
            }

            if(packet->hlen != ETHERNET_ADDRESS_LEN){
                LOG_ARP("Illegal hardware address length\n");
                return;
            }

            if(packet->plen != IP_ADDRESS_LEN){
                LOG_ARP("Illegal protocol address length\n");
                return;
            }

            // オペレーションコードによって分岐
            if(op == ARP_OPERATION_CODE_REQUEST){
                arp_request_arrives(input_dev, packet);
            }else if(op == ARP_OPERATION_CODE_REPLY){
                arp_reply_arrives(input_dev, packet);
            }

            break;
    }
}

/**
 * ARPリクエストパケットの受信処理
 * @param dev
 * @param packet
 */
void arp_request_arrives(net_device *dev, arp_ip_to_ethernet *packet){
    if(dev->ip_dev != nullptr and dev->ip_dev->address != IP_ADDRESS(0, 0, 0, 0)){ // IPアドレスが設定されているデバイスからの受信だったら
        if(dev->ip_dev->address == ntohl(packet->tpa)){ // 要求されているアドレスが自分の物だったら
            LOG_ARP("Sending arp reply via %s\n", ip_ntoa(packet->tpa));

            auto *reply_my_buf = my_buf::create(ARP_ETHERNET_PACKET_LEN);

            auto reply_buf = reinterpret_cast<arp_ip_to_ethernet *>(reply_my_buf->buffer);
            reply_buf->htype = htons(ARP_HTYPE_ETHERNET);
            reply_buf->ptype = htons(ETHERNET_TYPE_IP);
            reply_buf->hlen = ETHERNET_ADDRESS_LEN; // IPアドレスの長さ
            reply_buf->plen = IP_ADDRESS_LEN; // MACアドレスの長さ
            reply_buf->op = htons(ARP_OPERATION_CODE_REPLY);

            // 返答の情報を書き込む
            memcpy(reply_buf->sha, dev->mac_address, ETHERNET_ADDRESS_LEN);
            reply_buf->spa = htonl(dev->ip_dev->address);
            memcpy(reply_buf->tha, packet->sha, ETHERNET_ADDRESS_LEN);
            reply_buf->tpa = packet->spa;

            ethernet_encapsulate_output(dev, packet->sha, reply_my_buf, ETHERNET_TYPE_ARP); // イーサネットで送信
            add_arp_table_entry(dev, packet->sha, ntohl(packet->spa)); // ARPリクエストからもエントリを生成
            return;
        }
    }
}

/**
 * ARPリプライパケットの受信処理
 * @param dev
 * @param packet
 */
void arp_reply_arrives(net_device *dev, arp_ip_to_ethernet *packet){
    if(dev->ip_dev != nullptr and dev->ip_dev->address != IP_ADDRESS(0, 0, 0, 0)){ // IPアドレスが設定されているデバイスからの受信だったら
        LOG_ARP("Added arp table entry by arp reply (%s => %s)\n", ip_ntoa(packet->spa), mac_addr_toa(packet->sha));
        add_arp_table_entry(dev, packet->sha, ntohl(packet->spa)); // ARPテーブルエントリの追加
    }
}