#include "arp.h"

#include <cstring>
#include "config.h"
#include "ethernet.h"
#include "ip.h"
#include "log.h"
#include "my_buf.h"
#include "net.h"
#include "utils.h"

/**
 * ARPテーブル
 * グローバル変数にテーブルを保持
 */
arp_table_entry arp_table[ARP_TABLE_SIZE];

/**
 * ARPテーブルにエントリの追加と更新
 * @param dev
 * @param mac_addr
 * @param ip_addr
 */
void add_arp_table_entry(net_device *dev,
                         uint8_t *mac_addr,
                         uint32_t ip_addr){
    // 候補の場所は、HashテーブルのIPアドレスのハッシュがindexのもの
    const uint32_t index = ip_addr % ARP_TABLE_SIZE;
    arp_table_entry *candidate = &arp_table[index];

    // テーブルに入れられるか確認
    if(candidate->ip_addr == 0 or candidate->ip_addr == ip_addr){ // 初めの候補の場所に入れられるとき
        // エントリをセット
        memcpy(candidate->mac_addr, mac_addr, 6);
        candidate->ip_addr = ip_addr;
        candidate->dev = dev;
        return;
    }

    // 入れられなかった場合は、その候補にあるエントリに連結する
    while(candidate->next != nullptr){ // 連結リストの末尾までたどる
        candidate = candidate->next;
        // 途中で同じIPアドレスのエントリがあったら、そのエントリを更新する
        if(candidate->ip_addr == ip_addr){
            memcpy(candidate->mac_addr, mac_addr, 6);
            candidate->ip_addr = ip_addr;
            candidate->dev = dev;
            return;
        }
    }

    // 連結リストの末尾に新しくエントリを作成
    candidate->next = (arp_table_entry *) calloc(1, sizeof(arp_table_entry));
    memcpy(candidate->next->mac_addr, mac_addr, 6);
    candidate->next->ip_addr = ip_addr;
    candidate->next->dev = dev;
}

/**
 * ARPテーブルの検索
 * @param ip_addr
 * @return
 */
arp_table_entry *search_arp_table_entry(uint32_t ip_addr){
    // 初めの候補の場所は、HashテーブルのIPアドレスのハッシュがindexのもの
    arp_table_entry *candidate =
            &arp_table[ip_addr % ARP_TABLE_SIZE];

    if(candidate->ip_addr == ip_addr){ // 候補のエントリが検索しているIPアドレスの物だったら
        return candidate;
    }else if(candidate->ip_addr == 0){ // 候補のエントリが登録されていなかったら
        return nullptr;
    }

    // 候補のエントリが検索しているIPアドレスの物でなかった場合、そのエントリの連結リストを調べる
    while(candidate->next != nullptr){
        candidate = candidate->next;
        if(candidate->ip_addr == ip_addr){ // 連結リストの中に検索しているIPアドレスの物があったら
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
        if(arp_table[i].ip_addr == 0){
            continue;
        }
        // エントリの連結リストを順に出力する
        for(arp_table_entry *entry = &arp_table[i]; entry; entry = entry->next){
            printf("| %15s | %14s | %17s |  %04d |\n",
                   ip_htoa(entry->ip_addr),
                   mac_addr_toa(entry->mac_addr),
                   entry->dev->ifname, i);
        }
    }
    printf("|-----------------|-------------------|-------------------|-------|\n");
}

/**
 * ARPリクエストの送信
 * @param dev
 * @param search_ip
 */
void send_arp_request(net_device *dev, uint32_t ip_addr){
    LOG_ARP("Sending arp request via %s for %s\n", dev->ifname, ip_htoa(ip_addr));

    auto *arp_my_buf = my_buf::create(ARP_ETHERNET_PACKET_LEN);
    auto *arp_msg = reinterpret_cast<arp_ip_to_ethernet *>(arp_my_buf->buffer);
    arp_msg->htype = htons(ARP_HTYPE_ETHERNET); // ハードウェアタイプの設定
    arp_msg->ptype = htons(ETHER_TYPE_IP); // プロトコルタイプの設定
    arp_msg->hlen = ETHERNET_ADDRESS_LEN; // ハードウェアアドレス帳の設定
    arp_msg->plen = IP_ADDRESS_LEN; // プロトコルアドレス長の設定
    arp_msg->op = htons(ARP_OPERATION_CODE_REQUEST); // オペレーションコードの設定
    memcpy(arp_msg->sha, dev->mac_addr, 6); // 送信者ハードウェアアドレスにデバイスのMACアドレスを設定
    arp_msg->spa = htonl(dev->ip_dev->address); // 送信者プロトコルアドレスにデバイスのIPアドレスを設定
    arp_msg->tpa = htonl(ip_addr); // ターゲットプロトコルアドレスに、探すホストのIPアドレスを設定

    // イーサネットで送信する
    ethernet_encapsulate_output(dev, ETHERNET_ADDRESS_BROADCAST, arp_my_buf, ETHER_TYPE_ARP);
}

// 宣言のみ
void arp_request_arrives(net_device *dev, arp_ip_to_ethernet *request);
void arp_reply_arrives(net_device *dev, arp_ip_to_ethernet *reply);

/**
 * ARPパケットの受信処理
 * @param input_dev
 * @param buffer
 * @param len
 */
void arp_input(net_device *input_dev, uint8_t *buffer, ssize_t len){
    // ARPパケットの想定より短かったら
    if(len < sizeof(arp_ip_to_ethernet)){
        LOG_ARP("Too short arp packet\n");
        return;
    }

    auto *arp_msg = reinterpret_cast<arp_ip_to_ethernet *>(buffer);
    uint16_t op = ntohs(arp_msg->op);

    switch(ntohs(arp_msg->ptype)){
        case ETHER_TYPE_IP:

            if(arp_msg->hlen != ETHERNET_ADDRESS_LEN){
                LOG_ARP("Illegal hardware address length\n");
                return;
            }

            if(arp_msg->plen != IP_ADDRESS_LEN){
                LOG_ARP("Illegal protocol address length\n");
                return;
            }

            // オペレーションコードによって分岐
            if(op == ARP_OPERATION_CODE_REQUEST){
                // ARPリクエストの受信
                arp_request_arrives(input_dev, arp_msg);
                return;
            }else if(op == ARP_OPERATION_CODE_REPLY){
                // ARPリプライの受信
                arp_reply_arrives(input_dev, arp_msg);
                return;
            }
            break;
    }
}

/**
 * ARPリクエストパケットの受信処理
 * @param dev
 * @param request
 */
void arp_request_arrives(net_device *dev, arp_ip_to_ethernet *request){
    if(dev->ip_dev != nullptr and dev->ip_dev->address != IP_ADDRESS(0, 0, 0, 0)){ // IPアドレスが設定されているデバイスからの受信だったら
        if(dev->ip_dev->address == ntohl(request->tpa)){ // 要求されているアドレスが自分の物だったら
            LOG_ARP("Sending arp reply via %s\n", ip_ntoa(request->tpa));

            auto *reply_my_buf = my_buf::create(ARP_ETHERNET_PACKET_LEN);

            auto reply_msg = reinterpret_cast<arp_ip_to_ethernet *>(reply_my_buf->buffer);
            reply_msg->htype = htons(ARP_HTYPE_ETHERNET);
            reply_msg->ptype = htons(ETHER_TYPE_IP);
            reply_msg->hlen = ETHERNET_ADDRESS_LEN; // IPアドレスの長さ
            reply_msg->plen = IP_ADDRESS_LEN; // MACアドレスの長さ
            reply_msg->op = htons(ARP_OPERATION_CODE_REPLY);

            // 返答の情報を書き込む
            memcpy(reply_msg->sha, dev->mac_addr, ETHERNET_ADDRESS_LEN);
            reply_msg->spa = htonl(dev->ip_dev->address);
            memcpy(reply_msg->tha, request->sha, ETHERNET_ADDRESS_LEN);
            reply_msg->tpa = request->spa;

            ethernet_encapsulate_output(dev, request->sha, reply_my_buf, ETHER_TYPE_ARP); // イーサネットで送信
            add_arp_table_entry(dev, request->sha, ntohl(request->spa)); // ARPリクエストからもエントリを生成
            return;
        }
    }
}

/**
 * ARPリプライパケットの受信処理
 * @param dev
 * @param reply
 */
void arp_reply_arrives(net_device *dev,
                       arp_ip_to_ethernet *reply){
    if(dev->ip_dev != nullptr and dev->ip_dev->address != IP_ADDRESS(0, 0, 0, 0)){ // IPアドレスが設定されているデバイスからの受信だったら
        LOG_ARP("Added arp table entry by arp reply (%s => %s)\n", ip_ntoa(reply->spa), mac_addr_toa(reply->sha));
        add_arp_table_entry(dev, reply->sha, ntohl(reply->spa)); // ARPテーブルエントリの追加
    }
}
