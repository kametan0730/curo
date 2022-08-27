#include "arp.h"

#include <cstring>
#include "config.h"
#include "ethernet.h"
#include "ip.h"
#include "my_buf.h"
#include "net.h"
#include "utils.h"

arp_table_entry arp_table[ARP_TABLE_SIZE]; // グローバル変数にテーブルを保持

void add_arp_table_entry(net_device* device, uint8_t* mac_address, uint32_t ip_address){
    if(ip_address == IP_ADDRESS(0, 0, 0, 0)){
        return;
    }

    arp_table_entry* candidate = &arp_table[ip_address % ARP_TABLE_SIZE];

    // テーブルに入れられるか確認
    if(candidate->ip_address == 0 or candidate->ip_address == ip_address){ // 想定のHash値に入れられるとき
        memcpy(candidate->mac_address, mac_address, 6);
        candidate->ip_address = ip_address;
        candidate->device = device;
        return;
    }

    // 入れられなかった場合は、arp_table_entryに連結する
    while(candidate->next != nullptr){
        candidate = candidate->next;
        if(candidate->ip_address == ip_address){
            memcpy(candidate->mac_address, mac_address, 6);
            candidate->ip_address = ip_address;
            candidate->device = device;
            return;
        }
    }

    arp_table_entry* creation = (arp_table_entry*) calloc(1, sizeof(arp_table_entry));
    memcpy(creation->mac_address, mac_address, 6);
    creation->ip_address = ip_address;
    creation->device = device;

    candidate->next = creation;
}


arp_table_entry* search_arp_table_entry(uint32_t ip_address){
    arp_table_entry* candidate = &arp_table[ip_address % ARP_TABLE_SIZE];

    if(candidate->ip_address == ip_address){
        return candidate;
    }else if(candidate->ip_address == 0){
        return nullptr;
    }

    while(candidate->next != nullptr){
        candidate = candidate->next;
        if(candidate->ip_address == ip_address){
            return candidate;
        }
    }

    return nullptr;
}


void dump_arp_table_entry(){

    printf("|-----IP ADDR-----|------MAC ADDR-----|-----INTERFACE-----|-INDEX|\n");

    for(int i = 0; i < ARP_TABLE_SIZE; ++i){
        if(arp_table[i].ip_address == 0){
            continue;
        }

        for(arp_table_entry* a = &arp_table[i]; a; a = a->next){
            printf("| %15s | %14s | %17s | %04d |\n",
                   inet_htoa(a->ip_address),
                   mac_addr_toa(a->mac_address),
                   a->device->ifname, i);
        }
    }

    printf("|-----------------|-------------------|-------------------|------|\n");
}

void send_arp_request(net_device* device, uint32_t search_ip){
    LOG_ARP("Sending arp request via %s for %s\n", device->ifname, inet_htoa(search_ip));

    auto* new_buf = my_buf::create(46);
    auto* arp = reinterpret_cast<arp_ip_to_ethernet*>(new_buf->buffer);
    arp->htype = htons(ARP_HTYPE_ETHERNET);
    arp->ptype = htons(ETHERNET_PROTOCOL_TYPE_IP);
    arp->hlen = 0x06;
    arp->plen = 0x04;
    arp->op = htons(ARP_OPERATION_CODE_REQUEST);
    memcpy(arp->sha, device->mac_address, 6);
    arp->spa = htonl(device->ip_dev->address);
    arp->tpa = htonl(search_ip);

    ethernet_encapsulate_output(device, ETHERNET_ADDRESS_BROADCAST, new_buf, ETHERNET_PROTOCOL_TYPE_ARP);
}

void arp_request_arrives(net_device* dev, arp_ip_to_ethernet* packet); // 宣言のみ
void arp_reply_arrives(net_device* src_dev, arp_ip_to_ethernet* packet); // 宣言のみ

void arp_input(net_device* src_dev, uint8_t* buffer, ssize_t len){

    auto* packet = reinterpret_cast<arp_ip_to_ethernet*>(buffer);
    uint16_t op = ntohs(packet->op);

    switch(ntohs(packet->ptype)){
        case ETHERNET_PROTOCOL_TYPE_IP:{

            if(sizeof(arp_ip_to_ethernet) > len){
                LOG_ARP("Illegal arp packet length\n");
                return;
            }

            if(packet->hlen != 6){
                LOG_ARP("Illegal hardware address length\n");
                return;
            }

            if(packet->plen != 4){
                LOG_ARP("Illegal protocol address length\n");
                return;
            }

            if(op == ARP_OPERATION_CODE_REQUEST){
                arp_request_arrives(src_dev, packet);

            }else if(op == ARP_OPERATION_CODE_REPLY){
                arp_reply_arrives(src_dev, packet);
            }
        }
            break;
    }
}

void arp_request_arrives(net_device* dev, arp_ip_to_ethernet* packet){

    if(dev->ip_dev != nullptr and dev->ip_dev->address != IP_ADDRESS(0, 0, 0, 0)){ // IPアドレスが設定されているデバイスからの受信だったら
        if(dev->ip_dev->address == ntohl(packet->tpa)){ // 要求されているアドレスが自分の物だったら
            LOG_ARP("Sending arp reply via %s\n", inet_ntoa(packet->tpa));

            auto* res_my_buf = my_buf::create(46);

            auto res_arp = reinterpret_cast<arp_ip_to_ethernet*>(res_my_buf->buffer);
            res_arp->htype = htons(ARP_HTYPE_ETHERNET);
            res_arp->ptype = htons(ETHERNET_PROTOCOL_TYPE_IP);
            res_arp->hlen = 0x06; // IPアドレスの長さ
            res_arp->plen = 0x04; // MACアドレスの長さ
            res_arp->op = htons(ARP_OPERATION_CODE_REPLY);
            memcpy(res_arp->sha, dev->mac_address, 6);
            res_arp->spa = htonl(dev->ip_dev->address);
            memcpy(res_arp->tha, packet->sha, 6);
            res_arp->tpa = packet->spa;

            ethernet_encapsulate_output(dev, packet->sha, res_my_buf, ETHERNET_PROTOCOL_TYPE_ARP);

            add_arp_table_entry(dev, packet->sha, ntohl(packet->spa)); //
            return;
        }
    }else{
        LOG_ARP("ARP request received from device with no IP address: %s\n", dev->ifname);
    }
}

void arp_reply_arrives(net_device* dev, arp_ip_to_ethernet* packet){
    if(dev->ip_dev != nullptr and dev->ip_dev->address != IP_ADDRESS(0, 0, 0, 0)){ // IPアドレスが設定されているデバイスからの受信だったら
        LOG_ARP("Added arp table entry by arp reply (%s => %s)\n", inet_ntoa(packet->spa), mac_addr_toa(packet->sha));
        add_arp_table_entry(dev, packet->sha, ntohl(packet->spa)); // ARPテーブルエントリの追加
    }else{
        LOG_ARP("ARP reply received from device with no IP address: %s\n", dev->ifname);
    }
}