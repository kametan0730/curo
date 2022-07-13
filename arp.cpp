#include "arp.h"

#include <cstring>
#include "net.h"
#include "utils.h"
#include "ethernet.h"
#include "ip.h"
#include "my_buf.h"

arp_table_entry arp_table[ARP_TABLE_SIZE];

void add_arp_table_entry(net_device *device, uint8_t* mac_address, uint32_t ip_address) {

    if (ip_address == 0) {
        printf("Unable to create arp table to 0.0.0.0");
    }

    uint16_t index = ip_address % ARP_TABLE_SIZE;

    arp_table_entry* candidate = &arp_table[index];

    if(candidate->ip_address == 0){ // 想定のHash値に入れられるとき
        memcpy(candidate->mac_address, mac_address, 6);
        candidate->ip_address = ip_address;
        candidate->device = device;
    }

    // だめだったときは、candidateに連結する

    while(candidate->next != nullptr){
        candidate = candidate->next;
        if(candidate->ip_address == ip_address){
            memcpy(candidate->mac_address, mac_address, 6);
            candidate->ip_address = ip_address;
            candidate->device = device;
        }
    }

    arp_table_entry* creation = (arp_table_entry*) calloc(1, sizeof(arp_table_entry));
    memcpy(creation->mac_address, mac_address, 6);
    creation->ip_address = ip_address;
    creation->device = device;

    candidate->next = creation;
}


arp_table_entry *search_arp_table_entry(uint32_t ip_address) {
    uint16_t index = ip_address % ARP_TABLE_SIZE;
    arp_table_entry* candidate = &arp_table[index];

    if (candidate->ip_address == ip_address) {
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

    return nullptr; // Oops
}


void dump_arp_table_entry() {

    for (int i = 0; i < ARP_TABLE_SIZE; ++i) {
        if (arp_table[i].ip_address == 0) {
            continue;
        }

        for (arp_table_entry *a = &arp_table[i]; a; a = a->next) {

            printf("%s to %s dev %s index %04d", inet_htoa(a->ip_address),
                   mac_addr_toa(a->mac_address), a->device->ifname, i);
        }
    }
}

void issue_arp_request(net_device *device, uint32_t search_ip) {

    printf("Send arp request via %s", device->ifname);
    auto *new_buf = my_buf::create(46);

    auto *arp = reinterpret_cast<arp_ip_to_ethernet *>(new_buf->buffer);
    arp->htype = htons(ARP_HTYPE_ETHERNET);
    arp->ptype = htons(ETHERNET_PROTOCOL_TYPE_IP);
    arp->hlen = 0x06;
    arp->plen = 0x04;
    arp->oper = htons(ARP_OPERATION_CODE_REQUEST);
    memcpy(arp->sha, device->mac_address, 6);
    arp->spa = htonl(device->ip_dev->address);
    // memset(arp->tha, 0x00, 6); calloc is good
    arp->tpa = htonl(search_ip);

    ethernet_output_broadcast(device, new_buf, ETHERNET_PROTOCOL_TYPE_ARP);
}


void arp_request_arrives(net_device *source_interface, arp_ip_to_ethernet *packet) {

    printf("Received arp request packet\n");

    /**
     * リクエストからもARPレコードを生成する
     */
    add_arp_table_entry(source_interface, packet->sha, ntohl(packet->spa));

    for (net_device *a = net_dev; a; a = a->next) { // TODO このループいる?

        if (a->ip_dev != nullptr and a->ip_dev->address != IP_ADDRESS_FROM_HOST(0, 0, 0, 0)) {
            if (a->ip_dev->address == ntohl(packet->tpa)) {
                printf("ARP matched with %s\n", inet_ntoa(packet->tpa));
                auto *res = my_buf::create(46);

                auto res_arp = reinterpret_cast<arp_ip_to_ethernet *>(res->buffer);
                res_arp->htype = htons(0x0001);
                res_arp->ptype = htons(ETHERNET_PROTOCOL_TYPE_IP);
                res_arp->hlen = 0x06;
                res_arp->plen = 0x04;
                res_arp->oper = htons(0x0002);
                memcpy(res_arp->sha, a->mac_address, 6);
                res_arp->spa = htonl(a->ip_dev->address);
                memcpy(res_arp->tha, packet->sha, 6);
                res_arp->tpa = packet->spa;

                ethernet_output(source_interface, packet->sha, res, ETHERNET_PROTOCOL_TYPE_ARP);
                break; // 本当にこれでいいかな、もし誰かが偽装してるとしたら、複数いたときにも返してあげなければならないのではないか 2021/11/24
            }
        }
    }
}

void arp_reply_arrives(net_device *source_interface, arp_ip_to_ethernet *packet) {
    printf("Received arp reply packet");
    add_arp_table_entry(source_interface, packet->sha, ntohl(packet->spa));


}

void arp_input(net_device *source_interface, uint8_t *buffer, ssize_t len) {

    auto *packet = reinterpret_cast<arp_ip_to_ethernet *>(buffer);
    uint16_t oper = ntohs(packet->oper);

    switch (ntohs(packet->ptype)) {
        case ETHERNET_PROTOCOL_TYPE_IP: {

            if (sizeof(arp_ip_to_ethernet) > len) {
                printf("Illegal arp packet length");
                return;
            }

            if (packet->hlen != 6) {
                printf("Illegal hardware address length");
                return;
            }

            if (packet->plen != 4) {
                printf("Illegal protocol address");
                return;
            }

            if (oper == ARP_OPERATION_CODE_REQUEST) {
                arp_request_arrives(source_interface, packet);

            } else if (oper == ARP_OPERATION_CODE_REPLY) {
                arp_reply_arrives(source_interface, packet);

            }
        }
            break;
    }
}