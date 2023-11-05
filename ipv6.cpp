#include "ipv6.h"

#include "binary_trie.h"
#include "config.h"
#include "ethernet.h"
#include "icmpv6.h"
#include "log.h"
#include "my_buf.h"
#include "nat.h"
#include "nd.h"
#include "utils.h"

/**
 * IPv6パケットの受信処理
 * @param input_dev
 * @param buffer
 * @param len
 */

char ipv6ascii[4*16+15+1];
char* ipv6toascii(ipv6_addr addr){

    sprintf(ipv6ascii, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", ntohs(addr.per_16.int1), ntohs(addr.per_16.int2), ntohs(addr.per_16.int3),
            ntohs(addr.per_16.int4), ntohs(addr.per_16.int5), ntohs(addr.per_16.int6), ntohs(addr.per_16.int7),
            ntohs(addr.per_16.int8));

    return ipv6ascii;
}

void ipv6_input(net_device *input_dev, uint8_t *buffer, ssize_t len) {

    if(input_dev->ipv6_dev == nullptr){
        LOG_IPV6("Received IPv6 packet from non ipv6 device %s\n", input_dev->name);
        return;
    }

    if (len < sizeof(ipv6_addr)) {
        LOG_IPV6("Received IPv6 packet too short from %s\n", input_dev->name);
        return;
    }

    // 送られてきたバッファをキャストして扱う
    ipv6_header *packet = reinterpret_cast<ipv6_header *>(buffer);

    if (packet->ver_tc_fl & 0b1111 != 6) {
        return;
    }

    printf("Next: %02x\n", packet->next_hdr);

    LOG_IP("src: %s\n", ipv6toascii(packet->src_addr));

    LOG_IP("dst: %s\n", ipv6toascii(packet->dest_addr));

    switch (packet->next_hdr) {
    case IPV6_PROTOCOL_NUM_ICMP:
        return icmpv6_input(input_dev->ipv6_dev, packet->src_addr, packet->dest_addr, ((uint8_t *)packet) + sizeof(ipv6_header), len - sizeof(ipv6_header));
    default:
        break;
    }
}

void ipv6_encap_dev_output(net_device* output_dev, const uint8_t* dest_mac_addr, ipv6_addr dest_addr, my_buf* buffer, uint8_t next_hdr_num){

    // 連結リストをたどってIPヘッダで必要なIPパケットの全長を算出する
    uint16_t payload_len = 0;
    my_buf *current = buffer;
    while (current != nullptr) {
        payload_len += current->len;
        current = current->next;
    }

    // IPv6ヘッダ用のバッファを確保する
    my_buf *v6h_mybuf = my_buf::create(sizeof(ipv6_header));
    buffer->add_header(v6h_mybuf); // 包んで送るデータにヘッダとして連結する

    // IPヘッダの各項目を設定
    ipv6_header *v6h_buf = reinterpret_cast<ipv6_header *>(v6h_mybuf->buffer);
    v6h_buf->ver_tc_fl = 0x60;
    v6h_buf->payload_len = htons(payload_len);
    v6h_buf->next_hdr = next_hdr_num;
    v6h_buf->hop_limit = 0xff;
    v6h_buf->src_addr = output_dev->ipv6_dev->address;
    v6h_buf->dest_addr = dest_addr;

    ethernet_encapsulate_output(output_dev, dest_mac_addr, v6h_mybuf, ETHER_TYPE_IPV6);

}

void ipv6_output_to_nexthop(ipv6_addr dest_addr, ipv6_addr src_addr, my_buf* buffer){
    nd_table_entry *entry = search_nd_table_entry(dest_addr);

    if(entry != nullptr){
        LOG_IP("Found entry!\n");

        ethernet_encapsulate_output(entry->dev, entry->mac_addr, buffer, ETHER_TYPE_IPV6);
    }
}

void ipv6_encap_output(ipv6_addr dest_addr, ipv6_addr src_addr, my_buf* buffer, uint8_t next_hdr_num){

    // 連結リストをたどってIPヘッダで必要なIPパケットの全長を算出する
    uint16_t payload_len = 0;
    my_buf *current = buffer;
    while (current != nullptr) {
        payload_len += current->len;
        current = current->next;
    }

    // IPv6ヘッダ用のバッファを確保する
    my_buf *v6h_mybuf = my_buf::create(sizeof(ipv6_header));
    buffer->add_header(v6h_mybuf); // 包んで送るデータにヘッダとして連結する

    // IPヘッダの各項目を設定
    ipv6_header *v6h_buf = reinterpret_cast<ipv6_header *>(v6h_mybuf->buffer);
    v6h_buf->ver_tc_fl = 0x60;
    v6h_buf->payload_len = htons(payload_len);
    v6h_buf->next_hdr = next_hdr_num;
    v6h_buf->hop_limit = 0xff;
    v6h_buf->src_addr = src_addr;
    v6h_buf->dest_addr = dest_addr;

    ipv6_output_to_nexthop(dest_addr, src_addr, v6h_mybuf);

}