#include "ethernet.h"

#include <cstring>
#include "arp.h"
#include "config.h"
#include "ip.h"
#include "my_buf.h"
#include "utils.h"

void ethernet_input(net_device *dev, uint8_t *buffer, ssize_t len){

    // 送られてきた通信をイーサネットのフレームとして解釈する
    auto *header = reinterpret_cast<ethernet_header *>(buffer);
    uint16_t ethernet_type = ntohs(header->type); // イーサネットタイプを抜き出すし、ホストバイトオーダーに変換

    // 自分のMACアドレス宛てかブロードキャストの通信かを確認する
    if(memcmp(header->dest_address, dev->mac_address, 6) != 0 and
       memcmp(header->dest_address, ETHERNET_ADDRESS_BROADCAST, 6) != 0){
        return;
    }

    LOG_ETHERNET("Received ethernet frame type %04x from %s to %s\n",
                 ethernet_type, mac_addr_toa(header->src_address),
                 mac_addr_toa(header->dest_address));

    // イーサネットタイプの値から上位プロトコルを特定する
    switch(ethernet_type){
        case ETHERNET_PROTOCOL_TYPE_ARP: // イーサネットタイプがARPのものだったら
            return arp_input(
                    dev,
                    buffer + ETHERNET_HEADER_SIZE,
                    len - ETHERNET_HEADER_SIZE
            ); // Ethernetヘッダを外してARP処理へ
        case ETHERNET_PROTOCOL_TYPE_IP: // イーサネットタイプがIPのものだったら
            return ip_input(
                    dev,
                    buffer + ETHERNET_HEADER_SIZE,
                    len - ETHERNET_HEADER_SIZE
            ); // Ethernetヘッダを外してIP処理へ
        default:
        LOG_ETHERNET("Received unhandled ethernet type %04x\n", ethernet_type);
            return;
    }
}

void ethernet_encapsulate_output(net_device *device, const uint8_t *dest_addr, my_buf *upper_layer_buffer, uint16_t protocol_type){
    LOG_ETHERNET("Sent ethernet frame type %04x from %s to %s\n",
                 protocol_type, mac_addr_toa(device->mac_address),
                 mac_addr_toa(dest_addr));

    my_buf *ethernet_header_my_buf = my_buf::create(ETHERNET_HEADER_SIZE); // イーサネットヘッダ長分のバッファを確保
    auto *ether_header = reinterpret_cast<ethernet_header *>(ethernet_header_my_buf->buffer);

    // イーサネットヘッダの設定
    memcpy(ether_header->src_address, device->mac_address, 6); // 送信元アドレスにはデバイスのアドレスを設定
    memcpy(ether_header->dest_address, dest_addr, 6); // `宛先アドレスの設定
    ether_header->type = htons(protocol_type); // イーサネットタイプの設定

    upper_layer_buffer->add_header(ethernet_header_my_buf); // 上位プロトコルから受け取ったバッファにヘッダをつける

#if DEBUG_ETHERNET > 1
    printf("[ETHER] Transmit buffer: ");
    for (int i = 0; i < ethernet_header_my_buf->len; ++i) {
        printf("%02x", ethernet_header_my_buf->buffer[i]);
    }
    printf("\n");
#endif

    // ネットワークデバイスに送信する
    device->ops.transmit(device, ethernet_header_my_buf);
}
