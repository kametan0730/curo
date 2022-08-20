#include "icmp.h"

#include <cstring>
#include "config.h"
#include "ethernet.h"
#include "ip.h"
#include "my_buf.h"
#include "net.h"
#include "utils.h"

void icmp_input(uint32_t source, uint32_t destination, void *buffer, size_t len) {

    auto *header = reinterpret_cast<icmp_header *>(buffer);

    switch (header->type) {
        case ICMP_TYPE_ECHO_REPLY: {
            auto *reply = reinterpret_cast<icmp_echo *>(buffer);

#if DEBUG_ICMP > 0
            printf("[ICMP] Received icmp echo reply id %04x seq %d\n", ntohs(reply->identify), ntohs(reply->sequence));
#endif
        }
            break;
        case ICMP_TYPE_ECHO_REQUEST: {
            auto *request = reinterpret_cast<icmp_echo *>(buffer);
#if DEBUG_ICMP > 0
            printf("[ICMP] Received icmp echo request id %04x seq %d\n", ntohs(request->identify), ntohs(request->sequence));
#endif

            my_buf *reply_my_buf = my_buf::create(len);

            auto *reply = reinterpret_cast<icmp_echo *>(reply_my_buf->buffer);
            reply->header.type = ICMP_TYPE_ECHO_REPLY;
            reply->header.code = 0;
            reply->header.checksum = 0;
            reply->identify = request->identify;
            reply->sequence = request->sequence;
            memcpy(&reply->data, &request->data, len - 8);
            //reply->header.checksum = calc_checksum_16_my_buf(reply_my_buf);

            ip_encapsulate_output(source, destination, reply_my_buf, IP_PROTOCOL_TYPE_ICMP);
        }
            break;
        default:
#if DEBUG_ICMP > 0
            printf("[ICMP] Received unhandled icmp type %d\n", header->type);
#endif
            break;
    }
}

void send_icmp_time_exceeded(uint32_t src_addr, uint32_t dest_addr, uint8_t code, void* data){

    my_buf* buffer = my_buf::create(sizeof(icmp_time_exceeded) + sizeof(ip_header) + 8);

    auto* icmp_message = reinterpret_cast<icmp_time_exceeded*>(buffer->buffer);

    icmp_message->header.type = ICMP_TYPE_TIME_EXCEEDED;
    icmp_message->header.code = code;
    icmp_message->header.checksum = 0;
    icmp_message->unused = 0;

    memcpy(icmp_message->data, data, sizeof(ip_header) + 8);

    icmp_message->header.checksum = calc_checksum_16_my_buf(buffer);

    ip_encapsulate_output(dest_addr, src_addr, buffer, IP_PROTOCOL_TYPE_ICMP);
}
