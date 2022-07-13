//
// Created by ubuntu on 7/4/22.
//

#include "icmp.h"
#include <cstring>
#include "net.h"
#include "utils.h"
#include "ethernet.h"
#include "ip.h"
#include "my_buf.h"

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DESTINATION_UNREACHABLE 3
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_TIME_EXCEEDED 11


void icmp_input(uint32_t source, uint32_t destination, void* buffer, size_t len){

    auto* header = reinterpret_cast<icmp_header*>(buffer);

    switch(header->type){
        case ICMP_TYPE_ECHO_REPLY:
            printf("Received icmp echo reply\n");
            break;
        case ICMP_TYPE_ECHO_REQUEST:{
            printf("Received icmp echo request\n");

            auto* request = reinterpret_cast<icmp_echo*>(buffer);

            my_buf* reply_my_buf = my_buf::create(len);

            auto* reply = reinterpret_cast<icmp_echo*>(reply_my_buf->buffer);
            reply->header.type = ICMP_TYPE_ECHO_REPLY;
            reply->header.code = 0;
            reply->header.checksum = 0;
            reply->identify = request->identify;
            reply->sequence = request->sequence;
            memcpy(&reply->data, &request->data, len - 8);
            //reply->header.checksum = calc_checksum_16_my_buf(reply_my_buf);

            ip_output(source, destination, reply_my_buf, IP_PROTOCOL_TYPE_ICMP);
        }
            break;
        default:
            printf("Received unhandled icmp type %d\n", header->type);
            break;
    }
}
