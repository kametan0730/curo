#ifndef CURO_ICMP_H
#define CURO_ICMP_H

#include <iostream>

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DESTINATION_UNREACHABLE 3
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_TIME_EXCEEDED 11

struct icmp_header{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
} __attribute__((packed));

struct icmp_echo{
    uint16_t identify;
    uint16_t sequence;
    uint8_t data[];
} __attribute__((packed));

struct icmp_destination_unreachable{
    uint32_t unused;
    uint8_t data[];
} __attribute__((packed));

struct icmp_time_exceeded{
    uint32_t unused;
    uint8_t data[];
} __attribute__((packed));

struct icmp_message{
    icmp_header header;
    union{
        icmp_echo echo;
        icmp_destination_unreachable destination_unreachable;
        icmp_time_exceeded time_exceeded;
    };
} __attribute__((packed));

#define ICMP_DESTINATION_UNREACHABLE_CODE_NET_UNREACHABLE 0
#define ICMP_DESTINATION_UNREACHABLE_CODE_HOST_UNREACHABLE 1
#define ICMP_DESTINATION_UNREACHABLE_CODE_PROTOCOL_UNREACHABLE 2
#define ICMP_DESTINATION_UNREACHABLE_CODE_PORT_UNREACHABLE 3
#define ICMP_DESTINATION_UNREACHABLE_CODE_FRAGMENT_NEEDED_AND_DF_SET 4
#define ICMP_DESTINATION_UNREACHABLE_CODE_SOURCE_ROUTE_FAILED 5

#define ICMP_TIME_EXCEEDED_CODE_TIME_TO_LIVE_EXCEEDED 0
#define ICMP_TIME_EXCEEDED_CODE_FRAGMENT_REASSEMBLY_TIME_EXCEEDED 1


void icmp_input(uint32_t source, uint32_t destination, void *buffer, size_t len);

void send_icmp_time_exceeded(uint32_t dest_addr, uint32_t src_addr, uint8_t code, void *error_ip_buffer, size_t len);
void send_icmp_destination_unreachable(uint32_t dest_addr, uint32_t src_addr, uint8_t code, void *error_ip_buffer, size_t len);

#endif //CURO_ICMP_H
