#ifndef CURO_NAPT_H
#define CURO_NAPT_H

#include <cstdint>
#include "icmp.h"
#include "ip.h"
#include "utils.h"

#define NAPT_GLOBAL_PORT_MIN 20000
#define NAPT_GLOBAL_PORT_MAX 59999

#define NAPT_GLOBAL_PORT_SIZE (NAPT_GLOBAL_PORT_MAX - NAPT_GLOBAL_PORT_MIN + 1)

#define NAPT_ICMP_ID_SIZE 0xffff


// NAPTの方向
enum class napt_direction{
    outgoing, incoming
};

// NATに対応しているプロトコル
enum class napt_protocol{
    udp, tcp, icmp
};

struct napt_packet_head{
    union{
        struct{ // tcp, udp
            uint16_t src_port;
            uint16_t dest_port;
            union{
                struct{
                    uint16_t len;
                    uint16_t checksum;
                } udp;
                struct{
                    uint32_t seq;
                    uint32_t ack_seq;
                    uint8_t offset;
                    uint8_t flag;
                    uint16_t window;
                    uint16_t checksum;
                    uint16_t urg_ptr;
                } tcp;

            };
        };
        struct{ // icmp
            icmp_header header;
            uint16_t identify;
            uint16_t sequence;
        } icmp;
    };
};

struct napt_entry{
    uint32_t global_address;
    uint32_t local_address;
    uint16_t global_port;
    uint16_t local_port;
};

// ICMP, UDP, TCPのNAPTテーブルのセット
struct napt_entries{
    napt_entry icmp[NAPT_ICMP_ID_SIZE];
    napt_entry udp[NAPT_GLOBAL_PORT_SIZE];
    napt_entry tcp[NAPT_GLOBAL_PORT_SIZE];
};

struct napt_inside_device{
    uint32_t outside_address; // 変換先のIPアドレス
    napt_entries *entries; // NAPTテーブル
};

void dump_napt_tables();

bool napt_exec(ip_header *ip_packet, size_t len, napt_inside_device *napt_dev, napt_protocol proto, napt_direction direction);

napt_entry *get_napt_entry_by_global(napt_entries *entries, napt_protocol proto, uint32_t address, uint16_t id);
napt_entry *get_napt_entry_by_local(napt_entries *entries, napt_protocol proto, uint32_t address, uint16_t port);
napt_entry *create_napt_entry(napt_entries *entries, napt_protocol proto);


#endif //CURO_NAPT_H
