#ifndef CURO_NAT_H
#define CURO_NAT_H

#include <cstdint>
#include "icmp.h"
#include "ip.h"
#include "utils.h"

#define NAT_GLOBAL_PORT_MIN 20000
#define NAT_GLOBAL_PORT_MAX 59999

#define NAT_GLOBAL_PORT_SIZE (NAT_GLOBAL_PORT_MAX - NAT_GLOBAL_PORT_MIN + 1)

#define NAT_ICMP_ID_SIZE 0xffff


// NATの方向
enum class nat_direction{
    outgoing, incoming
};

// NATに対応しているプロトコル
enum class nat_protocol{
    udp, tcp, icmp
};

struct nat_packet_head{
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

struct nat_entry{
    uint32_t global_addr;
    uint32_t local_addr;
    uint16_t global_port;
    uint16_t local_port;
};

// ICMP, UDP, TCPのNATテーブルのセット
struct nat_entries{
    nat_entry icmp[NAT_ICMP_ID_SIZE];
    nat_entry udp[NAT_GLOBAL_PORT_SIZE];
    nat_entry tcp[NAT_GLOBAL_PORT_SIZE];
};

// NATの内側のip_deviceが持つNATデバイス
struct nat_device{
    uint32_t outside_addr; // 変換先のIPアドレス
    nat_entries *entries; // NATテーブル
};

void dump_nat_tables();

bool nat_exec(ip_header *ip_packet, size_t len, nat_device *nat_dev, nat_protocol proto, nat_direction direction);

nat_entry *get_nat_entry_by_global(nat_entries *entries, nat_protocol proto, uint32_t addr, uint16_t port);
nat_entry *get_nat_entry_by_local(nat_entries *entries, nat_protocol proto, uint32_t addr, uint16_t port);
nat_entry *create_nat_entry(nat_entries *entries, nat_protocol proto);


#endif //CURO_NAT_H
