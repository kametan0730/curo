#ifndef RAW_SOCKET_NAPT_H
#define RAW_SOCKET_NAPT_H

#include <cstdint>
#include "ip.h"
#include "utils.h"

#define NAPT_GLOBAL_PORT_MIN 20000
#define NAPT_GLOBAL_PORT_MAX 59999

#define NAPT_GLOBAL_PORT_SIZE (NAPT_GLOBAL_PORT_MAX - NAPT_GLOBAL_PORT_MIN + 1)

struct napt_packet_head {
    uint16_t src_port;
    uint16_t dest_port;

    union{
        struct{
            uint16_t len;
            uint16_t checksum;
        } udp;
        struct{
            uint32_t sequence_number;
            uint32_t acknowledge_number;
            uint8_t offset;
            uint8_t flag;
            uint16_t window;
            uint16_t checksum;
            uint16_t urgent_pointer;
        } tcp;
    };
};

struct napt_entry{
    uint32_t global_address;
    uint32_t local_address;
    uint16_t global_port;
    uint16_t local_port;
};

struct napt_entries{
    napt_entry translation[NAPT_GLOBAL_PORT_SIZE];
};

struct napt_outside_device{
    uint32_t outside_address;

    napt_entries* entries;
};

struct napt_inside_device{
    uint32_t outside_address;

    napt_entries* entries;
};

napt_entry* get_napt_entry_by_global(napt_entries* entries, uint32_t address, uint16_t port);
napt_entry* get_napt_entry_by_local(napt_entries* entries, uint32_t address, uint16_t port);

napt_entry* create_napt_entry(napt_entries* entries);


#endif //RAW_SOCKET_NAPT_H
