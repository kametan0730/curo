#ifndef RAW_SOCKET_NAPT_H
#define RAW_SOCKET_NAPT_H

#include <cstdint>
#include "ip.h"
#include "utils.h"

struct napt_packet_head {
    uint16_t src_port;
    uint16_t dest_port;
};

struct napt_entry{
    uint32_t global_address;
    uint32_t local_address;
    uint16_t global_port;
    uint16_t local_port;
};

struct napt_entries{
    napt_entry* transration[65535];
};

struct napt_outside_device{
    uint32_t outside_address;

    napt_entries* entries;
};

struct napt_inside_device{
    uint32_t outside_address;

    napt_entries* entries;
};

#endif //RAW_SOCKET_NAPT_H
