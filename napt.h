#ifndef RAW_SOCKET_NAPT_H
#define RAW_SOCKET_NAPT_H

#include <cstdint>
#include "ip.h"
#include "utils.h"

struct napt_entry{
    uint32_t global_address;
    uint32_t local_address;
    uint16_t global_port;
    uint16_t local_port;
};

napt_entry* global[65535];
napt_entry* local[65535];

#endif //RAW_SOCKET_NAPT_H
