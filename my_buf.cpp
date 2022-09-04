#include "my_buf.h"


uint16_t checksum_16_my_buf(my_buf *buffer, uint16_t start){

    auto *buf = reinterpret_cast<uint16_t *>(buffer->buffer);
    uint32_t size = buffer->len;
    uint64_t sum = start;

    while(size > 1){
        sum += *buf++;
        size -= 2;
    }
    if(size)
        sum += *(uint8_t *) buf;

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}
