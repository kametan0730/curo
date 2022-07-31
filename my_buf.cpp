#include "my_buf.h"

uint16_t calc_checksum_16(uint16_t* buffer, size_t count, uint16_t start){
    uint32_t sum = start;

    while(count > 1){
        /*  This is the inner loop */
        sum += *buffer++;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if(count > 0)
        sum += *(uint8_t*) buffer;

    /*  Fold 32-bit sum to 16 bits */
    while(sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

uint16_t calc_checksum_16_my_buf(my_buf* buffer, uint16_t start){

    auto* buf = reinterpret_cast<uint16_t*>(buffer->buffer);
    uint32_t size = buffer->len;
    uint64_t sum = start;

    while(size > 1){
        sum += *buf++;
        size -= 2;
    }
    if(size)
        sum += *(uint8_t*) buf;

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

uint16_t calc_checksum_16_my_buf_recursive(my_buf* buffer, uint16_t start){ // TODO support pointer my_buf

    my_buf* current_buffer = buffer;

    auto* buf = reinterpret_cast<uint16_t*>(current_buffer->buffer);
    size_t size = current_buffer->len;
    uint64_t sum = start;

    while(true){
        if(size > 1){

            sum += *buf++;
            size -= 2;

        }else if(size == 1 and current_buffer->next_my_buf != nullptr){

            sum += *(uint8_t*) buf;

            current_buffer = current_buffer->next_my_buf;
            buf = reinterpret_cast<uint16_t*>(current_buffer->buffer);
            size = current_buffer->len;

            sum += ((*(uint8_t*) buf) * 0x100);

            auto* aa = reinterpret_cast<uint8_t*>(buf);
            aa++;
            buf = reinterpret_cast<uint16_t*>(aa);

            size -= 1;

        }else if(size == 0 and current_buffer->next_my_buf != nullptr){

            current_buffer = current_buffer->next_my_buf;
            buf = reinterpret_cast<uint16_t*>(current_buffer->buffer);
            size = current_buffer->len;

        }else if(size == 1 and current_buffer->next_my_buf == nullptr){

            sum += *(uint8_t*) buf;
            break;

        }else{

            break;

        }

    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}
