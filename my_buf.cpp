#include "my_buf.h"

/**
 * Checksumの計算
 * @param buffer
 * @param count
 * @param start
 * @return
 */
uint16_t checksum_16(uint16_t *buffer, size_t count, uint16_t start){
    uint32_t sum = start;

    // まず16ビット毎に足す
    while(count > 1){
        sum += *buffer++;
        count -= 2;
    }

    // もし1バイト余ってたら足す
    if(count > 0)
        sum += *(uint8_t *) buffer;

    // あふれた桁を折り返して足す
    while(sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum; // 論理否定(NOT)をとる
}

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

uint16_t checksum_16_my_buf_recursive(my_buf *buffer, uint16_t start){ // TODO: Support non copy mode my_buf

    my_buf *current_buffer = buffer;
    auto *buf = reinterpret_cast<uint16_t *>(current_buffer->buffer);
    size_t size = current_buffer->len;
    uint64_t sum = start;

    while(true){
        if(size > 1){
            sum += *buf++;
            size -= 2;
        }else if(size == 1 and current_buffer->next_my_buf != nullptr){
            sum += *(uint8_t *) buf;
            current_buffer = current_buffer->next_my_buf;
            buf = reinterpret_cast<uint16_t *>(current_buffer->buffer);
            size = current_buffer->len;
            sum += ((*(uint8_t *) buf) * 0x100);
            auto *aa = reinterpret_cast<uint8_t *>(buf);
            aa++;
            buf = reinterpret_cast<uint16_t *>(aa);
            size -= 1;

        }else if(size == 0 and current_buffer->next_my_buf != nullptr){

            current_buffer = current_buffer->next_my_buf;
            buf = reinterpret_cast<uint16_t *>(current_buffer->buffer);
            size = current_buffer->len;

        }else if(size == 1 and current_buffer->next_my_buf == nullptr){
            sum += *(uint8_t *) buf;
            break;
        }else{
            break;
        }
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}
