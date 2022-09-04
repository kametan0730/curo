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
