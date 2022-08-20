#ifndef CURO_MY_BUF_H
#define CURO_MY_BUF_H

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include "config.h"

#define CALLOC calloc
#define FREE free

struct my_buf{
    my_buf* prev_my_buf = nullptr;
    my_buf* next_my_buf = nullptr;
    uint32_t len = 0;
//#ifdef CURO_ZERO_COPY_MODE_ENABLE
    uint8_t* buf_ptr = nullptr; //これ本ではなくす?
//#endif
    uint8_t buffer[];

    /**
     * Allocate my_buf structure with buffer length
     * @param len
     * @return
     */
    static my_buf* create(uint32_t len){

        auto* buf = (my_buf*) CALLOC(1, sizeof(my_buf) + len);
        buf->len = len;

        return buf;
    }

    static void my_buf_free(my_buf* buf, bool is_recursive = false){

        if(!is_recursive){
            FREE(buf);
            return;
        }

        my_buf* tail = buf->get_tail_my_buf(), * tmp;

        while(tail != nullptr){

            tmp = tail;
            tail = tmp->prev_my_buf;

            FREE(tmp);
        }

    }

    uint16_t get_length_until_tail(){ // TODO あってるか考える

        uint16_t total_len = 0;
        my_buf* current_buffer = this;
        while(current_buffer != nullptr){

            total_len += current_buffer->len;
            current_buffer = current_buffer->next_my_buf;

        }
        return total_len;
    }

    my_buf* get_tail_my_buf(){

        my_buf* candidate = this;
        while(candidate->next_my_buf != nullptr){
            candidate = candidate->next_my_buf;
        }
        return candidate;

    }

    my_buf* get_head_my_buf(){

        my_buf* candidate = this;
        while(candidate->prev_my_buf != nullptr){
            candidate = candidate->prev_my_buf;
        }
        return candidate;
    }

    void add_header(my_buf* buf){
        this->prev_my_buf = buf;
        buf->next_my_buf = this;
    }

    void add_before(my_buf* buf){
        this->prev_my_buf = buf;
        buf->next_my_buf = this;
    }

    void add_back(my_buf* buf){
        this->next_my_buf = buf;
        buf->prev_my_buf = this;
    }

};

uint16_t calc_checksum_16(uint16_t* buffer, size_t count, uint16_t start = 0);
uint16_t calc_checksum_16_my_buf(my_buf* buffer, uint16_t start = 0);
uint16_t calc_checksum_16_my_buf_recursive(my_buf* buffer, uint16_t start = 0);


#endif //CURO_MY_BUF_H
