#ifndef CURO_MY_BUF_H
#define CURO_MY_BUF_H

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include "config.h"

struct my_buf{
    my_buf *prev_my_buf = nullptr;
    my_buf *next_my_buf = nullptr;
    uint32_t len = 0;
#ifdef ENABLE_MYBUF_NON_COPY_MODE
    uint8_t *buf_ptr = nullptr;
#endif
    uint8_t buffer[];

    static my_buf *create(uint32_t len){
        auto *buf = (my_buf *) calloc(1, sizeof(my_buf) + len);
        buf->len = len;
        return buf;
    }

    static void my_buf_free(my_buf *buf, bool is_recursive = false){
        if(!is_recursive){
            free(buf);
            return;
        }

        my_buf *tail = buf->get_tail_my_buf(), *tmp;
        while(tail != nullptr){
            tmp = tail;
            tail = tmp->prev_my_buf;
            free(tmp);
        }
    }

    my_buf *get_tail_my_buf(){
        my_buf *current = this;
        while(current->next_my_buf != nullptr){
            current = current->next_my_buf;
        }
        return current;
    }

    void add_header(my_buf *buf){
        this->prev_my_buf = buf;
        buf->next_my_buf = this;
    }
};

uint16_t checksum_16(uint16_t *buffer, size_t count, uint16_t start = 0);
uint16_t checksum_16_my_buf(my_buf *buffer, uint16_t start = 0);


#endif //CURO_MY_BUF_H
