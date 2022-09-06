#ifndef CURO_MY_BUF_H
#define CURO_MY_BUF_H

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include "config.h"

struct my_buf{
    my_buf *prev_my_buf = nullptr; // 前の連結
    my_buf *next_my_buf = nullptr; // 後ろの連結
    uint32_t len = 0; // my_bufに含むバッファの長さ
#ifdef ENABLE_MYBUF_NON_COPY_MODE
    uint8_t *buf_ptr = nullptr;
#endif
    uint8_t buffer[]; // バッファ

    static my_buf *create(uint32_t len){
        auto *buf = (my_buf *) calloc(
                1,sizeof(my_buf) + len);
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

#endif //CURO_MY_BUF_H
