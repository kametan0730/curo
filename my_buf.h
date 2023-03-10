#ifndef CURO_MY_BUF_H
#define CURO_MY_BUF_H

#include "config.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

struct my_buf {
    my_buf *previous = nullptr; // 前のmy_buf
    my_buf *next = nullptr;     // 後ろのmy_buf
    uint32_t len = 0;           // my_bufに含むバッファの長さ
#ifdef ENABLE_MYBUF_NON_COPY_MODE
    uint8_t *buf_ptr = nullptr;
#endif
    uint8_t buffer[]; // バッファ

    /**
     * my_bufのメモリ確保
     * @param len 確保するバッファ長
     */
    static my_buf *create(uint32_t len) {
        auto *buf = (my_buf *)calloc(1, sizeof(my_buf) + len);
        buf->len = len;
        return buf;
    }

    /**
     * my_bufのメモリ開放
     * @param buf
     * @param is_recursive
     */
    static void my_buf_free(my_buf *buf, bool is_recursive = false) {
        if (!is_recursive) {
            free(buf);
            return;
        }

        my_buf *tail = buf->get_tail(), *tmp;
        while (tail != nullptr) {
            tmp = tail;
            tail = tmp->previous;
            free(tmp);
        }
    }

    /**
     * 連結リストの最後の項目を返す
     */
    my_buf *get_tail() {
        my_buf *current = this;
        while (current->next != nullptr) {
            current = current->next;
        }
        return current;
    }

    void add_header(my_buf *buf) {
        this->previous = buf;
        buf->next = this;
    }
};

#endif // CURO_MY_BUF_H
