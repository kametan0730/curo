#include "net.h"

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <cerrno>
#include <unistd.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netpacket/packet.h>
#include "my_buf.h"
net_device* net_dev;

void net_device_send_my_buf(net_device* device, my_buf* buf){

    uint8_t real_buffer[2000];
    uint16_t total_len = 0;

    my_buf* current_buffer = buf;
    while(current_buffer != nullptr){

        if(current_buffer->buf_ptr == nullptr){

            memcpy(&real_buffer[total_len], current_buffer->buffer, current_buffer->len);
        }else{

            memcpy(&real_buffer[total_len], current_buffer->buf_ptr, current_buffer->len);
        }

        total_len += current_buffer->len;
        current_buffer = current_buffer->next_my_buf;
    }

    printf("Send %d bytes\n", total_len);

    for (int i = 0; i < total_len; ++i) {
        printf("%02x", real_buffer[i]);
    }

    printf("\n");

    send(device->fd, real_buffer, total_len, 0);

    my_buf::my_buf_free(buf, true);
}