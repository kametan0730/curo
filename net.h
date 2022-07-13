#ifndef RAW_SOCKET_NET_H
#define RAW_SOCKET_NET_H

#include <cstdint>
#include <cstring>
#include <list>
#include <iostream>



#define CALLOC calloc
#define FREE free

struct ip_device;

struct net_device{
    int fd;
    char ifname[32]; // インターフェース名
    uint8_t mac_address[6];

    ip_device* ip_dev;

    net_device* next;

};

extern net_device* net_dev;

struct my_buf;
void net_device_send_my_buf(net_device* device, my_buf* buf);

#endif //RAW_SOCKET_NET_H
