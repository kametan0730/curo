#ifndef CURO_NET_H
#define CURO_NET_H

#include <cstdint>
#include <cstring>

struct net_device;

struct net_device_ops{
    int (*transmit)(net_device *dev, uint8_t *buffer, size_t len);
    int (*poll)(net_device *dev);
};

struct ip_device;

struct net_device{
    char ifname[32]; // インターフェース名
    uint8_t mac_addr[6];
    net_device_ops ops;
    ip_device *ip_dev;
    net_device *next;
    uint8_t data[];
};

extern net_device *net_dev_list; // net_deviceの連結リストの先頭

// #define FOR_EACH_NET_DEV(dev) for (dev = net_dev_list; dev; dev = dev->next)

#endif //CURO_NET_H
