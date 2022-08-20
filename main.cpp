#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cstddef>
#include <fstream>
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
#include <termios.h>
#include "binary_trie.h"
#include "command.h"
#include "config.h"
#include "ethernet.h"
#include "ip.h"
#include "net.h"
#include "utils.h"
#include "my_buf.h"

struct net_device_data{
    int fd;
};

int net_device_transmit(struct net_device* dev, my_buf* buf){

    uint8_t real_buffer[1550];
    uint16_t total_len = 0;

    my_buf* current_buffer = buf;
    while(current_buffer != nullptr){

        if(total_len + current_buffer->len > sizeof(real_buffer)){ // Overflowする場合
            printf("[DEV] Frame is too long!\n");
            return -1;
        }

#ifdef MYBUF_NON_COPY_MODE_ENABLE
        if(current_buffer->buf_ptr != nullptr){
            memcpy(&real_buffer[total_len], current_buffer->buf_ptr, current_buffer->len);
        }else{
#endif
        memcpy(&real_buffer[total_len], current_buffer->buffer, current_buffer->len);
#ifdef MYBUF_NON_COPY_MODE_ENABLE
        }
#endif

        total_len += current_buffer->len;
        current_buffer = current_buffer->next_my_buf;
    }

    /*
    printf("Send %d bytes\n", total_len);

    for (int i = 0; i < total_len; ++i) {
        printf("%02x", real_buffer[i]);
    }

    printf("\n");
    */

    send(((net_device_data*) dev->data)->fd, real_buffer, total_len, 0);

    my_buf::my_buf_free(buf, true);
    return 0;
}

int net_device_poll(net_device* dev){
    uint8_t buffer[1550];
    long n = recv(((net_device_data*) dev->data)->fd, buffer, sizeof(buffer), 0);
    if(n == -1){
        if(errno == EAGAIN){
            return 0;
        }else{
            return -1;
        }
    }
    ethernet_input(dev, buffer, n);
    return 0;
}

int main(){

    typedef void entry_point_function_type(struct ss* arg);

    struct ifreq ifr{};
    struct ifaddrs* addrs;
    bool enable;

    getifaddrs(&addrs);

    char enable_interfaces[][IF_NAMESIZE] = ENABLE_INTERFACES;

    for(ifaddrs* tmp = addrs; tmp; tmp = tmp->ifa_next){

        if(tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET){

            enable = false;

            memset(&ifr, 0, sizeof(ifr));

            strcpy(ifr.ifr_name, tmp->ifa_name);

            for(int i = 0; i < sizeof(enable_interfaces) / IF_NAMESIZE; i++){
                if(strcmp(enable_interfaces[i], tmp->ifa_name) == 0){
                    enable = true;
                }
            }

            if(!enable){
                printf("Skipped to enable interface %s\n", tmp->ifa_name);
                continue;
            }

            int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
            if(sock == -1){
                continue;
            }

            if(ioctl(sock, SIOCGIFHWADDR, &ifr) != 0){
                close(sock);
                continue;
            }

            auto* dev = (net_device*) malloc(sizeof(net_device) + sizeof(net_device_data));
            dev->ops.transmit = net_device_transmit;
            dev->ops.poll = net_device_poll;

            ((net_device_data*) dev->data)->fd = sock;
            strcpy(dev->ifname, tmp->ifa_name);

            memcpy(dev->mac_address, &ifr.ifr_hwaddr.sa_data[0], 6);

            if(ioctl(sock, SIOCGIFINDEX, &ifr) == -1){
                close(sock);
                continue;
            }

            sockaddr_ll addr{};
            memset(&addr, 0x00, sizeof(addr));
            addr.sll_family = AF_PACKET;
            addr.sll_protocol = htons(ETH_P_ALL);
            addr.sll_ifindex = ifr.ifr_ifindex;
            if(bind(sock, (struct sockaddr*) &addr, sizeof(addr)) == -1){
                close(sock);
                free(dev);
                continue;
            }

            printf("Created dev %s sock %d addr %s \n", dev->ifname, sock, mac_addr_toa(dev->mac_address));

            net_device* next;
            next = net_dev_list;
            net_dev_list = dev;
            dev->next = next;

            int val = fcntl(sock, F_GETFL, 0);
            fcntl(sock, F_SETFL, val | O_NONBLOCK); // ノンブロック
        }
    }

    freeifaddrs(addrs);

    if(net_dev_list == nullptr){
        printf("No interface is enabled!\n");
        return 0;
    }

    ip_fib = (binary_trie_node<ip_route_entry>*) calloc(1, sizeof(binary_trie_node<ip_route_entry>));

    configure();

    termios attr{};
    tcgetattr(0, &attr);

    attr.c_lflag &= ~(ECHO | ICANON);
    attr.c_cc[VTIME] = 0;
    attr.c_cc[VMIN] = 1;
    tcsetattr(0, TCSANOW, &attr);

    fcntl(0, F_SETFL, O_NONBLOCK);

    ssize_t n;
    unsigned char buf[1550];
    while(true){

        char input = getchar();
        if(input != -1){
            command_input(input);
        }

        for(net_device* a = net_dev_list; a; a = a->next){
            a->ops.poll(a);
        }
    }

    return 0;
}