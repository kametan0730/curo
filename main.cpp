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

#define NET_INPUT ethernet_input


void dump_frame(unsigned char* buf, size_t len){

    for(int i = 0; i < len; ++i){
        printf("%02x", buf[i]);
    }
    printf("\n");

}

void net_device_output(net_device* dev, uint8_t* buf){

}

int main(){

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

            auto* dev = (net_device*) malloc(sizeof(net_device));
            dev->fd = sock;
            strcpy(dev->ifname, tmp->ifa_name);

            memcpy(dev->mac_address, &ifr.ifr_hwaddr.sa_data[0], 6);

            if(ioctl(sock, SIOCGIFINDEX, &ifr) == -1){
                close(sock);
                continue;
            }

            struct sockaddr_ll addr{};
            memset(&addr, 0x00, sizeof(addr));
            addr.sll_family = AF_PACKET;
            addr.sll_protocol = htons(ETH_P_ALL);
            addr.sll_ifindex = ifr.ifr_ifindex;
            if(bind(sock, (struct sockaddr*) &addr, sizeof(addr)) == -1){
                close(sock);
                free(dev);
                continue;
            }

            printf("Created dev %s sock %d addr %s \n", dev->ifname, dev->fd, mac_addr_toa(dev->mac_address));

            net_device* next;
            next = net_dev;
            net_dev = dev;
            dev->next = next;

            int val = fcntl(dev->fd, F_GETFL, 0);
            fcntl(dev->fd, F_SETFL, val | O_NONBLOCK); // ノンブロック
        }
    }

    freeifaddrs(addrs);

    if(net_dev == nullptr){
        printf("No interface is enabled!\n");
        return 0;
    }

    ip_fib = (binary_trie_node<ip_route_entry>*) calloc(1, sizeof(binary_trie_node<ip_route_entry>));

    configure();

    termios attr;
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

        for(net_device* a = net_dev; a; a = a->next){
            /* ソケットからデータ受信 */
            n = recv(a->fd, buf, sizeof(buf), 0);
            if(n == -1){
                if(errno == EAGAIN){
                    continue;
                }else{
                    perror("recv");
                    //close(a->fd);
                    return -1;
                }
            }

            NET_INPUT(a, buf, n);

        }
    }

    return 0;
}