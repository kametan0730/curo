#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <cerrno>
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
#include "my_buf.h"
#include "net.h"
#include "utils.h"

#define ENABLE_INTERFACES {"router1-host1", "router1-router2"}


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

    send(((net_device_data*) dev->data)->fd, real_buffer, total_len, 0);

    my_buf::my_buf_free(buf, true);
    return 0;
}

int net_device_poll(net_device* dev){
    uint8_t buffer[1550];
    ssize_t n = recv(((net_device_data*) dev->data)->fd, buffer, sizeof(buffer), 0);
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



void configure(){

    configure_ip("router1-host1", IP_ADDRESS(192, 168, 1, 1), IP_ADDRESS(255, 255, 255, 0));
    configure_ip("router1-router2", IP_ADDRESS(192, 168, 0, 1), IP_ADDRESS(255, 255, 255, 0));

    //configure_ip_napt(LINK_TO_HOST1, LINK_TO_HOST0);

    configure_net_route(IP_ADDRESS(192, 168, 2, 2), 24, IP_ADDRESS(192, 168, 0, 2));

}

bool is_enable_interface(const char* ifname){

    char enable_interfaces[][IF_NAMESIZE] = ENABLE_INTERFACES;

    for(int i = 0; i < sizeof(enable_interfaces) / IF_NAMESIZE; i++){
        if(strcmp(enable_interfaces[i], ifname) == 0){
            return true;
        }
    }
    return false;
}

int main(){

    struct ifreq ifr{};
    struct ifaddrs* addrs;

    // ネットワークインターフェースを情報を取得
    getifaddrs(&addrs);

    for(ifaddrs* tmp = addrs; tmp; tmp = tmp->ifa_next){
        if(tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET){

            // ioctlでコントロールするインターフェースを設定
            memset(&ifr, 0, sizeof(ifr));
            strcpy(ifr.ifr_name, tmp->ifa_name);

            // 有効化するインターフェースか確認
            if(!is_enable_interface(tmp->ifa_name)){
                printf("Skipped to enable interface %s\n", tmp->ifa_name);
                continue;
            }

            // Socketをオープン
            int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
            if(sock == -1){
                LOG_ERROR("socket open failed\n");
                continue;
            }

            // インターフェースのインデックスを取得
            if(ioctl(sock, SIOCGIFINDEX, &ifr) == -1){
                LOG_ERROR("ioctl SIOCGIFINDEX\n");
                close(sock);
                continue;
            }

            // インターフェースをsocketにbindする
            sockaddr_ll addr{};
            memset(&addr, 0x00, sizeof(addr));
            addr.sll_family = AF_PACKET;
            addr.sll_protocol = htons(ETH_P_ALL);
            addr.sll_ifindex = ifr.ifr_ifindex;
            if(bind(sock, (struct sockaddr*) &addr, sizeof(addr)) == -1){
                LOG_ERROR("bind failed\n");
                close(sock);
                continue;
            }

            // インターフェースのMACアドレスを取得
            if(ioctl(sock, SIOCGIFHWADDR, &ifr) != 0){
                LOG_ERROR("ioctl SIOCGIFHWADDR failed\n");
                close(sock);
                continue;
            }

            // net_device構造体を作成
            auto* dev = (net_device*) calloc(1, sizeof(net_device) + sizeof(net_device_data));
            dev->ops.transmit = net_device_transmit; // 送信用の関数を設定
            dev->ops.poll = net_device_poll; // 受信用の関数を設定

            strcpy(dev->ifname, tmp->ifa_name); // net_deviceにインターフェース名をセット
            memcpy(dev->mac_address, &ifr.ifr_hwaddr.sa_data[0], 6); // net_deviceにMACアドレスをセット
            ((net_device_data*) dev->data)->fd = sock; //

            printf("[DEV] Created dev %s sock %d addr %s \n", dev->ifname, sock, mac_addr_toa(dev->mac_address));

            // 連結させる
            net_device* next;
            next = net_dev_list;
            net_dev_list = dev;
            dev->next = next;

            // ノンブロッキングに設定
            int val = fcntl(sock, F_GETFL, 0); // File descriptorのflagを取得
            fcntl(sock, F_SETFL, val | O_NONBLOCK); // Non blockingのbitをセット
        }
    }

    // 確保されていたメモリを解放
    freeifaddrs(addrs);

    // 1つも有効化されたインターフェースをが無かったら終了
    if(net_dev_list == nullptr){
        LOG_ERROR("No interface is enabled!\n");
        return 0;
    }

    // IPルーティングテーブルの木構造のrootノードを作成
    ip_fib = (binary_trie_node<ip_route_entry>*) calloc(1, sizeof(binary_trie_node<ip_route_entry>));

    // 設定の投入
    configure();

    termios attr{};
    tcgetattr(0, &attr);

    attr.c_lflag &= ~(ECHO | ICANON);
    attr.c_cc[VTIME] = 0;
    attr.c_cc[VMIN] = 1;
    tcsetattr(0, TCSANOW, &attr);

    fcntl(0, F_SETFL, O_NONBLOCK);

    while(true){

        char input = getchar();
        if(input != -1){
            command_input(input);
        }

        // インターフェースから通信を受信
        for(net_device* dev = net_dev_list; dev; dev = dev->next){
            dev->ops.poll(dev);
        }
    }

    return 0;
}