#include <cstdint>
#include <fcntl.h>
#include <ifaddrs.h>
#include <iostream>
#include <termios.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include "binary_trie.h"
#include "config.h"
#include "ethernet.h"
#include "arp.h"
#include "ip.h"
#include "log.h"
#include "my_buf.h"
#include "napt.h"
#include "net.h"
#include "utils.h"

/**
 * 無視するインターフェースたち
 * 中にはMACアドレスを持たないものなど、
 * このプログラムで使うとエラーを引き起こすものもある
 */
#define IGNORE_INTERFACES {"lo", "bond0", \
"dummy0", "tunl0", "sit0"}

/**
 * 無視するデバイスかどうかを返す
 * @param ifname
 * @return IGNORE_INTERFACESに含まれているかどうか
 */
bool is_ignore_interface(const char *ifname){
    char ignore_interfaces[][IF_NAMESIZE] = IGNORE_INTERFACES;

    for(int i = 0; i < sizeof(ignore_interfaces) / IF_NAMESIZE; i++){
        if(strcmp(ignore_interfaces[i], ifname) == 0){
            return true;
        }
    }
    return false;
}

/**
 * インターフェース名からデバイスを探す
 * @param name デバイス名
 * @return
 */
net_device *get_net_device_by_name(const char *name){
    net_device *dev;
    for(dev = net_dev_list; dev; dev = dev->next){
        if(strcmp(dev->ifname, name) == 0){
            return dev;
        }
    }
    return nullptr;
}

/**
 * 設定する
 */
void configure(){
    // for chapter 3
    configure_ip_address(
            get_net_device_by_name("router1-host1"),
            IP_ADDRESS(192, 168, 1, 1),
            IP_ADDRESS(255, 255, 255, 0));
    configure_ip_address(
            get_net_device_by_name("router1-router2"),
            IP_ADDRESS(192, 168, 0, 1),
            IP_ADDRESS(255, 255, 255, 0));
    configure_ip_net_route(
            IP_ADDRESS(192, 168, 2, 0), 24,
            IP_ADDRESS(192, 168, 0, 2));

    // for chapter4
    /*
    configure_ip_address(get_net_device_by_name("router1-host1"), IP_ADDRESS(192, 168, 0, 1), IP_ADDRESS(255, 255, 255, 0));
    configure_ip_address(get_net_device_by_name("router1-router2"), IP_ADDRESS(192, 168, 1, 1), IP_ADDRESS(255, 255, 255, 0));
    configure_ip_address(get_net_device_by_name("router1-router4"), IP_ADDRESS(192, 168, 4, 2), IP_ADDRESS(255, 255, 255, 0));
    //configure_net_route(IP_ADDRESS(192, 168, 5, 0), 24, IP_ADDRESS(192, 168, 1, 2));
    configure_ip_net_route(IP_ADDRESS(192, 168, 5, 0), 24, IP_ADDRESS(192, 168, 4, 1));
    */

    // for chapter 6
    /*
    configure_ip_address(get_net_device_by_name("router1-br0"), IP_ADDRESS(192, 168, 1, 1), IP_ADDRESS(255, 255, 255, 0));
    configure_ip_address(get_net_device_by_name("router1-router2"), IP_ADDRESS(192, 168, 0, 1), IP_ADDRESS(255, 255, 255, 0));
    configure_ip_net_route(IP_ADDRESS(192, 168, 2, 0), 24, IP_ADDRESS(192, 168, 0, 2));
    configure_ip_napt(get_net_device_by_name("router1-br0"), get_net_device_by_name("router1-router2"));
    */
}

// 宣言のみ
int net_device_transmit(struct net_device *dev,
        uint8_t *buffer, size_t len);
int net_device_poll(net_device *dev);

/**
 * デバイスのプラットフォーム依存のデータ
 */
struct net_device_data{
    int fd; // socketのFile descriptor
};

/**
 * エントリーポイント
 * @return
 */
int main(){
    struct ifreq ifr{};
    struct ifaddrs *addrs;

    // ネットワークインターフェースを情報を取得
    getifaddrs(&addrs);

    for(ifaddrs *tmp = addrs; tmp; tmp = tmp->ifa_next){
        if(tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET){

            // ioctlでコントロールするインターフェースを設定
            memset(&ifr, 0, sizeof(ifr));
            strcpy(ifr.ifr_name, tmp->ifa_name);

            // 無視するインターフェースか確認
            if(is_ignore_interface(tmp->ifa_name)){
                printf("Skipped to enable interface %s\n", tmp->ifa_name);
                continue;
            }

            // socketをオープン
            int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
            if(sock == -1){
                LOG_ERROR("socket open failed: %s\n", strerror(errno));
                continue;
            }

            // インターフェースのインデックスを取得
            if(ioctl(sock, SIOCGIFINDEX, &ifr) == -1){
                LOG_ERROR("ioctl SIOCGIFINDEX failed: %s\n", strerror(errno));
                close(sock);
                continue;
            }

            // socketにインターフェースをbindする
            sockaddr_ll addr{};
            memset(&addr, 0x00, sizeof(addr));
            addr.sll_family = AF_PACKET;
            addr.sll_protocol = htons(ETH_P_ALL);
            addr.sll_ifindex = ifr.ifr_ifindex;
            if(bind(sock, (struct sockaddr *) &addr, sizeof(addr)) == -1){
                LOG_ERROR("bind failed: %s\n", strerror(errno));
                close(sock);
                continue;
            }

            // インターフェースのMACアドレスを取得
            if(ioctl(sock, SIOCGIFHWADDR, &ifr) != 0){
                LOG_ERROR("ioctl SIOCGIFHWADDR failed %s\n", strerror(errno));
                close(sock);
                continue;
            }

            // net_device構造体を作成
            auto *dev = (net_device *) calloc(1, sizeof(net_device) + sizeof(net_device_data)); // net_deviceの領域と、net_device_dataの領域を確保する
            dev->ops.transmit = net_device_transmit; // 送信用の関数を設定
            dev->ops.poll = net_device_poll; // 受信用の関数を設定

            strcpy(dev->ifname, tmp->ifa_name); // net_deviceにインターフェース名をセット
            memcpy(dev->mac_addr, &ifr.ifr_hwaddr.sa_data[0], 6); // net_deviceにMACアドレスをセット
            ((net_device_data *) dev->data)->fd = sock;

            printf("Created device %s socket %d address %s \n", dev->ifname, sock, mac_addr_toa(dev->mac_addr));

            // net_deviceの連結リストに連結させる
            net_device *next;
            next = net_dev_list;
            net_dev_list = dev;
            dev->next = next;

            // ノンブロッキングに設定
            int val = fcntl(sock, F_GETFL, 0); // File descriptorのFlagを取得
            fcntl(sock, F_SETFL, val | O_NONBLOCK); // Non blockingのビットをセット
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
    ip_fib = (binary_trie_node<ip_route_entry> *) calloc(1, sizeof(binary_trie_node<ip_route_entry>));

    // ネットワーク設定の投入
    configure();

#ifdef ENABLE_COMMAND
    // 入力時にバッファリングせずにすぐ受け取る設定
    termios attr{};
    tcgetattr(0, &attr);
    attr.c_lflag &= ~(ECHO | ICANON);
    attr.c_cc[VTIME] = 0;
    attr.c_cc[VMIN] = 1;
    tcsetattr(0, TCSANOW, &attr);
    fcntl(0, F_SETFL, O_NONBLOCK); // 標準入力にノンブロッキングの設定
#endif
    while(true){
#ifdef ENABLE_COMMAND
        int input = getchar(); //
        if(input != -1){ // なにも入力がなかったら
            if(input == 'a') dump_arp_table_entry();
            else if(input == 'r') dump_ip_fib();
#ifdef ENABLE_NAPT
            else if(input == 'n') dump_napt_tables();
#endif
        }
#endif

        // デバイスから通信を受信
        for(net_device *dev = net_dev_list; dev; dev = dev->next){
            dev->ops.poll(dev);
        }
    }
    return 0;
}

/**
 * ネットデバイスの送信処理
 * @param dev 送信に使用するデバイス
 * @param buffer 送信するバッファ
 * @param len バッファの長さ
 * @return
 */
int net_device_transmit(struct net_device *dev,
        uint8_t *buffer, size_t len){
    // socketを通して送信
    send(((net_device_data *) dev->data)->fd,
         buffer, len, 0);
    return 0;
}

/**
 * ネットワークデバイスの受信処理
 * @param dev 受信を試みるデバイス
 * @return
 */
int net_device_poll(net_device *dev){
    uint8_t recv_buffer[1550];
    // socketから受信
    ssize_t n = recv(
            ((net_device_data *) dev->data)->fd,
            recv_buffer,
            sizeof(recv_buffer), 0);
    if(n == -1){
        if(errno == EAGAIN){ // 受け取るデータが無かったら
            return 0;
        }else{
            return -1; // 他のエラーなら
        }
    }
    // 受信したデータをイーサネットに送る
    ethernet_input(dev, recv_buffer, n);

    /*
    // for book chapter 2
    printf("Received %lu bytes from %s: ",
           n, dev->ifname);
    for(int i = 0; i < n; ++i){
        printf("%02x", dev->recv_buffer[i]);
    }
    printf("\n");
    */
    return 0;
}