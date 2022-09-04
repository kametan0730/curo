#include "ip.h"

#include "arp.h"
#include "binary_trie.h"
#include "config.h"
#include "ethernet.h"
#include "icmp.h"
#include "log.h"
#include "my_buf.h"
#include "napt.h"
#include "utils.h"

binary_trie_node<ip_route_entry> *ip_fib;

/**
 * IPルーティングテーブルの出力
 */
void dump_ip_fib(){
    binary_trie_node<ip_route_entry> *current_node;
    std::queue<binary_trie_node<ip_route_entry> *> node_queue;
    node_queue.push(ip_fib);

    while(!node_queue.empty()){
        current_node = node_queue.front();
        node_queue.pop();

        if(current_node->data != nullptr){
            if(current_node->data->type == ip_route_type::connected){
                printf("%s/%d connected %s\n",
                       ip_htoa(locate_prefix(
                               current_node,
                               ip_fib)), current_node->depth, current_node->data->device->ifname);
            }else{
                printf("%s/%d nexthop %s\n",
                       ip_htoa(locate_prefix(
                               current_node,
                               ip_fib)), current_node->depth,
                       ip_htoa(current_node->data->next_hop));
            }
        }

        if(current_node->node_0 != nullptr){
            node_queue.push(current_node->node_0);
        }
        if(current_node->node_1 != nullptr){
            node_queue.push(current_node->node_1);
        }
    }
}

/**
 * サブネットにIPアドレスが含まれているか比較
 * @param subnet_prefix
 * @param subnet_mask
 * @param target_address
 * @return
 */
bool in_subnet(uint32_t subnet_prefix, uint32_t subnet_mask, uint32_t target_address){
    return ((target_address & subnet_mask) == (subnet_prefix & subnet_mask));
}


/**
 * 自分宛のIPパケットの処理
 * @param input_dev
 * @param ip_packet
 * @param len
 */
void ip_input_to_ours(net_device *input_dev, ip_header *ip_packet, size_t len){

    // フラグメントされているかの確認
    if((ntohs(ip_packet->frag_offset) & IP_FRAG_OFFSET_MASK_OFFSET) != 0 or
       (ntohs(ip_packet->frag_offset) & IP_FRAG_OFFSET_MASK_MF_FLAG)){
        LOG_IP("IP fragment is not supported\n");
        return;
    }

#ifdef ENABLE_NAPT
    // NAPTの外側から内側への通信か判断
    for(net_device *dev = net_dev_list; dev; dev = dev->next){
        if(dev->ip_dev != nullptr and dev->ip_dev->napt_inside_dev != nullptr and
           dev->ip_dev->napt_inside_dev->outside_address == ntohl(ip_packet->dest_addr)){
            bool napt_executed = false;
            switch(ip_packet->protocol){
                case IP_PROTOCOL_TYPE_UDP:
                    if(napt_exec(ip_packet, len, dev->ip_dev->napt_inside_dev, napt_protocol::udp, napt_direction::incoming)){
                        napt_executed = true;
                    }
                    break;
                case IP_PROTOCOL_TYPE_TCP:
                    if(napt_exec(ip_packet, len, dev->ip_dev->napt_inside_dev, napt_protocol::tcp, napt_direction::incoming)){
                        napt_executed = true;
                    }
                    break;
                case IP_PROTOCOL_TYPE_ICMP:
                    if(napt_exec(ip_packet, len, dev->ip_dev->napt_inside_dev, napt_protocol::icmp, napt_direction::incoming)){
                        napt_executed = true;
                    }
                    break;
            }
            if(napt_executed){
#ifdef ENABLE_MYBUF_NON_COPY_MODE
                my_buf *nat_fwd_buf = my_buf::create(0);
                nat_fwd_buf->buf_ptr = (uint8_t *) ip_packet;
                nat_fwd_buf->len = len;
#else
                my_buf* nat_fwd_buf = my_buf::create(len);
                memcpy(nat_fwd_buf->buffer, ip_packet, len);
                nat_fwd_buf->len = len;
#endif
                ip_output(ntohl(ip_packet->src_addr), ntohl(ip_packet->dest_addr), nat_fwd_buf);
                return;
            }
        }
    }
#endif

    // 上位プロトコルの処理に移行
    switch(ip_packet->protocol){
        case IP_PROTOCOL_TYPE_ICMP:
            /*
            // for book chapter 3
            LOG_IP("ICMP received!\n");
            return;
            */
            return icmp_input(
                    ntohl(ip_packet->src_addr),
                    ntohl(ip_packet->dest_addr),
                    ((uint8_t *) ip_packet) + IP_HEADER_SIZE,
                    len - IP_HEADER_SIZE
                    );

        case IP_PROTOCOL_TYPE_UDP:
#ifdef ENABLE_ICMP_ERROR
            send_icmp_destination_unreachable(input_dev->ip_dev->address, ntohl(ip_packet->src_addr), ICMP_DESTINATION_UNREACHABLE_CODE_PORT_UNREACHABLE, ip_packet, len);
#endif
            return;
        case IP_PROTOCOL_TYPE_TCP:
            // まだこのルータにはTCPを扱う機能はない
            return;

        default:

        LOG_IP("Unhandled ip protocol %04x", ip_packet->protocol);
            return;
    }
}


/**
 * IPパケットの受信処理
 * @param input_dev
 * @param buffer
 * @param len
 */
void ip_input(net_device *input_dev, uint8_t *buffer, ssize_t len){

    // IPアドレスのついていないインターフェースからの受信は無視
    if(input_dev->ip_dev == nullptr or input_dev->ip_dev->address == 0){
        return;
    }

    // IPヘッダ長より短かったらドロップ
    if(len < sizeof(ip_header)){
        LOG_IP("Received IP packet too short from %s\n", input_dev->ifname);
        return;
    }

    // 送られてきたバッファをキャストして扱う
    auto *ip_packet = reinterpret_cast<ip_header *>(buffer);

    LOG_IP("Received IP packet type %d from %s to %s\n", ip_packet->protocol,
           ip_ntoa(ip_packet->src_addr), ip_ntoa(ip_packet->dest_addr));

    if(ip_packet->version != 4){
        LOG_IP("Incorrect IP version\n");
        return;
    }

    // IPヘッダオプションがついていたらドロップ
    if(ip_packet->header_len != (sizeof(ip_header) >> 2)){
        LOG_IP("IP header option is not supported\n");
        return;
    }


    if(ip_packet->dest_addr == IP_ADDRESS_LIMITED_BROADCAST){ // 宛先アドレスがブロードキャストアドレスの場合
        return ip_input_to_ours(input_dev, ip_packet, len); // 自分宛の通信として処理
    }

    // 宛先IPアドレスがルータの持っているIPアドレスの時の処理
    for(net_device *dev = net_dev_list; dev; dev = dev->next){
        if(dev->ip_dev->address != IP_ADDRESS(0, 0, 0, 0)){
            if(htonl(dev->ip_dev->address) == ip_packet->dest_addr){ // TODO ブロードキャストを考慮
                return ip_input_to_ours(dev, ip_packet, len); // 自分宛の通信として処理
            }
        }
    }

#ifdef ENABLE_NAPT
    // NAPTの内側から外側への通信
    if(input_dev->ip_dev->napt_inside_dev != nullptr){ // TODO これNATしないLAN内通信できない?
        if(ip_packet->protocol == IP_PROTOCOL_TYPE_UDP){ // NAPTの対象
            if(!napt_exec(ip_packet, len, input_dev->ip_dev->napt_inside_dev, napt_protocol::udp, napt_direction::outgoing)){
                return; // NAPTできないパケットはドロップ
            }
        }else if(ip_packet->protocol == IP_PROTOCOL_TYPE_TCP){
            if(!napt_exec(ip_packet, len, input_dev->ip_dev->napt_inside_dev, napt_protocol::tcp, napt_direction::outgoing)){
                return; // NAPTできないパケットはドロップ
            }
        }else if(ip_packet->protocol == IP_PROTOCOL_TYPE_ICMP){
            if(!napt_exec(ip_packet, len, input_dev->ip_dev->napt_inside_dev, napt_protocol::icmp, napt_direction::outgoing)){
                return; // NAPTできないパケットはドロップ
            }
        }else{
            LOG_IP("NAPT unimplemented packet dropped type=%d\n", ip_packet->protocol);
            return; // NAPTできないパケットはドロップ

        }
    }
#endif

    //宛先IPアドレスがルータの持っているIPアドレスでない場合はフォワーディングを行う
    ip_route_entry *route = binary_trie_search(ip_fib, ntohl(ip_packet->dest_addr)); // ルーティングテーブルをルックアップ
    if(route == nullptr){ // 宛先までの経路がなかったらパケットを破棄
        LOG_IP("No route to %s\n", ip_htoa(ntohl(ip_packet->dest_addr)));
        // Drop packet
        return;
    }

    if(ip_packet->ttl <= 1){ // TTLが1以下ならドロップ
#ifdef ENABLE_ICMP_ERROR
        send_icmp_time_exceeded(input_dev->ip_dev->address, ntohl(ip_packet->src_addr), ICMP_TIME_EXCEEDED_CODE_TIME_TO_LIVE_EXCEEDED, buffer, len);
#endif
        return;
    }

    // TTLを1へらす
    ip_packet->ttl--;

    // IPヘッダチェックサムの再計算
    ip_packet->header_checksum = 0;
    ip_packet->header_checksum = checksum_16(reinterpret_cast<uint16_t *>(buffer), sizeof(ip_header));

#ifdef ENABLE_MYBUF_NON_COPY_MODE
    my_buf *ip_forward_buf = my_buf::create(0);
    ip_forward_buf->buf_ptr = buffer;
    ip_forward_buf->len = len;
#else
    // my_buf構造にコピー
    my_buf* ip_forward_buf = my_buf::create(len);
    memcpy(ip_forward_buf->buffer, buffer, len);
    ip_forward_buf->len = len;
#endif

    if(route->type == connected){ // 直接接続ネットワークの経路なら
        ip_output_to_host(route->device, ntohl(ip_packet->src_addr), ntohl(ip_packet->dest_addr), ip_forward_buf); // hostに直接送信
        return;
    }else if(route->type == network){ // 直接接続ネットワークの経路ではなかったら
        ip_output_to_next_hop(route->next_hop, ip_forward_buf); // next hopに送信
        return;
    }
}

/**
 * IPパケットを直接イーサネットでホストに送信
 * @param dev
 * @param src_addr
 * @param dest_addr
 * @param buffer
 */
void ip_output_to_host(net_device *dev, uint32_t src_addr, uint32_t dest_addr, my_buf *buffer){
    arp_table_entry *entry = search_arp_table_entry(dest_addr); // ARPテーブルの検索

    if(!entry){ // ARPエントリが無かったら
        LOG_IP("Trying ip output to host, but no arp record to %s\n", ip_htoa(dest_addr));
        //send_icmp_destination_unreachable(dev->ip_dev->address, src_addr, ICMP_DESTINATION_UNREACHABLE_CODE_HOST_UNREACHABLE, buffer->buf_ptr, 100);
        send_arp_request(dev, dest_addr); // ARPリクエストの送信
        my_buf::my_buf_free(buffer, true); // Drop packet
        return;
    }else{
        ethernet_encapsulate_output(entry->device, entry->mac_address, buffer, ETHERNET_TYPE_IP); // イーサネットでカプセル化して送信
    }
}

/**
 * IPパケットをnext hopに送信
 * @param next_hop
 * @param buffer
 */
void ip_output_to_next_hop(uint32_t next_hop, my_buf *buffer){

    arp_table_entry *entry = search_arp_table_entry(next_hop); // ARPテーブルの検索

    if(!entry){  // ARPエントリが無かったら
        LOG_IP("Trying ip output to next hop, but no arp record to %s\n", ip_htoa(next_hop));

        ip_route_entry *route_to_next_hop = binary_trie_search(ip_fib, next_hop); // ルーティングテーブルのルックアップ

        if(route_to_next_hop == nullptr or route_to_next_hop->type != connected){ // next hopへの到達性が無かったら
            LOG_IP("Next hop %s is not reachable\n", ip_htoa(next_hop));
        }else{
            send_arp_request(route_to_next_hop->device, next_hop); // ARPリクエストを送信
        }
        my_buf::my_buf_free(buffer, true); // Drop packet
        return;

    }else{ // ARPエントリがあったら
        ethernet_encapsulate_output(entry->device, entry->mac_address, buffer, ETHERNET_TYPE_IP); // イーサネットでカプセル化して送信
    }
}

/**
 * IPパケットを送信
 * @param src_addr
 * @param dest_addr
 * @param buffer
 */
void ip_output(uint32_t src_addr, uint32_t dest_addr, my_buf *buffer){

    ip_route_entry *route = binary_trie_search(ip_fib, dest_addr); // 経路を検索
    if(route == nullptr){ // 経路が見つからなかったら
        LOG_IP("No route to %s\n", ip_htoa(dest_addr));
        my_buf::my_buf_free(buffer, true); // Drop packet
        return;
    }

    if(route->type == connected){ // 直接接続ネットワークだったら
        ip_output_to_host(route->device, src_addr, dest_addr, buffer);
        return;
    }else if(route->type == network){ // 直接つながっていないネットワークだったら
        ip_output_to_next_hop(route->next_hop, buffer);
        return;
    }
}


/**
 * IPパケットにカプセル化して送信
 * @param dest_addr
 * @param src_addr
 * @param upper_layer_buffer
 * @param protocol_type
 */
void ip_encapsulate_output(uint32_t dest_addr, uint32_t src_addr, my_buf *upper_layer_buffer, uint8_t protocol_type){

    // IPヘッダで必要なIPパケットの全長を算出する
    uint16_t total_len = 0;
    my_buf *current_buffer = upper_layer_buffer;
    while(current_buffer != nullptr){
        total_len += current_buffer->len;
        current_buffer = current_buffer->next_my_buf;
    }

    // IPヘッダ用のバッファを確保する
    my_buf *ip_my_buf = my_buf::create(IP_HEADER_SIZE);
    upper_layer_buffer->add_header(ip_my_buf); // 上位プロトコルのデータにヘッダとして連結する

    // IPヘッダの各項目を設定
    auto *ip_buf = reinterpret_cast<ip_header *>(ip_my_buf->buffer);
    ip_buf->version = 4;
    ip_buf->header_len = sizeof(ip_header) >> 2;
    ip_buf->tos = 0;
    ip_buf->total_len = htons(sizeof(ip_header) + total_len);
    ip_buf->protocol = protocol_type; // 8bit

    static uint64_t id = 0;
    ip_buf->identify = id++;
    ip_buf->frag_offset = 0;
    ip_buf->ttl = 0xff;
    ip_buf->header_checksum = 0;
    ip_buf->dest_addr = htonl(dest_addr);
    ip_buf->src_addr = htonl(src_addr);
    ip_buf->header_checksum = checksum_16(reinterpret_cast<uint16_t *>(ip_my_buf->buffer), ip_my_buf->len);

    ip_output(src_addr, dest_addr, ip_my_buf);

    /*
    // for book chapter3 (IP ルーティング/フォワーディングが実装されてないとき用)
    for(net_device* dev = net_dev_list; dev; dev = dev->next){
        if(dev->ip_dev == nullptr or dev->ip_dev->address == IP_ADDRESS(0, 0, 0, 0)) continue;
        if(in_subnet(dev->ip_dev->address, dev->ip_dev->netmask, dest_addr)){
            // TODO: イーサネットアドレスを特定して送信
            arp_table_entry* entry;
            entry = search_arp_table_entry(dest_addr);
            if(entry == nullptr){
                LOG_IP("Trying ip output, but no arp record to %s\n", ip_htoa(dest_addr));
                send_arp_request(dev, dest_addr);
                my_buf::my_buf_free(upper_layer_buffer, true);
                return;
            }
            ethernet_encapsulate_output(dev, entry->mac_address, ip_my_buf, ETHERNET_TYPE_IP);
        }
    }
    */
}
