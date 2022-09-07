#include "nat.h"

#include "config.h"
#include "ip.h"
#include "log.h"
#include "net.h"
#include "my_buf.h"

/**
 * NATテーブルを出力する
 */
void dump_nat_tables(){
#ifdef ENABLE_NAPT
    printf("|-PROTO-|---------LOCAL---------|--------GLOBAL---------|\n");
    for(net_device *dev = net_dev_list; dev; dev = dev->next){
        if(dev->ip_dev != nullptr and dev->ip_dev->napt_inside_dev != nullptr){
            for(int i = 0; i < NAT_GLOBAL_PORT_SIZE; ++i){
                if(dev->ip_dev->napt_inside_dev->entries->tcp[i].global_port != 0){
                    printf("|  TCP  | %15s:%05d | %15s:%05d |\n",
                           ip_htoa(dev->ip_dev->napt_inside_dev->entries->tcp[i].local_address),
                           dev->ip_dev->napt_inside_dev->entries->tcp[i].local_port,
                           ip_htoa(dev->ip_dev->napt_inside_dev->entries->tcp[i].global_address),
                           dev->ip_dev->napt_inside_dev->entries->tcp[i].global_port
                    );
                }
                if(dev->ip_dev->napt_inside_dev->entries->udp[i].global_port != 0){
                    printf("|  UDP  | %15s:%05d | %15s:%05d |\n",
                           ip_htoa(dev->ip_dev->napt_inside_dev->entries->udp[i].local_address),
                           dev->ip_dev->napt_inside_dev->entries->udp[i].local_port,
                           ip_htoa(dev->ip_dev->napt_inside_dev->entries->udp[i].global_address),
                           dev->ip_dev->napt_inside_dev->entries->udp[i].global_port
                    );
                }
            }
            for(int i = 0; i < NAT_ICMP_ID_SIZE; ++i){
                if(dev->ip_dev->napt_inside_dev->entries->icmp[i].local_address != 0){
                    printf("|  ICMP | %15s:%05d | %15s:%05d |\n",
                           ip_htoa(dev->ip_dev->napt_inside_dev->entries->icmp[i].local_address),
                           dev->ip_dev->napt_inside_dev->entries->icmp[i].local_port,
                           ip_htoa(dev->ip_dev->napt_inside_dev->entries->icmp[i].global_address),
                           dev->ip_dev->napt_inside_dev->entries->icmp[i].global_port
                    );
                }
            }
        }
    }
    printf("|-------|-----------------------|-----------------------|\n");
#else
    printf("NAPT has not been enabled for this build\n");
#endif
}

/**
 * NATのアドレス変換を実行する
 * @param ip_packet　アドレス変換を行うパケット
 * @param len アドレス変換を行うパケットの残りの長さ
 * @param napt_dev NATデバイス
 * @param proto IPプロトコルタイプ(UDP,TCP,ICMPのみ対応)
 * @param direction NATの方向
 * @return NATが成功したかどうか
 */
bool nat_exec(ip_header *ip_packet, size_t len, nat_inside_device *napt_dev, nat_protocol proto, nat_direction direction){
    auto *napt_packet = (nat_packet_head *) ((uint8_t *) ip_packet + sizeof(ip_header));

    // ICMPだったら、クエリーパケットのみNATする
    if(proto == nat_protocol::icmp and napt_packet->icmp.header.type != ICMP_TYPE_ECHO_REQUEST and
       napt_packet->icmp.header.type != ICMP_TYPE_ECHO_REPLY){
        return false;
    }

    nat_entry *entry;
    if(direction == nat_direction::incoming){ // NATの外から内の通信の時
        if(proto == nat_protocol::icmp){ // ICMPの場合はIDを用いる
            entry = get_nat_entry_by_global(
                    napt_dev->entries, proto,
                    ntohl(ip_packet->dest_addr),
                    ntohs(napt_packet->icmp.identify));
        }else{ // UDP/TCPの時はポート番号
            entry = get_nat_entry_by_global(
                    napt_dev->entries, proto,
                    ntohl(ip_packet->dest_addr),
                    ntohs(napt_packet->dest_port));
        }
        if(entry == nullptr){ // NAPTエントリが登録されていない場合、falseを返す
            return false;
        }
    }else{ // NATの内から外の通信の時
        if(proto == nat_protocol::icmp){ // ICMP
            entry = get_nat_entry_by_local(
                    napt_dev->entries, proto,
                    ntohl(ip_packet->src_addr),
                    ntohs(napt_packet->icmp.identify));
        }else{ // TCP/UDP
            entry = get_nat_entry_by_local(
                    napt_dev->entries, proto,
                    ntohl(ip_packet->src_addr),
                    ntohs(napt_packet->src_port));
        }
        if(entry == nullptr){
            entry = create_nat_entry(
                    napt_dev->entries, proto); // NAPTテーブルエントリの作成
            if(entry == nullptr){
                LOG_NAT("NAPT table is full!\n");
                return false;
            }
            LOG_NAT("Created new nat table entry global port %d\n", entry->global_port);
            entry->global_address = napt_dev->outside_address;
            entry->local_address = ntohl(ip_packet->src_addr);
            if(proto == nat_protocol::icmp){
                entry->local_port = ntohs(napt_packet->icmp.identify);
            }else{
                entry->local_port = ntohs(napt_packet->src_port);
            }
        }
    }

    uint32_t checksum;
    if(proto == nat_protocol::icmp){
        checksum = napt_packet->icmp.header.checksum;
        checksum = ~checksum;
        checksum -= napt_packet->icmp.identify;
        if(direction == nat_direction::incoming){
            checksum += htons(entry->local_port);
        }else{
            checksum += htons(entry->global_port);
        }
    }else{
        //
        if(proto == nat_protocol::udp){ // UDP
            checksum = napt_packet->udp.checksum;
        }else{ // TCP
            checksum = napt_packet->tcp.checksum;
        }
        checksum = ~checksum;

        // checksumの差分の計算
        if(direction == nat_direction::incoming){
            checksum -= ip_packet->dest_addr & 0xffff;
            checksum -= ip_packet->dest_addr >> 16;
            checksum -= napt_packet->dest_port;
            checksum += htonl(entry->local_address) & 0xffff;
            checksum += htonl(entry->local_address) >> 16;
            checksum += htons(entry->local_port);
        }else{
            checksum -= ip_packet->src_addr & 0xffff;
            checksum -= ip_packet->src_addr >> 16;
            checksum -= napt_packet->src_port;
            checksum += htonl(napt_dev->outside_address) & 0xffff;
            checksum += htonl(napt_dev->outside_address) >> 16;
            checksum += htons(entry->global_port);
        }
    }
    checksum = ~checksum;

    if(checksum > 0xffff){
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }

    if(proto == nat_protocol::icmp){ // ICMP
        napt_packet->icmp.header.checksum = checksum;
    }else if(proto == nat_protocol::udp){ // UDP
        napt_packet->udp.checksum = checksum;
    }else{ // TCP
        napt_packet->tcp.checksum = checksum;
    }
    if(direction == nat_direction::incoming){
        ip_packet->dest_addr = htonl(entry->local_address);
        if(proto == nat_protocol::icmp){ // ICMP
            napt_packet->icmp.identify = htons(entry->local_port);
        }else{ // UDP/TCP
            napt_packet->dest_port = htons(entry->local_port);
        }
    }else{
        ip_packet->src_addr = htonl(napt_dev->outside_address);
        if(proto == nat_protocol::icmp){ // ICMP
            napt_packet->icmp.identify = htons(entry->global_port);
        }else{ // UDP/TCP
            napt_packet->src_port = htons(entry->global_port);
        }
    }

    // IPヘッダのヘッダチェックサムの再計算
    ip_packet->header_checksum = 0;
    ip_packet->header_checksum = checksum_16(reinterpret_cast<uint16_t *>(ip_packet), sizeof(ip_header));

    return true;
}

/**
 * グローバルアドレスとグローバルポートからNATエントリを取得
 * @param entries
 * @param proto
 * @param address
 * @param id
 * @return
 */
nat_entry *get_nat_entry_by_global(nat_entries *entries, nat_protocol proto, uint32_t address, uint16_t id){
    if(proto == nat_protocol::udp){ // UDPの場合
        if(entries->udp[id - NAT_GLOBAL_PORT_MIN].global_address == address and entries->udp[id - NAT_GLOBAL_PORT_MIN].global_port == id){
            return &entries->udp[id - NAT_GLOBAL_PORT_MIN];
        }
    }else if(proto == nat_protocol::tcp){
        if(entries->tcp[id - NAT_GLOBAL_PORT_MIN].global_address == address and entries->tcp[id - NAT_GLOBAL_PORT_MIN].global_port == id){
            return &entries->tcp[id - NAT_GLOBAL_PORT_MIN];
        }
    }else if(proto == nat_protocol::icmp){

        // NATテーブルエントリがグローバルIPアドレス、ICMPのIDが一致しているか調べる
        if(entries->icmp[id].global_address == address and entries->icmp[id].global_port == id){
            return &entries->icmp[id];
        }
    }
    return nullptr;
}

/**
 * ローカルアドレスとローカルポートからNATエントリを取得
 * @param entries
 * @param proto
 * @param address
 * @param port
 * @return
 */
nat_entry *get_nat_entry_by_local(nat_entries *entries, nat_protocol proto, uint32_t address, uint16_t port){
    if(proto == nat_protocol::udp){ // UDPの場合
        // UDPのNATテーブルをローカルIPアドレス, ローカルポートで検索する
        for(int i = 0; i < NAT_GLOBAL_PORT_SIZE; ++i){
            if(entries->udp[i].local_address == address and entries->udp[i].local_port == port){
                return &entries->udp[i];
            }
        }
    }else if(proto == nat_protocol::tcp){ // TCPの場合
        // TCPのNATテーブルをローカルIPアドレス, ローカルポートで検索する
        for(int i = 0; i < NAT_GLOBAL_PORT_SIZE; ++i){
            if(entries->tcp[i].local_address == address and entries->tcp[i].local_port == port){
                return &entries->tcp[i];
            }
        }
    }else if(proto == nat_protocol::icmp){ // ICMPの場合
        // ICMPのNATテーブルをローカルIPアドレス、ICMPのIDで検索する
        for(int i = 0; i < NAT_ICMP_ID_SIZE; ++i){
            if(entries->icmp[i].local_address == address and entries->icmp[i].local_port == port){
                return &entries->icmp[i];
            }
        }
    }
    return nullptr; // テーブルに一致するエントリがなかったらnullptrを返す
}

/**
 * 空いてるポートを探し、NATエントリを作成する
 * @param entries
 * @param proto
 * @return
 */
nat_entry *create_nat_entry(nat_entries *entries, nat_protocol proto){
    if(proto == nat_protocol::udp){ // UDPの場合
        for(int i = 0; i < NAT_GLOBAL_PORT_SIZE; ++i){ // NATテーブルのサイズ分
            if(entries->udp[i].global_address == 0){
                // 空いてるエントリが見つかったら、グローバルポートを設定してエントリを返す
                entries->udp[i].global_port = NAT_GLOBAL_PORT_MIN + i;
                return &entries->udp[i];
            }
        }
    }else if(proto == nat_protocol::tcp){
        for(int i = 0; i < NAT_GLOBAL_PORT_SIZE; ++i){
            if(entries->tcp[i].global_address == 0){
                entries->tcp[i].global_port = NAT_GLOBAL_PORT_MIN + i;
                return &entries->tcp[i];
            }
        }
    }else if(proto == nat_protocol::icmp){
        for(int i = 0; i < NAT_ICMP_ID_SIZE; ++i){
            if(entries->icmp[i].global_address == 0){
                entries->icmp[i].global_port = i;
                return &entries->icmp[i];
            }
        }
    }
    return nullptr; // 空いているエントリがなかったら
}
