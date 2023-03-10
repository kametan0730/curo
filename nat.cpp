#include "nat.h"

#include "config.h"
#include "ip.h"
#include "log.h"
#include "my_buf.h"
#include "net.h"

/**
 * NATテーブルを出力する
 */
void dump_nat_tables() {
#ifdef ENABLE_NAT
    printf("|-PROTO-|---------LOCAL---------|--------GLOBAL---------|\n");
    for (net_device *dev = net_dev_list; dev; dev = dev->next) {
        if (dev->ip_dev != nullptr and dev->ip_dev->nat_dev != nullptr) {
            for (int i = 0; i < NAT_GLOBAL_PORT_SIZE; ++i) {
                if (dev->ip_dev->nat_dev->entries->tcp[i].global_port != 0) {
                    printf(
                        "|  TCP  | %15s:%05d | %15s:%05d |\n",
                        ip_htoa(
                            dev->ip_dev->nat_dev->entries->tcp[i].local_addr),
                        dev->ip_dev->nat_dev->entries->tcp[i].local_port,
                        ip_htoa(
                            dev->ip_dev->nat_dev->entries->tcp[i].global_addr),
                        dev->ip_dev->nat_dev->entries->tcp[i].global_port);
                }
                if (dev->ip_dev->nat_dev->entries->udp[i].global_port != 0) {
                    printf(
                        "|  UDP  | %15s:%05d | %15s:%05d |\n",
                        ip_htoa(
                            dev->ip_dev->nat_dev->entries->udp[i].local_addr),
                        dev->ip_dev->nat_dev->entries->udp[i].local_port,
                        ip_htoa(
                            dev->ip_dev->nat_dev->entries->udp[i].global_addr),
                        dev->ip_dev->nat_dev->entries->udp[i].global_port);
                }
            }
            for (int i = 0; i < NAT_ICMP_ID_SIZE; ++i) {
                if (dev->ip_dev->nat_dev->entries->icmp[i].local_addr != 0) {
                    printf(
                        "|  ICMP | %15s:%05d | %15s:%05d |\n",
                        ip_htoa(
                            dev->ip_dev->nat_dev->entries->icmp[i].local_addr),
                        dev->ip_dev->nat_dev->entries->icmp[i].local_port,
                        ip_htoa(
                            dev->ip_dev->nat_dev->entries->icmp[i].global_addr),
                        dev->ip_dev->nat_dev->entries->icmp[i].global_port);
                }
            }
        }
    }
    printf("|-------|-----------------------|-----------------------|\n");
#else
    printf("NAT has not been enabled for this build\n");
#endif
}

/**
 * NATのアドレス変換を実行する
 * @param ip_packet　アドレス変換を行うパケット
 * @param len アドレス変換を行うパケットの残りの長さ
 * @param nat_dev NATデバイス
 * @param proto IPプロトコルタイプ(UDP,TCP,ICMPのみ対応)
 * @param direction NATの方向
 * @return NATが成功したかどうか
 */
bool nat_exec(ip_header *ip_packet, size_t len, nat_device *nat_dev,
              nat_protocol proto, nat_direction direction) {
    nat_packet_head *nat_packet;
    nat_packet = (nat_packet_head *)((uint8_t *)ip_packet + sizeof(ip_header));
    // ICMPだったら、クエリーパケットのみNATする
    if (proto == nat_protocol::icmp and
        nat_packet->icmp.header.type != ICMP_TYPE_ECHO_REQUEST and
        nat_packet->icmp.header.type != ICMP_TYPE_ECHO_REPLY) {
        if (nat_packet->icmp.header.type == ICMP_TYPE_TIME_EXCEEDED or
            nat_packet->icmp.header.type == ICMP_TYPE_DESTINATION_UNREACHABLE) {
            proto = nat_protocol::icmp_error;
        } else {
            return false;
        }
    }

    nat_entry *entry;
    if (direction == nat_direction::incoming) { // NATの外から内の通信の時
        if (proto == nat_protocol::icmp) { // ICMPの場合はIDを用いる
            entry = get_nat_entry_by_global(nat_dev->entries, proto,
                                            ntohl(ip_packet->dest_addr),
                                            ntohs(nat_packet->icmp.identify));
        } else if (proto == nat_protocol::icmp_error) { // ICMPエラーの場合、エラーパケットの中身を用いる

            if (len < sizeof(ip_header) + sizeof(icmp_dest_unreachable) + sizeof(ip_header) + sizeof(uint16_t) * 2) {
                return false;
            }

            if (nat_packet->icmp_error.error_iph.protocol == IP_PROTOCOL_NUM_UDP) {
                entry = get_nat_entry_by_global(
                    nat_dev->entries, nat_protocol::udp,
                    ntohl(nat_packet->icmp_error.error_iph.src_addr),
                    ntohs(nat_packet->icmp_error.src_port));
            } else if (nat_packet->icmp_error.error_iph.protocol == IP_PROTOCOL_NUM_TCP) {
                entry = get_nat_entry_by_global(
                    nat_dev->entries, nat_protocol::tcp,
                    ntohl(nat_packet->icmp_error.error_iph.src_addr),
                    ntohs(nat_packet->icmp_error.src_port));
            } else { // UDP/TCP以外の場合、扱えないのでfalseを返す
                LOG_NAT("Unsupported nat error ip packet protocol\n");
                return false;
            }
        } else { // UDP/TCPの時はポート番号
            entry = get_nat_entry_by_global(nat_dev->entries, proto,
                                            ntohl(ip_packet->dest_addr),
                                            ntohs(nat_packet->dest_port));
        }
        if (entry == nullptr) { // NATエントリが登録されていない場合、falseを返す
            return false;
        }
    } else { // NATの内から外の通信の時
        if (proto == nat_protocol::icmp) { // ICMP
            entry = get_nat_entry_by_local(nat_dev->entries, proto,
                                           ntohl(ip_packet->src_addr),
                                           ntohs(nat_packet->icmp.identify));
        } else if (proto == nat_protocol::icmp_error) {
            LOG_NAT("Outgoing icmp error is not supported\n");
            return false;
        } else { // TCP/UDP
            entry = get_nat_entry_by_local(nat_dev->entries, proto,
                                           ntohl(ip_packet->src_addr),
                                           ntohs(nat_packet->src_port));
        }
        if (entry == nullptr) {

            if (proto == nat_protocol::icmp) { // ICMP
                entry = create_nat_entry(
                    nat_dev->entries, proto,
                    ntohs(nat_packet->icmp.identify)); // NATテーブルエントリの作成
            } else if (proto == nat_protocol::icmp_error) {
                return false; // ICMPエラーの場合、そのエラーの元となったパケットのエントリがないと通過できないので、エントリの新規作成は行わない
            } else { // TCP/UDP
                entry = create_nat_entry(
                    nat_dev->entries, proto,
                    ntohs(nat_packet->src_port)); // NATテーブルエントリの作成
            }

            if (entry == nullptr) {
                LOG_NAT("NAT table is full!\n");
                return false;
            }
            LOG_NAT("Created new nat table entry global port %d\n",
                    entry->global_port);
            entry->global_addr = nat_dev->outside_addr;
            entry->local_addr = ntohl(ip_packet->src_addr);
            if (proto == nat_protocol::icmp) {
                entry->local_port = ntohs(nat_packet->icmp.identify);
            } else {
                entry->local_port = ntohs(nat_packet->src_port);
            }
        }
    }

    uint32_t checksum;
    if (proto == nat_protocol::icmp) {
        checksum = nat_packet->icmp.header.checksum;
        checksum = ~checksum;
        checksum -= nat_packet->icmp.identify;
        if (direction == nat_direction::incoming) {
            checksum += htons(entry->local_port);
        } else {
            checksum += htons(entry->global_port);
        }
    }else if(proto == nat_protocol::icmp_error){

        checksum = nat_packet->icmp.header.checksum;
        checksum = ~checksum;

        // only incoming
        checksum -= nat_packet->icmp_error.error_iph.src_addr & 0xffff;
        checksum -= nat_packet->icmp_error.error_iph.src_addr >> 16;
        checksum += htonl(entry->local_addr) & 0xffff;
        checksum += htonl(entry->local_addr) >> 16;

        checksum -= htons(entry->global_port);
        checksum += htons(entry->local_port);

    } else { // UDP/TCP
        if (proto == nat_protocol::udp) { // UDP
            checksum = nat_packet->udp.checksum;
        } else { // TCP
            checksum = nat_packet->tcp.checksum;
        }
        checksum = ~checksum;
        // checksumの差分の計算
        if (direction == nat_direction::incoming) {
            checksum -= ip_packet->dest_addr & 0xffff;
            checksum -= ip_packet->dest_addr >> 16;
            checksum -= nat_packet->dest_port;
            checksum += htonl(entry->local_addr) & 0xffff;
            checksum += htonl(entry->local_addr) >> 16;
            checksum += htons(entry->local_port);
        } else {
            checksum -= ip_packet->src_addr & 0xffff;
            checksum -= ip_packet->src_addr >> 16;
            checksum -= nat_packet->src_port;
            checksum += htonl(nat_dev->outside_addr) & 0xffff;
            checksum += htonl(nat_dev->outside_addr) >> 16;
            checksum += htons(entry->global_port);
        }
    }
    checksum = ~checksum;

    if (checksum > 0xffff) {
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }

    // checksumの書き換え
    if (proto == nat_protocol::icmp) { // ICMP
        nat_packet->icmp.header.checksum = checksum;
    } else if (proto == nat_protocol::icmp_error) { // ICMP Error
        nat_packet->icmp.header.checksum = checksum;
    } else if (proto == nat_protocol::udp) { // UDP
        nat_packet->udp.checksum = checksum;
    } else { // TCP
        nat_packet->tcp.checksum = checksum;
    }

    // アドレスなどの書き換え
    if (direction == nat_direction::incoming) {
        ip_packet->dest_addr = htonl(entry->local_addr);
        if (proto == nat_protocol::icmp) { // ICMP
            nat_packet->icmp.identify = htons(entry->local_port);
        } else if (proto == nat_protocol::icmp_error) { // ICMPエラー
            nat_packet->icmp_error.error_iph.src_addr = htonl(entry->local_addr);
            nat_packet->icmp_error.src_port = htons(entry->local_port);
            // TODO エラーパケットのIPヘッダchecksumも更新した方良いかも
        } else { // UDP/TCP
            nat_packet->dest_port = htons(entry->local_port);
        }
    } else {
        ip_packet->src_addr = htonl(nat_dev->outside_addr);
        if (proto == nat_protocol::icmp) { // ICMP
            nat_packet->icmp.identify = htons(entry->global_port);
        } else if (proto == nat_protocol::icmp_error) { // ICMPエラー
            // Outgoinには非対応
        } else { // UDP/TCP
            nat_packet->src_port = htons(entry->global_port);
        }
    }

    // IPヘッダのヘッダチェックサムの再計算
    ip_packet->header_checksum = 0;
    ip_packet->header_checksum = checksum_16(reinterpret_cast<uint16_t *>(ip_packet), sizeof(ip_header));

    return true;
}

/**
 * グローバルアドレスとグローバルポートからNATエントリを取得
 */
nat_entry *get_nat_entry_by_global(nat_entries *entries, nat_protocol proto,
                                   uint32_t addr, uint16_t port) {
    if (proto == nat_protocol::udp) { // UDPの場合
        if (entries->udp[port - NAT_GLOBAL_PORT_MIN].global_addr == addr and
            entries->udp[port - NAT_GLOBAL_PORT_MIN].global_port == port) {
            return &entries->udp[port - NAT_GLOBAL_PORT_MIN];
        }
    } else if (proto == nat_protocol::tcp) {
        if (entries->tcp[port - NAT_GLOBAL_PORT_MIN].global_addr == addr and
            entries->tcp[port - NAT_GLOBAL_PORT_MIN].global_port == port) {
            return &entries->tcp[port - NAT_GLOBAL_PORT_MIN];
        }
    } else if (proto == nat_protocol::icmp) {
        // NATテーブルエントリがグローバルIPアドレス、ICMPのIDが一致しているか調べる
        if (entries->icmp[port].global_addr == addr and
            entries->icmp[port].global_port == port) {
            return &entries->icmp[port];
        }
    }
    return nullptr;
}

/**
 * ローカルアドレスとローカルポートからNATエントリを取得
 */
nat_entry *get_nat_entry_by_local(nat_entries *entries, nat_protocol proto,
                                  uint32_t addr, uint16_t port) {
    if (proto == nat_protocol::udp) { // UDPの場合
        // UDPのNATテーブルをローカルIPアドレス, ローカルポートで検索する
        for (int i = 0; i < NAT_GLOBAL_PORT_SIZE; ++i) {
            if (entries->udp[i].local_addr == addr and
                entries->udp[i].local_port == port) {
                return &entries->udp[i];
            }
        }
    } else if (proto == nat_protocol::tcp) { // TCPの場合
        // TCPのNATテーブルをローカルIPアドレス, ローカルポートで検索する
        for (int i = 0; i < NAT_GLOBAL_PORT_SIZE; ++i) {
            if (entries->tcp[i].local_addr == addr and
                entries->tcp[i].local_port == port) {
                return &entries->tcp[i];
            }
        }
    } else if (proto == nat_protocol::icmp) { // ICMPの場合
        // ICMPのNATテーブルをローカルIPアドレス、ICMPのIDで検索する
        for (int i = 0; i < NAT_ICMP_ID_SIZE; ++i) {
            if (entries->icmp[i].local_addr == addr and
                entries->icmp[i].local_port == port) {
                return &entries->icmp[i];
            }
        }
    }
    return nullptr; // テーブルに一致するエントリがなかったらnullptrを返す
}

/**
 * 空いてるポートを探し、NATエントリを作成する
 */
nat_entry *create_nat_entry(nat_entries *entries, nat_protocol proto,
                            uint16_t desired) {


    do {
        if (proto == nat_protocol::udp) { // UDPの場合

            if (desired < NAT_GLOBAL_PORT_MIN or
                NAT_GLOBAL_PORT_MAX < desired) {
                break;
            }

            if (entries->udp[desired - NAT_GLOBAL_PORT_MIN].global_port == 0) {
                entries->udp[desired - NAT_GLOBAL_PORT_MIN].global_port =
                    desired;
                return &entries->udp[desired - NAT_GLOBAL_PORT_MIN];
            }
        } else if (proto == nat_protocol::tcp) {
            if (desired < NAT_GLOBAL_PORT_MIN or
                NAT_GLOBAL_PORT_MAX < desired) {
                break;
            }

            if (entries->tcp[desired - NAT_GLOBAL_PORT_MIN].global_port == 0) {
                entries->tcp[desired - NAT_GLOBAL_PORT_MIN].global_port =
                    desired;
                return &entries->tcp[desired - NAT_GLOBAL_PORT_MIN];
            }

        } else if (proto == nat_protocol::icmp) {
            if (NAT_ICMP_ID_SIZE < desired) {
                break;
            }

            if (entries->icmp[desired].global_addr == 0) {
                entries->icmp[desired].global_port = desired;
                return &entries->icmp[desired];
            }
        }

    } while (0);



    if (proto == nat_protocol::udp) { // UDPの場合
        for (int i = 0; i < NAT_GLOBAL_PORT_SIZE;
             ++i) { // NATテーブルのサイズ分
            if (entries->udp[i].global_addr == 0) {
                // 空いてるエントリが見つかったら、グローバルポートを設定してエントリを返す
                entries->udp[i].global_port = NAT_GLOBAL_PORT_MIN + i;
                return &entries->udp[i];
            }
        }
    } else if (proto == nat_protocol::tcp) {
        for (int i = 0; i < NAT_GLOBAL_PORT_SIZE; ++i) {
            if (entries->tcp[i].global_addr == 0) {
                entries->tcp[i].global_port = NAT_GLOBAL_PORT_MIN + i;
                return &entries->tcp[i];
            }
        }
    } else if (proto == nat_protocol::icmp) {
        for (int i = 0; i < NAT_ICMP_ID_SIZE; ++i) {
            if (entries->icmp[i].global_addr == 0) {
                entries->icmp[i].global_port = i;
                return &entries->icmp[i];
            }
        }
    }
    return nullptr; // 空いているエントリがなかったら
}
