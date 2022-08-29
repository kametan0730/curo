#include "napt.h"

#include "config.h"
#include "net.h"
#include "my_buf.h"

void dump_napt_tables(){
#ifdef ENABLE_NAPT
    printf("|-PROTO-|--------SOURCE---------|------DESTINATION------|\n");
    net_device *a;
    for(a = net_dev_list; a; a = a->next){
        if(a->ip_dev != nullptr and a->ip_dev->napt_inside_dev != nullptr){

            for(int i = 0; i < NAPT_GLOBAL_PORT_SIZE; ++i){
                if(a->ip_dev->napt_inside_dev->entries->tcp[i].global_port != 0){
                    printf("|  TCP  | %15s:%05d | %15s:%05d |\n",
                           inet_htoa(a->ip_dev->napt_inside_dev->entries->tcp[i].local_address),
                           a->ip_dev->napt_inside_dev->entries->tcp[i].local_port,
                           inet_htoa(a->ip_dev->napt_inside_dev->entries->tcp[i].global_address),
                           a->ip_dev->napt_inside_dev->entries->tcp[i].global_port
                    );
                }
                if(a->ip_dev->napt_inside_dev->entries->udp[i].global_port != 0){
                    printf("|  UDP  | %15s:%05d | %15s:%05d |\n",
                           inet_htoa(a->ip_dev->napt_inside_dev->entries->udp[i].local_address),
                           a->ip_dev->napt_inside_dev->entries->udp[i].local_port,
                           inet_htoa(a->ip_dev->napt_inside_dev->entries->udp[i].global_address),
                           a->ip_dev->napt_inside_dev->entries->udp[i].global_port
                    );
                }
            }
            for(int i = 0; i < NAPT_ICMP_ID_SIZE; ++i){
                if(a->ip_dev->napt_inside_dev->entries->icmp[i].local_address != 0){
                    printf("|  ICMP | %15s:%05d | %15s:%05d |\n",
                           inet_htoa(a->ip_dev->napt_inside_dev->entries->icmp[i].local_address),
                           a->ip_dev->napt_inside_dev->entries->icmp[i].local_port,
                           inet_htoa(a->ip_dev->napt_inside_dev->entries->icmp[i].global_address),
                           a->ip_dev->napt_inside_dev->entries->icmp[i].global_port
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


bool napt_exec(ip_header *ip_packet, size_t len, napt_inside_device *napt_dev, napt_protocol proto, napt_direction direction){

    auto *napt_packet = (napt_packet_head *) ((uint8_t *) ip_packet + sizeof(ip_header));

    // ICMPだったら、クエリーパケットのみNATする
    if(proto == napt_protocol::icmp and napt_packet->icmp.header.type != ICMP_TYPE_ECHO_REQUEST and
       napt_packet->icmp.header.type != ICMP_TYPE_ECHO_REPLY){
        return false;
    }

    napt_entry *entry;
    if(direction == napt_direction::incoming){ // NATの外から内の通信の時
        if(proto == napt_protocol::icmp){ // ICMPの場合はIDを用いる
            entry = get_napt_entry_by_global(napt_dev->entries, proto, ntohl(ip_packet->dest_addr), ntohs(napt_packet->icmp.identify));
        }else{ // UDP/TCPの時はポート番号
            entry = get_napt_entry_by_global(napt_dev->entries, proto, ntohl(ip_packet->dest_addr), ntohs(napt_packet->dest_port));
        }
        if(entry == nullptr){ // NAPTエントリが登録されていない場合、falseを返す
            return false;
        }
    }else{ //  // NATの内から外の通信の時
        if(proto == napt_protocol::icmp){ // ICMP
            entry = get_napt_entry_by_local(napt_dev->entries, proto, ntohl(ip_packet->src_addr), ntohs(napt_packet->icmp.identify));
        }else{ // TCP/UDP
            entry = get_napt_entry_by_local(napt_dev->entries, proto, ntohl(ip_packet->src_addr), ntohs(napt_packet->src_port));
        }
        if(entry == nullptr){
            entry = create_napt_entry(napt_dev->entries, proto); // NAPTテーブルエントリの作成
            if(entry == nullptr){
                LOG_NAT("NAPT table is full!\n");
                return false;
            }
            LOG_NAT("Created new nat table entry global port %d\n", entry->global_port);
            entry->global_address = napt_dev->outside_address;
            entry->local_address = ntohl(ip_packet->src_addr);
            if(proto == napt_protocol::icmp){
                entry->local_port = ntohs(napt_packet->icmp.identify);
            }else{
                entry->local_port = ntohs(napt_packet->src_port);
            }
        }
    }

    uint32_t checksum;
    if(proto == napt_protocol::icmp){
        checksum = napt_packet->icmp.header.checksum;
        checksum = ~checksum;
        checksum -= napt_packet->icmp.identify;
        if(direction == napt_direction::incoming){
            checksum += htons(entry->local_port);
        }else{
            checksum += htons(entry->global_port);
        }
    }else{
        //
        if(proto == napt_protocol::udp){ // UDP
            checksum = napt_packet->udp.checksum;
        }else{ // TCP
            checksum = napt_packet->tcp.checksum;
        }
        checksum = ~checksum;

        // checksumの差分の計算
        if(direction == napt_direction::incoming){
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

    if(proto == napt_protocol::icmp){ // ICMP
        napt_packet->icmp.header.checksum = checksum;
    }else if(proto == napt_protocol::udp){ // UDP
        napt_packet->udp.checksum = checksum;
    }else{ // TCP
        napt_packet->tcp.checksum = checksum;
    }
    if(direction == napt_direction::incoming){
        ip_packet->dest_addr = htonl(entry->local_address);
        if(proto == napt_protocol::icmp){ // ICMP
            napt_packet->icmp.identify = htons(entry->local_port);
        }else{ // UDP/TCP
            napt_packet->dest_port = htons(entry->local_port);
        }
    }else{
        ip_packet->src_addr = htonl(napt_dev->outside_address);
        if(proto == napt_protocol::icmp){ // ICMP
            //LOG_NAT("Address port translation executed %s:%d => %s:%d\n", inet_ntoa(ip_packet->src_addr), ntohs(napt_packet->icmp.identify), inet_htoa(napt_dev->outside_address), entry->global_port);
            napt_packet->icmp.identify = htons(entry->global_port);
        }else{ // UDP/TCP
            napt_packet->src_port = htons(entry->global_port);
        }
    }

    // IPヘッダのヘッダチェックサムの再計算
    ip_packet->header_checksum = 0;
    ip_packet->header_checksum = calc_checksum_16(reinterpret_cast<uint16_t *>(ip_packet), sizeof(ip_header));

    return true;
}

napt_entry *get_napt_entry_by_global(napt_entries *entries, napt_protocol proto, uint32_t address, uint16_t port){


    if(proto == napt_protocol::udp){
        if(entries->udp[port - NAPT_GLOBAL_PORT_MIN].global_address == address and entries->udp[port - NAPT_GLOBAL_PORT_MIN].global_port == port){
            return &entries->udp[port] - NAPT_GLOBAL_PORT_MIN;
        }
    }else if(proto == napt_protocol::tcp){
        if(entries->tcp[port - NAPT_GLOBAL_PORT_MIN].global_address == address and entries->tcp[port - NAPT_GLOBAL_PORT_MIN].global_port == port){
            return &entries->tcp[port - NAPT_GLOBAL_PORT_MIN];
        }
    }else if(proto == napt_protocol::icmp){
        if(entries->icmp[port].global_address == address and entries->icmp[port].global_port == port){
            return &entries->icmp[port];
        }
    }
    return nullptr;
}

napt_entry *get_napt_entry_by_local(napt_entries *entries, napt_protocol proto, uint32_t address, uint16_t port){

    if(proto == napt_protocol::udp){
        for(int i = 0; i < NAPT_GLOBAL_PORT_SIZE; ++i){
            if(entries->udp[i].local_address == address and entries->udp[i].local_port == port){
                return &entries->udp[i];
            }
        }
    }else if(proto == napt_protocol::tcp){
        for(int i = 0; i < NAPT_GLOBAL_PORT_SIZE; ++i){
            if(entries->tcp[i].local_address == address and entries->tcp[i].local_port == port){
                return &entries->tcp[i];
            }
        }
    }else if(proto == napt_protocol::icmp){
        for(int i = 0; i < NAPT_ICMP_ID_SIZE; ++i){
            if(entries->icmp[i].local_address == address and entries->icmp[i].local_port == port){
                return &entries->icmp[i];
            }
        }
    }
    return nullptr;
}

napt_entry *create_napt_entry(napt_entries *entries, napt_protocol proto){
    if(proto == napt_protocol::udp){
        for(int i = 0; i < NAPT_GLOBAL_PORT_SIZE; ++i){
            if(entries->udp[i].global_address == 0){
                entries->udp[i].global_port = NAPT_GLOBAL_PORT_MIN + i;
                return &entries->udp[i];
            }
        }
    }else if(proto == napt_protocol::tcp){
        for(int i = 0; i < NAPT_GLOBAL_PORT_SIZE; ++i){
            if(entries->tcp[i].global_address == 0){
                entries->tcp[i].global_port = NAPT_GLOBAL_PORT_MIN + i;
                return &entries->tcp[i];
            }
        }
    }else if(proto == napt_protocol::icmp){
        for(int i = 0; i < NAPT_ICMP_ID_SIZE; ++i){
            if(entries->icmp[i].global_address == 0){
                entries->icmp[i].global_port = i;
                return &entries->icmp[i];
            }
        }
    }
    return nullptr;
}
