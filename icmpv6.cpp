#include "icmpv6.h"

#include "config.h"
#include "ipv6.h"
#include "log.h"
#include "my_buf.h"
#include "nd.h"
#include "net.h"
#include "utils.h"
#include <cstring>

/**
 * ICMPv6パケットの受信処理
 * @param source
 * @param destination
 * @param buffer
 * @param len
 */
void icmpv6_input(ipv6_device* v6dev, ipv6_addr source, ipv6_addr destination, void *buffer, size_t len) {
    icmpv6_hdr *icmp_pkt = reinterpret_cast<icmpv6_hdr *>(buffer);
    LOG_IPV6("icmpv6 code=%d, type=%d\n", icmp_pkt->code, icmp_pkt->type);

    switch(icmp_pkt->type){
        case ICMPV6_TYPE_NEIGHBOR_SOLICIATION:{
            if (len < sizeof(icmpv6_na)) {
                LOG_IPV6("Received neighbor solicitation packet too short\n");
                return;
            }

            icmpv6_na *nspkt = reinterpret_cast<icmpv6_na *>(buffer);

            LOG_IPV6("Ns target %s\n", ipv6toascii(nspkt->target_addr));

            if(memcmp(&nspkt->target_addr, &v6dev->address, 16) == 0){
                LOG_IPV6("Ns target math! %s\n", ipv6toascii(nspkt->target_addr));
                
                add_nd_table_entry(v6dev->net_dev, nspkt->opt_mac_addr, source);

                my_buf *icmpv6_mybuf = my_buf::create(sizeof(icmpv6_na));
                icmpv6_na *napkt = (icmpv6_na *) icmpv6_mybuf->buffer;

                napkt->hdr.code = 0;
                napkt->hdr.type = ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT;
                napkt->hdr.checksum = 0;
                napkt->flags = ICMPV6_NA_FLAG_SOLICITED | ICMPV6_NA_FLAG_OVERRIDE;
                napkt->target_addr = nspkt->target_addr;

                napkt->opt_type = 2;
                napkt->opt_length = 1;
                memcpy(&napkt->opt_mac_addr, v6dev->net_dev->mac_addr, 6);

                ipv6_pseudo_header phdr;
                phdr.src_addr = v6dev->address;
                phdr.dest_addr = source;
                phdr.packet_length = htonl(sizeof(icmpv6_na));
                phdr.zero1 = 0;
                phdr.zero2 = 0;
                phdr.next_header = IPV6_PROTOCOL_NUM_ICMP;

                uint16_t psum = ~checksum_16((uint16_t*) &phdr, sizeof(ipv6_pseudo_header), 0);

                napkt->hdr.checksum = checksum_16((uint16_t*) napkt, sizeof(icmpv6_na), psum);

                ipv6_encap_dev_output(v6dev->net_dev, &nspkt->opt_mac_addr[0], source, icmpv6_mybuf, IPV6_PROTOCOL_NUM_ICMP);

            }
        }
            break;
        case ICMPV6_TYPE_ECHO_REQUEST:{
            if (len < sizeof(icmpv6_echo)) {
                LOG_IPV6("Received echo request packet too short\n");
                return;
            }

            icmpv6_echo *echo_packet = reinterpret_cast<icmpv6_echo *>(buffer);

            LOG_IPV6("Received echo request id=%d seq=%d\n", ntohs(echo_packet->id), ntohs(echo_packet->seq));

            uint32_t data_len = len - sizeof(icmpv6_echo);

            if(data_len >= 200){ // TODO modify
                LOG_IPV6("Echo size is too large\n");
                return;
            }

            my_buf *reply_buf = my_buf::create(sizeof(icmpv6_echo) + data_len);
            icmpv6_echo *reply_pkt = reinterpret_cast<icmpv6_echo *>(reply_buf->buffer);
            reply_pkt->hdr.type = ICMPV6_TYPE_ECHO_REPLY;
            reply_pkt->hdr.code = 0;
            reply_pkt->hdr.checksum = 0;

            reply_pkt->id = echo_packet->id;
            reply_pkt->seq = echo_packet->seq;

            memcpy(&reply_pkt->data[0], &echo_packet->data[0], data_len);

                ipv6_pseudo_header phdr;
                phdr.src_addr = v6dev->address;
                phdr.dest_addr = source;
                phdr.packet_length = htonl(sizeof(icmpv6_echo) + data_len);
                phdr.zero1 = 0;
                phdr.zero2 = 0;
                phdr.next_header = IPV6_PROTOCOL_NUM_ICMP;

                uint16_t psum = ~checksum_16((uint16_t*) &phdr, sizeof(ipv6_pseudo_header), 0);

                reply_pkt->hdr.checksum = checksum_16((uint16_t*) reply_pkt, sizeof(icmpv6_echo) + data_len, psum);

                ipv6_encap_output(source, v6dev->address, reply_buf, IPV6_PROTOCOL_NUM_ICMP);

        }
            break;
    }
}
