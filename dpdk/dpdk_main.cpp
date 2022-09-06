/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <cstdint>
#include <cinttypes>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include "../binary_trie.h"
#include "../ethernet.h"
#include "../net.h"
#include "../utils.h"
#include "../ip.h"

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250

struct rte_mempool *mbuf_pool;

int net_device_transmit(struct net_device *dev, uint8_t *buffer, size_t len); // 宣言のみ
int net_device_poll(net_device *dev); // 宣言のみ

/**
 * デバイスのプラットフォーム依存のデータ
 */
struct net_device_data{
    int port; // DPDKのポート
};

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */


/* Main functional part of port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Starting Ethernet port. 8< */
	retval = rte_eth_dev_start(port);
	/* >8 End of starting of ethernet port. */
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

    // net_device構造体を作成
    auto *dev = (net_device *) calloc(1, sizeof(net_device) + sizeof(net_device_data)); // net_deviceの領域と、net_device_dataの領域を確保する
    dev->ops.transmit = net_device_transmit; // 送信用の関数を設定
    dev->ops.poll = net_device_poll; // 受信用の関数を設定

    sprintf(dev->ifname, "dpdk%d", port);
    //strcpy(dev->ifname, "dpdk"); // net_deviceにインターフェース名をセット
    memcpy(dev->mac_address, addr.addr_bytes, 6); // net_deviceにMACアドレスをセット
    ((net_device_data *) dev->data)->port = port;

    printf("Created dev %s port %d address %s \n", dev->ifname, port, mac_addr_toa(dev->mac_address));

    // net_deviceの連結リストに連結させる
    net_device *next;
    next = net_dev_list;
    net_dev_list = dev;
    dev->next = next;

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	/* End of setting RX port in promiscuous mode. */
	if (retval != 0)
		return retval;

	return 0;
}
/* >8 End of main functional part of port initialization. */

/**
 * インターフェース名からデバイスを探す
 * @param interface
 * @return
 */
net_device *get_net_device_by_name(const char *interface){
    net_device *dev;
    for(dev = net_dev_list; dev; dev = dev->next){
        if(strcmp(dev->ifname, interface) == 0){
            return dev;
        }
    }
    return nullptr;
}


/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

 /* Basic forwarding application lcore. 8< */
static __rte_noreturn void
lcore_main(void)
{
	uint16_t port;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) >= 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

    ip_fib = (binary_trie_node<ip_route_entry> *) calloc(1, sizeof(binary_trie_node<ip_route_entry>));


    configure_ip_address(
            get_net_device_by_name("dpdk0"),
            IP_ADDRESS(10, 0, 0, 2),
            IP_ADDRESS(255, 255, 255, 0));
    configure_ip_address(
            get_net_device_by_name("dpdk1"),
            IP_ADDRESS(10, 0, 1, 2),
            IP_ADDRESS(255, 255, 255, 0));

	/* Main work of application loop. 8< */
	for (;;) {

        // デバイスから通信を受信
        for(net_device *dev = net_dev_list; dev; dev = dev->next){
            dev->ops.poll(dev);
        }

	}
	/* >8 End of loop. */
}
/* >8 End Basic forwarding application lcore. */

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	unsigned nb_ports;
	uint16_t portid;

	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	/* >8 End of initialization the Environment Abstraction Layer (EAL). */

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */

	/* Allocates mempool to hold the mbufs. 8< */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	/* >8 End of allocating mempool to hold mbuf. */

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initializing all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
					portid);
	/* >8 End of initializing all ports. */

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the main core only. Called on single lcore. 8< */
	lcore_main();
	/* >8 End of called on single lcore. */

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}


/**
 * ネットデバイスの送信処理
 * @param dev
 * @param buf
 * @return
 */
int net_device_transmit(struct net_device *dev, uint8_t *buffer, size_t len){
    struct rte_mbuf *mbuf;
    mbuf = rte_pktmbuf_alloc(mbuf_pool);
    uint8_t *bbb_buf = rte_pktmbuf_mtod(mbuf , uint8_t*);
    mbuf->pkt_len = len;
    mbuf->buf_len = len;
    mbuf->data_len = len;

    memcpy(bbb_buf, buffer, len);

    const uint16_t nb_tx = rte_eth_tx_burst(((net_device_data *) dev->data)->port, 0,&mbuf, 1);
    if(nb_tx < 1){
        rte_pktmbuf_free(mbuf);
    }
    return 0;
}

/**
 * ネットワークデバイスの受信処理
 * @param dev
 * @return
 */
int net_device_poll(net_device *dev){
    struct rte_mbuf *buf;
    const uint16_t nb_rx = rte_eth_rx_burst(((net_device_data *) dev->data)->port, 0, &buf, 1);

    if (unlikely(nb_rx == 0))
        return 0;
    // 受信したデータをイーサネットに送る
    ethernet_input(dev,  rte_pktmbuf_mtod(buf , uint8_t*), buf->data_len);
    return 0;
}