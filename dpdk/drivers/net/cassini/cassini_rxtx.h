/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Google LLC
 */

#ifndef _CASSINI_RXTX_H_
#define _CASSINI_RXTX_H_

#include <rte_ethdev.h>

struct cassini_rx_queue {
	struct rte_mempool *mb_pool;
	volatile uint32_t *rx_ring;
	uint16_t nb_rx_desc;
	uint16_t rx_tail;
	struct rte_mbuf **sw_ring;
	uint64_t rx_pkts;
	uint64_t rx_bytes;
	uint64_t err_pkts;
};

struct cassini_tx_queue {
	volatile uint32_t *tx_ring;
	uint16_t nb_tx_desc;
	uint16_t tx_tail;
	struct rte_mbuf **sw_ring;
	uint64_t tx_pkts;
	uint64_t tx_bytes;
	uint64_t err_pkts;
};

int cassini_rx_queue_setup(struct rte_eth_dev *dev, uint16_t rx_queue_id,
			   uint16_t nb_rx_desc, unsigned int socket_id,
			   const struct rte_eth_rxconf *rx_conf,
			   struct rte_mempool *mb_pool);
void cassini_rx_queue_release(void *rxq);
int cassini_tx_queue_setup(struct rte_eth_dev *dev, uint16_t tx_queue_id,
			   uint16_t nb_tx_desc, unsigned int socket_id,
			   const struct rte_eth_txconf *tx_conf);
void cassini_tx_queue_release(void *txq);
uint16_t cassini_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
			   uint16_t nb_pkts);
uint16_t cassini_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
			   uint16_t nb_pkts);
void cassini_dev_rx_queue_start(struct rte_eth_dev *dev, uint16_t rx_queue_id);
void cassini_dev_tx_queue_start(struct rte_eth_dev *dev, uint16_t tx_queue_id);
int cassini_dev_rx_queue_stop(struct rte_eth_dev *dev, uint16_t rx_queue_id);
int cassini_dev_tx_queue_stop(struct rte_eth_dev *dev, uint16_t tx_queue_id);

#endif /* _CASSINI_RXTX_H_ */
