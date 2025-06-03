/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Google LLC
 */

#ifndef _CASSINI_ETHDEV_H_
#define _CASSINI_ETHDEV_H_

#include <rte_ethdev.h>

#define CASSINI_MAX_RX_QUEUES 1
#define CASSINI_MAX_TX_QUEUES 1

#define CASSINI_MAX_MAC_ADDRS 1

/* Structure to store memory mapped region */
struct cassini_mem_region {
	void *addr;
	rte_iova_t iova;
	size_t len;
};

struct cassini_adapter {
	struct rte_eth_dev *eth_dev;
	struct rte_pci_device *pci_dev;
	void *hw_addr;
	struct cassini_mem_region rx_ring_mem; /* RX ring memory */
	struct cassini_mem_region tx_ring_mem; /* TX ring memory */
};

int cassini_dev_configure(struct rte_eth_dev *dev);
int cassini_dev_start(struct rte_eth_dev *dev);
void cassini_dev_stop(struct rte_eth_dev *dev);
void cassini_dev_close(struct rte_eth_dev *dev);
int cassini_dev_reset(struct rte_eth_dev *dev);
int cassini_promiscuous_enable(struct rte_eth_dev *dev);
int cassini_promiscuous_disable(struct rte_eth_dev *dev);
int cassini_link_update(struct rte_eth_dev *dev, int wait_to_complete);
int cassini_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats);
int cassini_stats_reset(struct rte_eth_dev *dev);
int cassini_dev_infos_get(struct rte_eth_dev *dev,
			  struct rte_eth_dev_info *dev_info);
const uint32_t *cassini_dev_supported_ptypes_get(struct rte_eth_dev *dev);
int cassini_mtu_set(struct rte_eth_dev *dev, uint16_t mtu);
int cassini_mac_addr_set(struct rte_eth_dev *dev, struct rte_ether_addr *mac_addr);
int cassini_mac_addr_add(struct rte_eth_dev *dev, struct rte_ether_addr *mac_addr,
			 uint32_t index, uint32_t vmdq);
void cassini_mac_addr_remove(struct rte_eth_dev *dev, uint32_t index);
int cassini_allmulticast_enable(struct rte_eth_dev *dev);
int cassini_allmulticast_disable(struct rte_eth_dev *dev);

/* Memory management functions */
int cassini_dma_alloc(struct cassini_adapter *adapter, const char *name,
		      uint64_t size, int socket_id,
		      struct cassini_mem_region *region);
void cassini_dma_free(struct cassini_adapter *adapter,
		      struct cassini_mem_region *region);

#endif /* _CASSINI_ETHDEV_H_ */
